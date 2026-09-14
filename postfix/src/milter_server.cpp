#include "milter_server.h"
#include "session_context.h"
#include "auth_results.h"
#include "policy.h"
#include <libmilter/mfapi.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <iostream>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <iomanip>
#include <memory>
#include <strings.h>

namespace klar {

// ---------------------------------------------------------------------------
// Global state (set once at startup, read-only during operation)
// ---------------------------------------------------------------------------
static std::shared_ptr<const Config> g_cfg;
static ModelRuntime* g_runtime = nullptr;
static EventStore*   g_store   = nullptr;
static ServerState*  g_state   = nullptr;
static OriginIpBlocklist* g_ip_blocklist = nullptr;
// Parsed once at startup / SIGHUP from cfg.trusted_relay_cidrs. Read-only during
// operation, like the other globals here.
static TrustedRelays g_trusted_relays;

void set_global_state(std::shared_ptr<const Config> cfg, ModelRuntime* runtime,
                      EventStore* store, ServerState* state,
                      OriginIpBlocklist* ip_blocklist) {
    std::atomic_store(&g_cfg, std::move(cfg));
    g_runtime = runtime;
    g_store   = store;
    g_state   = state;
    g_ip_blocklist = ip_blocklist;
}

void set_trusted_relays(const TrustedRelays& relays) {
    g_trusted_relays = relays;
}

void swap_global_config(std::shared_ptr<const Config> new_cfg) {
    std::atomic_store(&g_cfg, std::move(new_cfg));
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Decrement inflight_bytes by the session's buffered amount and reset to 0.
// Uses CAS loop to avoid underflow.
static void release_session_bytes(SessionContext* session, ServerState* state) {
    uint64_t bytes = session->buffered_bytes;
    if (bytes > 0) {
        uint64_t cur = state->inflight_bytes.load(std::memory_order_relaxed);
        while (true) {
            uint64_t next = (cur >= bytes) ? cur - bytes : 0;
            if (state->inflight_bytes.compare_exchange_weak(
                    cur, next, std::memory_order_relaxed)) {
                break;
            }
        }
        session->buffered_bytes = 0;
    }
}

// Strip surrounding angle brackets from an email address.
static std::string strip_angles(const char* s) {
    if (!s) return {};
    std::string addr(s);
    if (addr.size() >= 2 && addr.front() == '<' && addr.back() == '>') {
        addr = addr.substr(1, addr.size() - 2);
    }
    return addr;
}

// Truncate a header value to the configured maximum length.
static std::string truncate_header_value(const std::string& value, int max_bytes) {
    if (max_bytes <= 0 || static_cast<int>(value.size()) <= max_bytes) {
        return value;
    }
    if (max_bytes <= 3) {
        return value.substr(0, max_bytes);
    }
    return value.substr(0, max_bytes - 3) + "...";
}

// Format a float with 6 decimal places.
static std::string fmt_score(float v) {
    std::ostringstream os;
    os << std::fixed << std::setprecision(6) << v;
    return os.str();
}

// Simple parser for "Display Name <email@example.com>" form.
static void parse_from_header(const std::string& value,
                               std::string& display_name,
                               std::string& email) {
    auto lt = value.find('<');
    auto gt = value.find('>');
    if (lt != std::string::npos && gt != std::string::npos && gt > lt) {
        email = value.substr(lt + 1, gt - lt - 1);
        display_name = value.substr(0, lt);
        // Trim trailing whitespace from display name
        while (!display_name.empty() &&
               (display_name.back() == ' ' || display_name.back() == '\t' || display_name.back() == '"')) {
            display_name.pop_back();
        }
        // Trim leading whitespace / quotes from display name
        size_t start = 0;
        while (start < display_name.size() &&
               (display_name[start] == ' ' || display_name[start] == '\t' || display_name[start] == '"')) {
            ++start;
        }
        if (start > 0) display_name = display_name.substr(start);
    } else {
        // No angle brackets – whole value is the email
        email = value;
        // Trim whitespace
        while (!email.empty() && (email.back() == ' ' || email.back() == '\t'))
            email.pop_back();
        size_t start = 0;
        while (start < email.size() && (email[start] == ' ' || email[start] == '\t'))
            ++start;
        if (start > 0) email = email.substr(start);
        display_name.clear();
    }
}

// ---------------------------------------------------------------------------
// Milter callbacks
// ---------------------------------------------------------------------------

// Textual form of the connecting peer's address, "" for a unix socket, an
// unknown family, or a NULL hostaddr (Postfix passes NULL for a local
// submission). This is the ONLY address allowed to feed the DROP offset: it is
// what the MTA observed on the wire, not what a header claims (TASK-113).
static std::string peer_ip_text(const _SOCK_ADDR* hostaddr) {
    if (hostaddr == nullptr) return {};
    const void* src = nullptr;
    if (hostaddr->sa_family == AF_INET) {
        src = &reinterpret_cast<const struct sockaddr_in*>(hostaddr)->sin_addr;
    } else if (hostaddr->sa_family == AF_INET6) {
        src = &reinterpret_cast<const struct sockaddr_in6*>(hostaddr)->sin6_addr;
    } else {
        return {};
    }
    char buf[INET6_ADDRSTRLEN] = {0};
    if (inet_ntop(hostaddr->sa_family, src, buf, sizeof(buf)) == nullptr) return {};
    return buf;
}

static sfsistat xxfi_connect(SMFICTX* ctx, char* /* hostname */, _SOCK_ADDR* hostaddr) {
    auto cfg = std::atomic_load(&g_cfg);
    if (static_cast<int>(g_state->inflight_sessions.load(std::memory_order_relaxed))
        >= cfg->max_inflight_sessions) {
        smfi_setreply(ctx, const_cast<char*>("421"), const_cast<char*>("4.7.0"),
                      const_cast<char*>("Server busy"));
        return SMFIS_TEMPFAIL;
    }

    g_state->inflight_sessions.fetch_add(1, std::memory_order_relaxed);

    auto* session = new SessionContext();
    session->started = std::chrono::steady_clock::now();
    session->connect_ip = peer_ip_text(hostaddr);
    smfi_setpriv(ctx, session);

    return SMFIS_CONTINUE;
}

static sfsistat xxfi_envfrom(SMFICTX* ctx, char** argv) {
    auto* session = static_cast<SessionContext*>(smfi_getpriv(ctx));
    if (!session) return SMFIS_TEMPFAIL;

    // A non-conformant upstream MTA can deliver MAIL FROM with no address arg.
    if (!argv || !argv[0]) return SMFIS_CONTINUE;
    session->mail_from = strip_angles(argv[0]);

    // Clear per-message state (connection reuse)
    session->raw_rfc822.clear();
    session->received.clear();
    session->rcpt_to.clear();
    session->from_header_name.clear();
    session->from_header_email.clear();
    session->message_id_header.clear();
    session->truncated = false;
    session->buffered_bytes = 0;
    session->bypass_due_overload = false;
    session->queue_id.clear();
    session->started = std::chrono::steady_clock::now();
    session->drop_auth_results = ignores_auth_results(*std::atomic_load(&g_cfg));

    return SMFIS_CONTINUE;
}

static sfsistat xxfi_envrcpt(SMFICTX* ctx, char** argv) {
    auto* session = static_cast<SessionContext*>(smfi_getpriv(ctx));
    if (!session) return SMFIS_TEMPFAIL;

    if (!argv || !argv[0]) return SMFIS_CONTINUE;
    session->rcpt_to.push_back(strip_angles(argv[0]));
    return SMFIS_CONTINUE;
}

static sfsistat xxfi_header(SMFICTX* ctx, char* headerf, char* headerv) {
    auto* session = static_cast<SessionContext*>(smfi_getpriv(ctx));
    if (!session) return SMFIS_TEMPFAIL;

    // auth_results = "ignore": the engine never sees the client's claims about
    // its own authentication (config.h). Dropped here, before accumulation, so
    // the bytes handed to classify_rfc822 carry no such header at all, which is
    // the state the engine reads as DMARC Unknown.
    if (session->drop_auth_results && is_auth_results_header(headerf)) return SMFIS_CONTINUE;

    // Accumulate raw RFC822
    session->raw_rfc822 += headerf;
    session->raw_rfc822 += ": ";
    session->raw_rfc822 += headerv;
    session->raw_rfc822 += "\r\n";

    // Parse interesting headers
    if (strcasecmp(headerf, "Received") == 0) {
        // Bounded: a forged message can carry thousands of Received lines, and
        // the trust walk only ever reads down to the first untrusted hop anyway.
        if (session->received.size() < 32) {
            session->received.emplace_back(headerv ? headerv : "");
        }
    }
    if (strcasecmp(headerf, "From") == 0) {
        parse_from_header(headerv, session->from_header_name, session->from_header_email);
    } else if (strcasecmp(headerf, "Message-ID") == 0) {
        session->message_id_header = headerv;
    }

    return SMFIS_CONTINUE;
}

static sfsistat xxfi_eoh(SMFICTX* ctx) {
    auto* session = static_cast<SessionContext*>(smfi_getpriv(ctx));
    if (!session) return SMFIS_TEMPFAIL;

    // Blank line separating headers from body
    session->raw_rfc822 += "\r\n";
    return SMFIS_CONTINUE;
}

static sfsistat xxfi_body(SMFICTX* ctx, unsigned char* bodyp, size_t bodylen) {
    auto* session = static_cast<SessionContext*>(smfi_getpriv(ctx));
    if (!session) return SMFIS_TEMPFAIL;

    if (session->bypass_due_overload) {
        return SMFIS_CONTINUE;
    }

    auto cfg = std::atomic_load(&g_cfg);
    uint64_t max_msg = static_cast<uint64_t>(cfg->max_message_bytes);
    uint64_t actually_buffered = 0;
    if (session->buffered_bytes + bodylen > max_msg) {
        // Append only up to the limit
        uint64_t remaining = max_msg - session->buffered_bytes;
        if (remaining > 0) {
            session->raw_rfc822.append(reinterpret_cast<const char*>(bodyp), remaining);
            session->buffered_bytes += remaining;
            actually_buffered = remaining;
        }
        session->truncated = true;
    } else {
        session->raw_rfc822.append(reinterpret_cast<const char*>(bodyp), bodylen);
        session->buffered_bytes += bodylen;
        actually_buffered = bodylen;
    }

    if (actually_buffered > 0) {
        g_state->inflight_bytes.fetch_add(actually_buffered, std::memory_order_relaxed);
    }

    if (static_cast<int64_t>(g_state->inflight_bytes.load(std::memory_order_relaxed))
        > cfg->max_inflight_bytes) {
        session->bypass_due_overload = true;
    }

    return SMFIS_CONTINUE;
}

static sfsistat xxfi_eom(SMFICTX* ctx) {
    auto* session = static_cast<SessionContext*>(smfi_getpriv(ctx));
    if (!session) return SMFIS_TEMPFAIL;

    // Retrieve queue id from Postfix
    char* qid = smfi_getsymval(ctx, const_cast<char*>("i"));
    session->queue_id = qid ? qid : "unknown";

    // Snapshot config for this message
    auto cfg = std::atomic_load(&g_cfg);

    // Classify
    // Resolve the origin against the DROP list here, at the layer that owns the
    // connection, and hand the engine the answer (TASK-113/387). Behind a
    // configured trusted relay the observed peer is our own hop, so the origin
    // comes from the Received chain instead — and is reported as the WEAKER
    // header-derived signal, never as an observed one.
    const bool have_list = g_ip_blocklist != nullptr;
    const bool connect_ip_blocked =
        have_list && g_ip_blocklist->contains(session->connect_ip);
    bool header_ip_blocked = false;
    if (have_list && !connect_ip_blocked) {
        const std::string origin = klar::resolve_origin_ip(
            session->connect_ip, session->received, g_trusted_relays);
        header_ip_blocked = origin != session->connect_ip &&
                            g_ip_blocklist->contains(origin);
    }

    ClassifyResult cr = g_runtime->classify_rfc822(
        session->raw_rfc822,
        session->from_header_name,
        session->mail_from,
        connect_ip_blocked, header_ip_blocked);

    // Evaluate policy
    PolicyResult pr = evaluate_policy(
        *cfg, cr, session->mail_from, session->rcpt_to,
        !cr.ok, session->bypass_due_overload);

    // Latency
    auto now = std::chrono::steady_clock::now();
    double latency_ms = std::chrono::duration<double, std::milli>(now - session->started).count();

    // Build decision event
    DecisionEvent ev;
    ev.ts             = now_rfc3339();
    ev.event_id       = generate_uuid();
    ev.queue_id       = session->queue_id;
    // mail_from / message_id are attacker-controlled; bound them before they are
    // persisted to SQLite and written to the JSON log (Postfix caps header sizes,
    // but the milter must not rely on that).
    ev.mail_from      = truncate_header_value(session->mail_from, 1024);
    ev.rcpt_count     = static_cast<int>(session->rcpt_to.size());
    ev.bytes_seen     = static_cast<int64_t>(session->buffered_bytes);
    ev.truncated      = session->truncated;
    ev.model_version  = g_runtime->loaded_model_version();
    ev.score_spam     = pr.score_spam;
    ev.score_regular  = pr.score_regular;
    ev.score_marketing = pr.score_marketing;
    ev.score_gibberish = pr.score_gibberish;
    ev.label          = pr.label;
    ev.action         = action_to_string(pr.action);
    ev.latency_ms     = latency_ms;
    ev.status         = pr.status;
    ev.error_code     = pr.error_code;
    ev.message_id_header = truncate_header_value(session->message_id_header, 1024);
    ev.policy_reason  = pr.policy_reason;
    ev.fired_offsets  = cr.fired_offsets;

    // Record & log
    g_store->record(ev);
    std::cerr << event_to_json(ev) << std::endl;

    // Add X-Klar-* headers
    int max_hv = cfg->header_value_max_bytes;
    auto add_hdr = [&](const char* name, const std::string& value) {
        std::string tv = truncate_header_value(value, max_hv);
        smfi_addheader(ctx, const_cast<char*>(name), const_cast<char*>(tv.c_str()));
    };

    add_hdr("X-Klar-Event-ID",        ev.event_id);
    add_hdr("X-Klar-Label",          pr.label);
    add_hdr("X-Klar-Class",          pr.klass);
    add_hdr("X-Klar-Score-Spam",     fmt_score(pr.score_spam));
    add_hdr("X-Klar-Score-Regular",  fmt_score(pr.score_regular));
    add_hdr("X-Klar-Score-Marketing", fmt_score(pr.score_marketing));
    add_hdr("X-Klar-Score-Gibberish", fmt_score(pr.score_gibberish));
    add_hdr("X-Klar-Action",         action_to_string(pr.action));
    add_hdr("X-Klar-Model-Version",  g_runtime->loaded_model_version());
    // Only stamped when it fires: the scores above explain a content-driven
    // verdict, but a DROP hit is the one reason a low-scoring message can still
    // be junked, and an operator debugging that needs to see it (TASK-113).
    if (connect_ip_blocked || header_ip_blocked) {
        // The value names the PROVENANCE, because the two carry different weight
        // and an operator debugging a verdict needs to know which one fired.
        add_hdr("X-Klar-Origin-IP",
                connect_ip_blocked ? "drop-listed" : "drop-listed-via-relay");
        g_state->origin_ip_blocked.fetch_add(1, std::memory_order_relaxed);
    }

    // Update metrics
    g_state->decisions_total.fetch_add(1, std::memory_order_relaxed);
    switch (pr.action) {
        case Action::TAG:        g_state->decisions_tag.fetch_add(1, std::memory_order_relaxed); break;
        case Action::REJECT:     g_state->decisions_reject.fetch_add(1, std::memory_order_relaxed); break;
        case Action::BYPASS:     g_state->decisions_bypass.fetch_add(1, std::memory_order_relaxed); break;
        case Action::TEMPFAIL:   break;
    }
    if (pr.status != "ok") {
        g_state->errors_total.fetch_add(1, std::memory_order_relaxed);
    }

    // Release buffered bytes from global counter now that processing is done
    release_session_bytes(session, g_state);

    // Apply action
    switch (pr.action) {
        case Action::REJECT:
            smfi_setreply(ctx, const_cast<char*>("550"), const_cast<char*>("5.7.1"),
                          const_cast<char*>("Message rejected by spam policy"));
            return SMFIS_REJECT;

        case Action::TEMPFAIL:
            smfi_setreply(ctx, const_cast<char*>("451"), const_cast<char*>("4.7.1"),
                          const_cast<char*>("Temporary filtering failure"));
            return SMFIS_TEMPFAIL;

        case Action::TAG:
        case Action::BYPASS:
        default:
            return SMFIS_ACCEPT;
    }
}

static sfsistat xxfi_abort(SMFICTX* ctx) {
    auto* session = static_cast<SessionContext*>(smfi_getpriv(ctx));
    if (session) {
        // Release buffered bytes from global counter
        release_session_bytes(session, g_state);
        // Free buffered message data but keep the session alive for the connection
        session->raw_rfc822.clear();
        session->raw_rfc822.shrink_to_fit();
    }
    return SMFIS_CONTINUE;
}

static sfsistat xxfi_close(SMFICTX* ctx) {
    auto* session = static_cast<SessionContext*>(smfi_getpriv(ctx));
    if (session) {
        g_state->inflight_sessions.fetch_sub(1, std::memory_order_relaxed);
        // Safety net: release any remaining bytes (normally already 0 after eom/abort)
        release_session_bytes(session, g_state);
        delete session;
        smfi_setpriv(ctx, nullptr);
    }
    return SMFIS_CONTINUE;
}

// ---------------------------------------------------------------------------
// milter_setup
// ---------------------------------------------------------------------------

int milter_setup(const Config& cfg) {
    static struct smfiDesc smfilter = {
        const_cast<char*>("klar-milter"),  // xxfi_name
        SMFI_VERSION,                       // xxfi_version
        SMFIF_ADDHDRS,                      // xxfi_flags
        xxfi_connect,                       // xxfi_connect
        nullptr,                            // xxfi_helo
        xxfi_envfrom,                       // xxfi_envfrom
        xxfi_envrcpt,                       // xxfi_envrcpt
        xxfi_header,                        // xxfi_header
        xxfi_eoh,                           // xxfi_eoh
        xxfi_body,                          // xxfi_body
        xxfi_eom,                           // xxfi_eom
        xxfi_abort,                         // xxfi_abort
        xxfi_close,                         // xxfi_close
        nullptr,                            // xxfi_unknown
        nullptr,                            // xxfi_data
        nullptr                             // xxfi_negotiate
    };

    if (smfi_setconn(const_cast<char*>(cfg.listen.c_str())) == MI_FAILURE) {
        std::cerr << "smfi_setconn failed for: " << cfg.listen << std::endl;
        return -1;
    }

    int timeout_secs = std::max(1, (cfg.timeout_ms + 999) / 1000);
    if (smfi_settimeout(timeout_secs) == MI_FAILURE) {
        std::cerr << "smfi_settimeout failed" << std::endl;
        return -1;
    }

    if (smfi_register(smfilter) == MI_FAILURE) {
        std::cerr << "smfi_register failed" << std::endl;
        return -1;
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Prometheus metrics
// ---------------------------------------------------------------------------

std::string generate_metrics(const ServerState& state, const ModelRuntime& runtime,
                             const OriginIpBlocklist& ip_blocklist) {
    std::ostringstream os;

    os << "# HELP klar_inflight_sessions Number of active milter sessions\n"
       << "# TYPE klar_inflight_sessions gauge\n"
       << "klar_inflight_sessions " << state.inflight_sessions.load(std::memory_order_relaxed) << "\n";

    os << "# HELP klar_inflight_bytes Total bytes buffered across active sessions\n"
       << "# TYPE klar_inflight_bytes gauge\n"
       << "klar_inflight_bytes " << state.inflight_bytes.load(std::memory_order_relaxed) << "\n";

    os << "# HELP klar_decisions_total Total number of classification decisions\n"
       << "# TYPE klar_decisions_total counter\n"
       << "klar_decisions_total " << state.decisions_total.load(std::memory_order_relaxed) << "\n";

    os << "# HELP klar_decisions Decisions by action type\n"
       << "# TYPE klar_decisions counter\n"
       << "klar_decisions{action=\"tag\"} " << state.decisions_tag.load(std::memory_order_relaxed) << "\n"
       << "klar_decisions{action=\"reject\"} " << state.decisions_reject.load(std::memory_order_relaxed) << "\n"
       << "klar_decisions{action=\"bypass\"} " << state.decisions_bypass.load(std::memory_order_relaxed) << "\n";

    os << "# HELP klar_errors_total Total errors encountered\n"
       << "# TYPE klar_errors_total counter\n"
       << "klar_errors_total " << state.errors_total.load(std::memory_order_relaxed) << "\n";

    os << "# HELP klar_model_loaded Whether the model is loaded\n"
       << "# TYPE klar_model_loaded gauge\n"
       << "klar_model_loaded " << (runtime.is_loaded() ? 1 : 0) << "\n";

    os << "# HELP klar_model_generation Model reload generation counter\n"
       << "# TYPE klar_model_generation counter\n"
       << "klar_model_generation " << runtime.generation() << "\n";

    // Origin-IP reputation (TASK-113). Three series, because this layer dies
    // silently in three ways: the artifact never shipped (0 ranges), nobody
    // refreshes it (stale), or it loads fresh and never matches because the
    // address never reaches the lookup (a flat 0 counter against the measured
    // ~3% of spam). Alert on all three.
    os << "# HELP klar_ip_blocklist_ranges Loaded DROP netblock ranges (0 = signal off)\n"
       << "# TYPE klar_ip_blocklist_ranges gauge\n"
       << "klar_ip_blocklist_ranges " << ip_blocklist.size() << "\n";

    os << "# HELP klar_ip_blocklist_stale DROP list older than ip_blocklist_max_age_days\n"
       << "# TYPE klar_ip_blocklist_stale gauge\n"
       << "klar_ip_blocklist_stale " << (ip_blocklist.stale() ? 1 : 0) << "\n";

    os << "# HELP klar_origin_ip_blocked_total Messages from a DROP-listed IP\n"
       << "# TYPE klar_origin_ip_blocked_total counter\n"
       << "klar_origin_ip_blocked_total " << state.origin_ip_blocked.load(std::memory_order_relaxed) << "\n";

    return os.str();
}

} // namespace klar
