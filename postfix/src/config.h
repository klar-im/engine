#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "decision_profiles.h"

namespace klar {

struct DomainPolicy {
    std::string recipient_domain;
    std::string mode;         // tag|reject
    std::string profile;      // cautious|standard|aggressive
    double spam_threshold_override = -1.0;
    double reject_threshold = 0.995;
};

struct Config {
    // Milter / network
    std::string listen = "inet:127.0.0.1:8891";
    std::string mode = "tag";
    bool fail_open = true;
    int timeout_ms = 1500;
    int max_message_bytes = 5242880;
    int max_inflight_sessions = 128;
    int64_t max_inflight_bytes = 268435456;
    int shutdown_drain_timeout_ms = 30000;

    // Scoring
    std::string profile = "standard";
    double spam_threshold_override = -1.0;
    double reject_threshold = 0.995;

    // Model
    // Where postfix/scripts/fetch_model.sh puts the model. The version file is
    // the engine's MANIFEST.json (model_uuid) or a plain VERSION line; see
    // ModelRuntime::read_version_file.
    std::string model_dir = "/var/lib/klar/model";
    std::string model_version_file = "/var/lib/klar/model/MANIFEST.json";
    // Spamhaus DROP netblocks, built by model-lab/scripts/build_ip_blocklist.py
    // (TASK-113). Defaults NEXT TO the model, which is where packaging puts it, so
    // a stock install finds it without extra configuration. Empty disables the
    // origin-IP signal; a missing or malformed file disables it too, it never
    // blocks startup. Refresh it on a cron (and SIGHUP) — DROP moves, and
    // ip_blocklist_max_age_days is only how long we stay quiet about it.
    std::string ip_blocklist_path = "/var/lib/klar/model/ip_blocklist.bin";
    int ip_blocklist_max_age_days = 14;
    // Our own relay hops, as CIDRs or bare addresses (TASK-387). Set this ONLY
    // when the milter sits behind an MTA you control: it is what licenses reading
    // an origin address out of the Received chain instead of the connection.
    // Empty (the default) means the connecting address is the only origin we
    // trust. Getting this wrong lets a sender's own Received line be believed, so
    // it is opt-in and never inferred.
    std::vector<std::string> trusted_relay_cidrs;

    // What to make of the message's own Authentication-Results header. The
    // engine READS it and does not verify (engine/ARCHITECTURE.md, "Trust
    // boundary"): the topmost AR is believed, and a `dkim=pass header.d=<brand>`
    // on a From at that brand's own domain buys a -0.90 ham rescue. Behind an
    // MTA that stamps a trusted AR and strips the client's (Postfix with
    // OpenDKIM/OpenDMARC ahead of this milter) that is the design. Behind an MTA
    // whose milters see the client's raw bytes, notably Stalwart (stalwart/README.md),
    // it is a forged-AR hole, so "ignore" drops every Authentication-Results
    // header before the engine sees the message: no AR-derived rescue, no
    // AR-derived condemn, the verdict rests on everything else.
    //   "trust-topmost"  (default) the topmost AR is the receiving MTA's
    //   "ignore"         the message is classified as if it carried none
    std::string auth_results = "trust-topmost";

    // Output
    int header_value_max_bytes = 256;
    std::string log_level = "info";
    bool log_json = true;
    bool health_enabled = true;
    std::string health_listen = "127.0.0.1:8892";
    // The /metrics endpoint is unauthenticated. Binding all interfaces
    // (0.0.0.0 / ::) is refused unless this is explicitly set true (e.g. a
    // firewalled container that must expose readiness to its orchestrator).
    bool health_allow_public = false;

    // Lists
    std::vector<std::string> allowlist_senders;
    std::vector<std::string> allowlist_domains;
    std::vector<std::string> blocklist_senders;
    std::vector<std::string> blocklist_domains;
    std::string blocklist_action = "reject";

    // Storage
    std::string event_store_path = "/var/lib/klar/events.sqlite3";

    // Per-domain overrides
    std::vector<DomainPolicy> domain_policies;
};

// profile_to_threshold(profile) now lives in decision_profiles.h
// (shared with spamd/), included above.

// Parse a TOML config file. Throws std::runtime_error on parse failure.
Config load_config(const std::string& path);

// Validate a parsed config.  Returns "" on success, error message otherwise.
std::string validate_config(const Config& cfg);

// Split "host:port" on the LAST colon (so bracketed IPv6 like "[::1]:8892"
// works) and strip the [] from a bracketed IPv6 host. Returns false if there is
// no ':' (no port component). Shared by validate_config and HealthServer::start
// so validation and binding can never disagree on what an address means.
bool split_host_port(const std::string& addr, std::string& host,
                     std::string& port);

} // namespace klar
