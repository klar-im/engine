#pragma once
#include <atomic>
#include <memory>
#include <string>
#include "config.h"
#include "model_runtime.h"
#include "origin_ip_blocklist.h"
#include "event_store.h"
#include "health_server.h"

namespace klar {

struct ServerState {
    std::atomic<uint32_t> inflight_sessions{0};
    std::atomic<uint64_t> inflight_bytes{0};
    std::atomic<bool> shutting_down{false};

    // Metrics counters
    std::atomic<uint64_t> decisions_total{0};
    std::atomic<uint64_t> decisions_tag{0};
    std::atomic<uint64_t> decisions_reject{0};
    std::atomic<uint64_t> decisions_bypass{0};
    std::atomic<uint64_t> errors_total{0};
    // Messages whose connecting IP was DROP-listed (TASK-113). The only aggregate
    // view of the offset: the decision event records no structural offset at all
    // (TASK-388), so without this a list that loads, stays fresh and never matches
    // anything is indistinguishable from a healthy one.
    std::atomic<uint64_t> origin_ip_blocked{0};
};

// These are global because libmilter callbacks use static function pointers
// and smfi_setpriv/getpriv for per-connection state.
void set_global_state(std::shared_ptr<const Config> cfg, ModelRuntime* runtime,
                      EventStore* store, ServerState* state,
                      OriginIpBlocklist* ip_blocklist);

// Install the parsed trusted-relay set (TASK-387). Separate from the config swap
// because parsing can fail and must be reported by the caller that has a logger.
void set_trusted_relays(const TrustedRelays& relays);

// Atomically swap the global config (used by SIGHUP reload).
void swap_global_config(std::shared_ptr<const Config> new_cfg);

// Register milter callbacks and return the smfilter struct name
// Call smfi_setconn, smfi_settimeout, smfi_register before this
int milter_setup(const Config& cfg);

// Generate Prometheus metrics text
std::string generate_metrics(const ServerState& state, const ModelRuntime& runtime,
                             const OriginIpBlocklist& ip_blocklist);

} // namespace klar
