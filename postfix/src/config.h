#pragma once

#include <cstdint>
#include <string>
#include <vector>

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
    std::string model_dir = "/var/lib/klar/model/current";
    std::string model_version_file = "/var/lib/klar/model/current/VERSION";

    // Output
    std::string header_prefix = "X-Klar";
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

// Returns the spam threshold for a named profile.
// cautious=0.70, standard=0.50, aggressive=0.30
double profile_to_threshold(const std::string& profile);

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
