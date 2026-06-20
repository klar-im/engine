#include "config.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>

namespace klar {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

// ---------------------------------------------------------------------------
// Minimal TOML value types
// ---------------------------------------------------------------------------

enum class TomlType { String, Int, Float, Bool, StringArray };

struct TomlValue {
    TomlType type = TomlType::String;
    std::string str_val;
    int64_t int_val = 0;
    double float_val = 0.0;
    bool bool_val = false;
    std::vector<std::string> arr_val;
};

// ---------------------------------------------------------------------------
// Minimal TOML parser
// ---------------------------------------------------------------------------

static std::string parse_quoted_string(const std::string& s, size_t& pos) {
    // pos points at the opening quote character
    char quote = s[pos];
    ++pos;
    std::string result;
    while (pos < s.size() && s[pos] != quote) {
        if (s[pos] == '\\' && pos + 1 < s.size()) {
            ++pos;
            switch (s[pos]) {
                case 'n':  result += '\n'; break;
                case 't':  result += '\t'; break;
                case '\\': result += '\\'; break;
                case '"':  result += '"';  break;
                case '\'': result += '\''; break;
                default:   result += '\\'; result += s[pos]; break;
            }
        } else {
            result += s[pos];
        }
        ++pos;
    }
    if (pos < s.size()) ++pos;  // skip closing quote
    return result;
}

static TomlValue parse_value(const std::string& raw) {
    std::string s = trim(raw);
    TomlValue v;

    if (s.empty()) {
        throw std::runtime_error("empty TOML value");
    }

    // String
    if (s.front() == '"' || s.front() == '\'') {
        v.type = TomlType::String;
        size_t pos = 0;
        v.str_val = parse_quoted_string(s, pos);
        return v;
    }

    // Bool
    if (s == "true" || s == "false") {
        v.type = TomlType::Bool;
        v.bool_val = (s == "true");
        return v;
    }

    // String array: ["a", "b", "c"]
    if (s.front() == '[') {
        v.type = TomlType::StringArray;
        size_t pos = 1; // skip '['
        while (pos < s.size()) {
            // skip whitespace and commas
            while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t' ||
                                       s[pos] == ',' || s[pos] == '\r'))
                ++pos;
            if (pos >= s.size() || s[pos] == ']') break;
            if (s[pos] == '"' || s[pos] == '\'') {
                v.arr_val.push_back(parse_quoted_string(s, pos));
            } else {
                // unexpected token in array
                throw std::runtime_error("expected quoted string in array");
            }
        }
        return v;
    }

    // Number: try int first, then float
    // Check if it contains a dot => float
    if (s.find('.') != std::string::npos) {
        v.type = TomlType::Float;
        size_t idx = 0;
        v.float_val = std::stod(s, &idx);
        if (idx != s.size()) {
            throw std::runtime_error("invalid float value: " + s);
        }
        return v;
    }

    // Integer
    v.type = TomlType::Int;
    size_t idx = 0;
    v.int_val = std::stoll(s, &idx);
    if (idx != s.size()) {
        throw std::runtime_error("invalid integer value: " + s);
    }
    return v;
}

struct TomlTable {
    std::string name;  // empty for root
    std::vector<std::pair<std::string, TomlValue>> entries;
};

struct TomlDoc {
    TomlTable root;
    // array-of-tables: key -> vector of tables
    std::vector<std::pair<std::string, std::vector<TomlTable>>> array_tables;

    std::vector<TomlTable>& get_or_create_array(const std::string& name) {
        for (auto& [k, v] : array_tables) {
            if (k == name) return v;
        }
        array_tables.push_back({name, {}});
        return array_tables.back().second;
    }
};

static TomlDoc parse_toml(const std::string& text) {
    TomlDoc doc;
    TomlTable* current = &doc.root;

    std::istringstream stream(text);
    std::string line;
    int line_num = 0;

    while (std::getline(stream, line)) {
        ++line_num;
        std::string trimmed = trim(line);

        // skip blank lines and comments
        if (trimmed.empty() || trimmed.front() == '#') continue;

        // [[array_of_tables]]
        if (trimmed.size() >= 4 && trimmed[0] == '[' && trimmed[1] == '[') {
            size_t end = trimmed.find("]]");
            if (end == std::string::npos) {
                throw std::runtime_error("line " + std::to_string(line_num) +
                                         ": malformed [[table]] header");
            }
            std::string name = trim(trimmed.substr(2, end - 2));
            auto& arr = doc.get_or_create_array(name);
            arr.push_back(TomlTable{name, {}});
            current = &arr.back();
            continue;
        }

        // [table] -- we don't need regular table sections for this config,
        // but skip them gracefully (treat keys as root-level with prefix)
        if (trimmed.front() == '[') {
            // For now ignore regular [table] sections -- our config doesn't use them
            continue;
        }

        // key = value
        size_t eq = trimmed.find('=');
        if (eq == std::string::npos) {
            throw std::runtime_error("line " + std::to_string(line_num) +
                                     ": expected key = value");
        }

        std::string key = trim(trimmed.substr(0, eq));
        std::string val_str = trimmed.substr(eq + 1);

        // strip inline comment (only outside of quoted strings)
        // Simple heuristic: if val starts with a quote, find the closing quote
        // then look for # after it.  Otherwise just split on #.
        {
            std::string vs = trim(val_str);
            if (!vs.empty() && vs.front() != '"' && vs.front() != '\'' &&
                vs.front() != '[') {
                size_t hash = vs.find('#');
                if (hash != std::string::npos) {
                    val_str = vs.substr(0, hash);
                }
            }
        }

        try {
            current->entries.push_back({key, parse_value(val_str)});
        } catch (const std::exception& e) {
            throw std::runtime_error("line " + std::to_string(line_num) +
                                     ": " + e.what());
        }
    }
    return doc;
}

// ---------------------------------------------------------------------------
// Helpers to pull typed values out of a table
// ---------------------------------------------------------------------------

static const TomlValue* find(const TomlTable& t, const std::string& key) {
    for (auto& [k, v] : t.entries) {
        if (k == key) return &v;
    }
    return nullptr;
}

static void set_string(const TomlTable& t, const std::string& key,
                       std::string& dst) {
    auto* v = find(t, key);
    if (!v) return;
    if (v->type != TomlType::String)
        throw std::runtime_error("expected string for key '" + key + "'");
    dst = v->str_val;
}

static void set_bool(const TomlTable& t, const std::string& key, bool& dst) {
    auto* v = find(t, key);
    if (!v) return;
    if (v->type != TomlType::Bool)
        throw std::runtime_error("expected bool for key '" + key + "'");
    dst = v->bool_val;
}

static void set_int(const TomlTable& t, const std::string& key, int& dst) {
    auto* v = find(t, key);
    if (!v) return;
    if (v->type != TomlType::Int)
        throw std::runtime_error("expected int for key '" + key + "'");
    dst = static_cast<int>(v->int_val);
}

static void set_int64(const TomlTable& t, const std::string& key,
                      int64_t& dst) {
    auto* v = find(t, key);
    if (!v) return;
    if (v->type != TomlType::Int)
        throw std::runtime_error("expected int for key '" + key + "'");
    dst = v->int_val;
}

static void set_double(const TomlTable& t, const std::string& key,
                       double& dst) {
    auto* v = find(t, key);
    if (!v) return;
    if (v->type == TomlType::Float) {
        dst = v->float_val;
    } else if (v->type == TomlType::Int) {
        dst = static_cast<double>(v->int_val);
    } else {
        throw std::runtime_error("expected number for key '" + key + "'");
    }
}

static void set_string_array(const TomlTable& t, const std::string& key,
                             std::vector<std::string>& dst) {
    auto* v = find(t, key);
    if (!v) return;
    if (v->type != TomlType::StringArray)
        throw std::runtime_error("expected string array for key '" + key + "'");
    dst = v->arr_val;
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

static void apply_root(const TomlTable& root, Config& cfg) {
    set_string(root, "listen", cfg.listen);
    set_string(root, "mode", cfg.mode);
    set_bool(root, "fail_open", cfg.fail_open);
    set_int(root, "timeout_ms", cfg.timeout_ms);
    set_int(root, "max_message_bytes", cfg.max_message_bytes);
    set_int(root, "max_inflight_sessions", cfg.max_inflight_sessions);
    set_int64(root, "max_inflight_bytes", cfg.max_inflight_bytes);
    set_int(root, "shutdown_drain_timeout_ms", cfg.shutdown_drain_timeout_ms);

    set_string(root, "profile", cfg.profile);
    set_double(root, "spam_threshold_override", cfg.spam_threshold_override);
    set_double(root, "reject_threshold", cfg.reject_threshold);

    set_string(root, "model_dir", cfg.model_dir);
    set_string(root, "model_version_file", cfg.model_version_file);

    set_string(root, "header_prefix", cfg.header_prefix);
    set_int(root, "header_value_max_bytes", cfg.header_value_max_bytes);
    set_string(root, "log_level", cfg.log_level);
    set_bool(root, "log_json", cfg.log_json);
    set_bool(root, "health_enabled", cfg.health_enabled);
    set_string(root, "health_listen", cfg.health_listen);
    set_bool(root, "health_allow_public", cfg.health_allow_public);

    set_string_array(root, "allowlist_senders", cfg.allowlist_senders);
    set_string_array(root, "allowlist_domains", cfg.allowlist_domains);
    set_string_array(root, "blocklist_senders", cfg.blocklist_senders);
    set_string_array(root, "blocklist_domains", cfg.blocklist_domains);
    set_string(root, "blocklist_action", cfg.blocklist_action);

    set_string(root, "event_store_path", cfg.event_store_path);
}

static DomainPolicy parse_domain_policy(const TomlTable& t) {
    DomainPolicy dp;
    set_string(t, "recipient_domain", dp.recipient_domain);
    set_string(t, "mode", dp.mode);
    set_string(t, "profile", dp.profile);
    set_double(t, "spam_threshold_override", dp.spam_threshold_override);
    set_double(t, "reject_threshold", dp.reject_threshold);
    return dp;
}

Config load_config(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        throw std::runtime_error("cannot open config file: " + path);
    }

    std::string text((std::istreambuf_iterator<char>(f)),
                     std::istreambuf_iterator<char>());

    TomlDoc doc = parse_toml(text);

    Config cfg;
    apply_root(doc.root, cfg);

    for (auto& [name, tables] : doc.array_tables) {
        if (name == "domain_policy") {
            for (auto& t : tables) {
                cfg.domain_policies.push_back(parse_domain_policy(t));
            }
        }
    }

    return cfg;
}

// ---------------------------------------------------------------------------
// profile_to_threshold / Config helpers
// ---------------------------------------------------------------------------

double profile_to_threshold(const std::string& profile) {
    if (profile == "cautious")   return 0.70;
    if (profile == "standard")   return 0.50;
    if (profile == "aggressive") return 0.30;
    return 0.50; // fallback
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

static bool is_one_of(const std::string& val,
                      std::initializer_list<const char*> opts) {
    for (auto* o : opts) {
        if (val == o) return true;
    }
    return false;
}

static std::string validate_threshold(const std::string& name, double val) {
    if (val < 0.0 || val > 1.0) {
        return name + " must be in [0, 1], got " + std::to_string(val);
    }
    return "";
}

static std::string validate_list_entries(const std::string& name,
                                         const std::vector<std::string>& list) {
    std::set<std::string> seen;
    for (auto& entry : list) {
        if (entry != to_lower(entry)) {
            return name + ": entry '" + entry + "' must be lowercase";
        }
        if (entry.find('*') != std::string::npos) {
            return name + ": entry '" + entry + "' must not contain wildcards";
        }
        if (!seen.insert(entry).second) {
            return name + ": duplicate entry '" + entry + "'";
        }
    }
    return "";
}

bool split_host_port(const std::string& addr, std::string& host,
                     std::string& port) {
    auto colon = addr.rfind(':');
    if (colon == std::string::npos) return false;
    host = addr.substr(0, colon);
    port = addr.substr(colon + 1);
    // Strip [] around an IPv6 literal, e.g. "[::1]:8892".
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    return true;
}

std::string validate_config(const Config& cfg) {
    // 1. mode
    if (!is_one_of(cfg.mode, {"tag", "reject"})) {
        return "mode must be tag|reject, got '" + cfg.mode + "'";
    }

    // 2. profile
    if (!is_one_of(cfg.profile, {"cautious", "standard", "aggressive"})) {
        return "profile must be cautious|standard|aggressive, got '" +
               cfg.profile + "'";
    }

    // 3. thresholds in [0,1]
    std::string err;
    if (cfg.spam_threshold_override >= 0.0) {
        err = validate_threshold("spam_threshold_override",
                                 cfg.spam_threshold_override);
        if (!err.empty()) return err;
    }
    err = validate_threshold("reject_threshold", cfg.reject_threshold);
    if (!err.empty()) return err;

    // 4. timeout_ms
    if (cfg.timeout_ms < 100 || cfg.timeout_ms > 10000) {
        return "timeout_ms must be in [100, 10000], got " +
               std::to_string(cfg.timeout_ms);
    }

    // 5. max_message_bytes
    if (cfg.max_message_bytes < 65536 || cfg.max_message_bytes > 26214400) {
        return "max_message_bytes must be in [65536, 26214400], got " +
               std::to_string(cfg.max_message_bytes);
    }

    // 6. max_inflight_sessions
    if (cfg.max_inflight_sessions < 1 || cfg.max_inflight_sessions > 1024) {
        return "max_inflight_sessions must be in [1, 1024], got " +
               std::to_string(cfg.max_inflight_sessions);
    }

    // 7. max_inflight_bytes
    if (cfg.max_inflight_bytes < 1048576 || cfg.max_inflight_bytes > 2147483648LL) {
        return "max_inflight_bytes must be in [1048576, 2147483648], got " +
               std::to_string(cfg.max_inflight_bytes);
    }

    // 7b. health_listen (only meaningful when the health server is enabled)
    if (cfg.health_enabled) {
        std::string host, port;
        if (!split_host_port(cfg.health_listen, host, port) || host.empty() ||
            port.empty()) {
            return "health_listen must be host:port (e.g. 127.0.0.1:8892), got '" +
                   cfg.health_listen + "'";
        }
        // size>5 also guards std::stoi below from throwing on a long digit run.
        if (port.size() > 5 ||
            port.find_first_not_of("0123456789") != std::string::npos) {
            return "health_listen port must be numeric, got '" + port + "'";
        }
        int p = std::stoi(port);
        if (p < 1 || p > 65535) {
            return "health_listen port must be in [1, 65535], got '" + port + "'";
        }
        // The /metrics endpoint is unauthenticated; refuse all-interface binds
        // unless the operator explicitly opts in.
        if ((host == "0.0.0.0" || host == "::") && !cfg.health_allow_public) {
            return "health_listen binds all interfaces (" + host +
                   ") which exposes the unauthenticated /metrics endpoint; bind a "
                   "specific address (e.g. 127.0.0.1) or set health_allow_public=true";
        }
    }

    // 8. blocklist_action
    if (cfg.blocklist_action != "reject") {
        return "blocklist_action must be reject, got '" +
               cfg.blocklist_action + "'";
    }

    // 9. allow/block list entries (non-empty, lowercase)
    err = validate_list_entries("allowlist_senders", cfg.allowlist_senders);
    if (!err.empty()) return err;
    err = validate_list_entries("allowlist_domains", cfg.allowlist_domains);
    if (!err.empty()) return err;
    err = validate_list_entries("blocklist_senders", cfg.blocklist_senders);
    if (!err.empty()) return err;
    err = validate_list_entries("blocklist_domains", cfg.blocklist_domains);
    if (!err.empty()) return err;

    // 10. domain_policy entries
    std::set<std::string> seen_domains;
    for (size_t i = 0; i < cfg.domain_policies.size(); ++i) {
        const auto& dp = cfg.domain_policies[i];
        std::string prefix =
            "domain_policy[" + std::to_string(i) + "]: ";

        if (dp.recipient_domain.empty()) {
            return prefix + "recipient_domain is required";
        }
        if (!seen_domains.insert(dp.recipient_domain).second) {
            return prefix + "duplicate recipient_domain '" +
                   dp.recipient_domain + "'";
        }
        if (!dp.mode.empty() &&
            !is_one_of(dp.mode, {"tag", "reject"})) {
            return prefix + "mode must be tag|reject, got '" +
                   dp.mode + "'";
        }
        if (!dp.profile.empty() &&
            !is_one_of(dp.profile,
                       {"cautious", "standard", "aggressive"})) {
            return prefix +
                   "profile must be cautious|standard|aggressive, got '" +
                   dp.profile + "'";
        }
        if (dp.spam_threshold_override >= 0.0) {
            err = validate_threshold(prefix + "spam_threshold_override",
                                     dp.spam_threshold_override);
            if (!err.empty()) return err;
        }
        err = validate_threshold(prefix + "reject_threshold",
                                 dp.reject_threshold);
        if (!err.empty()) return err;
    }

    return "";
}

} // namespace klar
