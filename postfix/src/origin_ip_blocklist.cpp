#include "origin_ip_blocklist.h"

#include "config.h"

#include <cstdlib>

namespace klar {

namespace {

using spam_engine::IpBlocklist;

// Globally routable == worth checking against DROP. A private, loopback or
// link-local hop is our own plumbing and can never be listed, so skipping it is
// both correct and what makes the walk survive internal relay chains.
bool is_global_v4(uint32_t ip) {
    const uint8_t a = static_cast<uint8_t>(ip >> 24), b = static_cast<uint8_t>(ip >> 16);
    if (a == 10 || a == 127 || a == 0) return false;
    if (a == 172 && b >= 16 && b <= 31) return false;
    if (a == 192 && b == 168) return false;
    if (a == 169 && b == 254) return false;          // link-local
    if (a == 100 && b >= 64 && b <= 127) return false;  // CGNAT
    if (a >= 224) return false;                       // multicast / reserved
    return true;
}

bool is_global_v6(uint64_t hi, uint64_t lo) {
    if (hi == 0 && lo == 1) return false;             // ::1
    if (hi == 0 && lo == 0) return false;             // ::
    const uint16_t top = static_cast<uint16_t>(hi >> 48);
    if ((top & 0xFE00) == 0xFC00) return false;       // fc00::/7 unique-local
    if ((top & 0xFFC0) == 0xFE80) return false;       // fe80::/10 link-local
    // ::ffff:a.b.c.d — judge it as the IPv4 host it is.
    if (hi == 0 && (lo >> 32) == 0xFFFFULL) {
        return is_global_v4(static_cast<uint32_t>(lo & 0xFFFFFFFFULL));
    }
    return true;
}

bool is_global(const std::string& ip) {
    uint32_t v4 = 0;
    if (IpBlocklist::parse_ipv4(ip, &v4)) return is_global_v4(v4);
    uint64_t hi = 0, lo = 0;
    if (IpBlocklist::parse_ipv6(ip, &hi, &lo)) return is_global_v6(hi, lo);
    return false;
}

}  // namespace

bool TrustedRelays::load(const std::vector<std::string>& cidrs, std::string* err) {
    v4_.clear();
    v6_.clear();
    for (const std::string& entry : cidrs) {
        const size_t slash = entry.find('/');
        const std::string addr = slash == std::string::npos ? entry : entry.substr(0, slash);
        // A bare address is its own /32 or /128.
        long bits = -1;
        if (slash != std::string::npos) {
            const std::string suffix = entry.substr(slash + 1);
            if (suffix.empty() || suffix.find_first_not_of("0123456789") != std::string::npos) {
                if (err) *err = "trusted_relay_cidrs: bad prefix length in '" + entry + "'";
                return false;
            }
            bits = std::strtol(suffix.c_str(), nullptr, 10);
        }

        uint32_t v4 = 0;
        uint64_t hi = 0, lo = 0;
        if (IpBlocklist::parse_ipv4(addr, &v4)) {
            if (bits < 0) bits = 32;
            if (bits > 32) {
                if (err) *err = "trusted_relay_cidrs: IPv4 prefix > 32 in '" + entry + "'";
                return false;
            }
            const uint32_t mask = bits == 0 ? 0u : (0xFFFFFFFFu << (32 - bits));
            v4_.push_back({v4 & mask, (v4 & mask) | ~mask});
        } else if (IpBlocklist::parse_ipv6(addr, &hi, &lo)) {
            if (bits < 0) bits = 128;
            if (bits > 128) {
                if (err) *err = "trusted_relay_cidrs: IPv6 prefix > 128 in '" + entry + "'";
                return false;
            }
            const uint64_t mask_hi = bits >= 64 ? ~0ULL
                                   : (bits == 0 ? 0ULL : (~0ULL << (64 - bits)));
            const uint64_t mask_lo = bits <= 64 ? 0ULL
                                   : (bits == 128 ? ~0ULL : (~0ULL << (128 - bits)));
            const uint64_t base_hi = hi & mask_hi, base_lo = lo & mask_lo;
            v6_.push_back({base_hi, base_lo, base_hi | ~mask_hi, base_lo | ~mask_lo});
        } else {
            if (err) *err = "trusted_relay_cidrs: not an IP or CIDR: '" + entry + "'";
            return false;
        }
    }
    return true;
}

bool TrustedRelays::contains(const std::string& ip) const {
    uint32_t v4 = 0;
    if (IpBlocklist::parse_ipv4(ip, &v4)) {
        for (const R4& r : v4_) {
            if (v4 >= r.lo && v4 <= r.hi) return true;
        }
        return false;
    }
    uint64_t hi = 0, lo = 0;
    if (!IpBlocklist::parse_ipv6(ip, &hi, &lo)) return false;
    // A v4-mapped literal is the IPv4 host it names, so it matches IPv4 entries.
    if (hi == 0 && (lo >> 32) == 0xFFFFULL) {
        const uint32_t mapped = static_cast<uint32_t>(lo & 0xFFFFFFFFULL);
        for (const R4& r : v4_) {
            if (mapped >= r.lo && mapped <= r.hi) return true;
        }
    }
    for (const R6& r : v6_) {
        const bool ge = hi > r.lo_hi || (hi == r.lo_hi && lo >= r.lo_lo);
        const bool le = hi < r.hi_hi || (hi == r.hi_hi && lo <= r.hi_lo);
        if (ge && le) return true;
    }
    return false;
}

namespace {

// Content of each `open`..`close` group in the line, in order.
std::vector<std::string> delimited(const std::string& line, char open, char close) {
    std::vector<std::string> out;
    for (size_t i = 0; i < line.size(); ++i) {
        if (line[i] != open) continue;
        const size_t end = line.find(close, i + 1);
        if (end == std::string::npos) break;
        out.push_back(line.substr(i + 1, end - i - 1));
        i = end;
    }
    return out;
}

std::string trimmed(const std::string& s) {
    const size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return {};
    return s.substr(b, s.find_last_not_of(" \t") - b + 1);
}

}  // namespace

std::string received_hop_ip(const std::string& line) {
    // ONLY bracketed (or parenthesised-and-bare) addresses count. The HELO name
    // earlier in the line is chosen by the SENDER — "from 192.0.2.5 (unknown
    // [203.0.113.7])" is a perfectly ordinary line whose first IP-looking token
    // is the attacker's — so a scan that took the first address in the line
    // would read a spoofable string as the origin. The bracketed form is what
    // the receiving MTA itself wrote.
    for (std::string token : delimited(line, '[', ']')) {
        if (token.compare(0, 5, "IPv6:") == 0) token = token.substr(5);
        token = trimmed(token);
        if (is_global(token)) return token;
    }
    // Some MTAs write the bare address in parentheses: "from x (203.0.113.7)".
    // Accepted only when the WHOLE group is the address, so "(unknown [1.2.3.4])"
    // is handled by the bracket pass above and never by loose scanning.
    for (const std::string& group : delimited(line, '(', ')')) {
        const std::string token = trimmed(group);
        if (is_global(token)) return token;
    }
    return {};
}

std::string resolve_origin_ip(const std::string& connect_ip,
                              const std::vector<std::string>& received,
                              const TrustedRelays& trusted) {
    // Not behind a configured relay: what we observed IS the origin. Reading
    // headers here would only add forgery surface, so we do not.
    if (trusted.empty() || connect_ip.empty() || !trusted.contains(connect_ip)) {
        return connect_ip;
    }
    // Behind a relay. Walk down while each recorded peer is one of ours; the
    // first untrusted address was written by a hop we trust. Stop there: the
    // lines below it are whatever the sender chose to write.
    for (const std::string& line : received) {
        const std::string hop = received_hop_ip(line);
        if (hop.empty()) continue;      // internal handoff with no routable peer
        if (trusted.contains(hop)) continue;
        return hop;
    }
    return {};
}

OriginIpBlocklist::Reload OriginIpBlocklist::load(const Config& cfg) {
    std::lock_guard<std::mutex> lock(mutex_);
    max_age_days_ = cfg.ip_blocklist_max_age_days;
    if (cfg.ip_blocklist_path.empty()) {
        list_ = spam_engine::IpBlocklist();  // path cleared -> signal off
        return Reload::Disabled;
    }
    spam_engine::IpBlocklist fresh;
    if (!fresh.load(cfg.ip_blocklist_path)) return Reload::Failed;
    list_ = std::move(fresh);
    return Reload::Loaded;
}

bool OriginIpBlocklist::contains(const std::string& ip) const {
    if (ip.empty()) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    return list_.contains(ip);
}

size_t OriginIpBlocklist::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return list_.size();
}

bool OriginIpBlocklist::stale() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (list_.empty()) return false;
    return list_.stale(max_age_days_, std::time(nullptr));
}

std::string OriginIpBlocklist::status() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string s = "ranges=" + std::to_string(list_.size());
    if (!list_.empty() && list_.stale(max_age_days_, std::time(nullptr))) {
        s += " STALE";
    }
    return s;
}

} // namespace klar
