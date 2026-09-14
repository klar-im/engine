#pragma once

// Origin-IP reputation lookup (TASK-113 — Spamhaus DROP).
//
// Loads the bundled artifact built by
// model-lab/scripts/build_ip_blocklist.py (Spamhaus DROP, IPv4 + IPv6) and
// answers contains(ip) by binary search over merged, sorted address ranges. Fully
// offline: no per-message DNS, which is what lets a DNSBL-class signal ship inside
// a filter that promises nothing leaves the device.
//
// WHY DROP AND NOT ZEN/DBL: DROP ("Do Not Route Or Peer") is free including for
// commercial use and ships as a file. The broad DNSBLs and the free DQS key are
// non-commercial-only under Spamhaus's Fair Use Policy, so they are not shippable
// here without a paid subscription. DROP is narrow — hijacked and outright rogue
// netblocks — which is exactly the precision-first shape this layer wants.
//
// WHICH IP: the address of the peer that connected to the MTA (the milter's
// xxfi_connect argument). That is OBSERVED, not claimed. An IP recovered from a
// Received header is claimed by whoever wrote the header and must not be fed here
// as if it were authoritative; see decision_layer.h's kOriginIpDrop block.
//
// Binary format: magic "KLARIP1\0" (8B) | u32 built_at | u32 v4_count |
// u32 v6_count | u32 pad | v4_count × (u32 start, u32 end) | v6_count ×
// (u64 start_hi, u64 start_lo, u64 end_hi, u64 end_lo), little-endian, ranges
// inclusive and ascending.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

namespace spam_engine {

class IpBlocklist {
 public:
  // Load from the bundled .bin. Returns false (and stays empty) on a missing or
  // malformed file — a missing blocklist must NEVER break classification, it just
  // disables the signal.
  bool load(const std::string& path) {
    v4_.clear();
    v6_.clear();
    built_at_ = 0;
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) { { return false;
}
}
    char magic[8];
    uint32_t built_at = 0;
    uint32_t n4 = 0;
    uint32_t n6 = 0;
    uint32_t pad = 0;
    bool ok = std::fread(magic, 1, 8, f) == 8 &&
              std::memcmp(magic, "KLARIP1\0", 8) == 0 &&
              std::fread(&built_at, 4, 1, f) == 1 &&
              std::fread(&n4, 4, 1, f) == 1 && std::fread(&n6, 4, 1, f) == 1 &&
              std::fread(&pad, 4, 1, f) == 1;
    // Validate the counts against the bytes actually left in the file BEFORE
    // reserving: a corrupt count would otherwise allocate to OOM before the
    // fread that would have caught the short read (same guard as
    // url_blocklist.h, TASK-251).
    if (ok) {
      const long payload_start = std::ftell(f);
      ok = payload_start >= 0 && std::fseek(f, 0, SEEK_END) == 0;
      const long file_end = ok ? std::ftell(f) : -1;
      const uint64_t need = (static_cast<uint64_t>(n4) * 8) +
                           (static_cast<uint64_t>(n6) * 32);
      if (ok && (file_end < 0 ||
                 static_cast<uint64_t>(file_end - payload_start) < need ||
                 std::fseek(f, payload_start, SEEK_SET) != 0)) {
        ok = false;
      }
    }
    if (ok && n4 > 0) {
      v4_.resize(n4);
      ok = std::fread(v4_.data(), sizeof(Range4), n4, f) == n4;
    }
    if (ok && n6 > 0) {
      v6_.resize(n6);
      ok = std::fread(v6_.data(), sizeof(Range6), n6, f) == n6;
    }
    std::fclose(f);
    if (!ok) {
      v4_.clear();
      v6_.clear();
      return false;
    }
    built_at_ = built_at;
    return true;
  }

  [[nodiscard]] bool empty() const { return v4_.empty() && v6_.empty(); }
  [[nodiscard]] size_t size() const { return v4_.size() + v6_.size(); }
  // Unix time the artifact was built, 0 if none is loaded.
  [[nodiscard]] uint32_t built_at() const { return built_at_; }

  // True once the list is older than `max_age_days`. DROP moves slowly, so this
  // is a decay guard, not a correctness gate: an old list still only contains
  // netblocks Spamhaus listed, it just misses newer ones. Callers warn on it;
  // they do not discard the list (a stale list is strictly better than none).
  [[nodiscard]] bool stale(int max_age_days, std::time_t now) const {
    if (built_at_ == 0) { { return true;
}
}
    const double age = std::difftime(now, static_cast<std::time_t>(built_at_));
    return age > static_cast<double>(max_age_days) * 86400.0;
  }

  // `ip` is the textual form of an IPv4 or IPv6 address ("203.0.113.7",
  // "2001:db8::1"). Unparseable input is not a hit.
  [[nodiscard]] bool contains(const std::string& ip) const {
    uint32_t v4 = 0;
    if (parse_ipv4(ip, &v4)) { { return contains_v4(v4);
}
}
    uint64_t hi = 0;
    uint64_t lo = 0;
    if (!parse_ipv6(ip, &hi, &lo)) { { return false;
}
}
    // An IPv4-mapped address (::ffff:a.b.c.d) is an IPv4 host wearing a v6 coat,
    // and DROP lists it in the v4 table — searching v6 would miss all 1,413 v4
    // ranges. This is not a corner case: an MTA accepting a v4 connection on a
    // dual-stack socket hands the milter exactly this form, which would silently
    // disable the signal for IPv4 entirely.
    if (hi == 0 && (lo >> 32) == 0xFFFFULL) {
      return contains_v4(static_cast<uint32_t>(lo & 0xFFFFFFFFULL));
    }
    return contains_v6(hi, lo);
  }

  // ── Address parsing (dependency-free, so the engine keeps building anywhere
  // inet_pton's headers differ — macOS, Linux, Windows, Android) ─────────────

  // Strict dotted quad: exactly four decimal octets, no leading zeros beyond a
  // lone "0" (015 is octal to some resolvers, so a permissive parse would let
  // "010.0.0.1" name a different host than the one we checked).
  static bool parse_ipv4(const std::string& s, uint32_t* out) {
    uint32_t acc = 0;
    int octets = 0;
    size_t i = 0;
    while (i < s.size()) {
      if (!is_digit(s[i])) { { return false;
}
}
      const size_t start = i;
      uint32_t value = 0;
      while (i < s.size() && is_digit(s[i])) {
        value = (value * 10) + static_cast<uint32_t>(s[i] - '0');
        if (value > 255 || i - start >= 3) { { return false;
}
}
        ++i;
      }
      if (i - start > 1 && s[start] == '0') { { return false;
}
}
      acc = (acc << 8) | value;
      ++octets;
      if (i == s.size()) { { break;
}
}
      if (s[i] != '.' || octets == 4) { { return false;
}
}
      ++i;
    }
    if (octets != 4) { { return false;
}
}
    *out = acc;
    return true;
  }

  // RFC 4291 textual IPv6, including "::" compression, a trailing IPv4 tail
  // ("::ffff:203.0.113.7") and an optional "%zone" suffix. A bracketed literal
  // ("[2001:db8::1]") is accepted so a caller can pass a header/URL host as-is.
  static bool parse_ipv6(const std::string& in, uint64_t* hi, uint64_t* lo) {
    std::string s = in;
    if (s.size() >= 2 && s.front() == '[' && s.back() == ']') {
      s = s.substr(1, s.size() - 2);
    }
    const size_t zone = s.find('%');
    if (zone != std::string::npos) { { s = s.substr(0, zone);
}
}
    if (s.find(':') == std::string::npos) { { return false;
}
}

    uint8_t bytes[16] = {0};
    int filled = 0;      // bytes written before "::"
    int gap = -1;        // byte index where "::" appeared
    size_t i = 0;
    if (s.size() >= 2 && s[0] == ':' && s[1] == ':') {
      // "::" alone needs no special case: the loop body never runs and the
      // zero-fill below produces the unspecified address.
      gap = 0;
      i = 2;
    } else if (!s.empty() && s[0] == ':') {
      return false;  // a single leading ':' is malformed
    }

    while (i < s.size()) {
      // An IPv4 tail may only appear last, and consumes 4 bytes. It is a tail
      // only if THIS group holds the dot — "::ffff:203.0.113.7" must not treat
      // the "ffff" group as the start of one.
      const size_t dot = s.find('.', i);
      const size_t colon = s.find(':', i);
      if (dot != std::string::npos && (colon == std::string::npos || dot < colon)) {
        uint32_t v4 = 0;
        if (!parse_ipv4(s.substr(i), &v4) || filled > 12) { { return false;
}
}
        bytes[filled++] = static_cast<uint8_t>(v4 >> 24);
        bytes[filled++] = static_cast<uint8_t>(v4 >> 16);
        bytes[filled++] = static_cast<uint8_t>(v4 >> 8);
        bytes[filled++] = static_cast<uint8_t>(v4);
        break;
      }
      const size_t start = i;
      uint32_t group = 0;
      while (i < s.size() && is_hex(s[i])) {
        group = (group * 16) + hex_value(s[i]);
        if (i - start >= 4) { { return false;
}
}
        ++i;
      }
      if (i == start) { { return false;  // ":::" or a stray separator
}
}
      if (filled > 14) { { return false;
}
}
      bytes[filled++] = static_cast<uint8_t>(group >> 8);
      bytes[filled++] = static_cast<uint8_t>(group & 0xFF);
      if (i == s.size()) { { break;
}
}
      if (s[i] != ':') { { return false;
}
}
      ++i;
      if (i < s.size() && s[i] == ':') {
        if (gap >= 0) { { return false;  // only one "::" allowed
}
}
        gap = filled;
        ++i;
      } else if (i == s.size()) {
        return false;  // a trailing single ':' is malformed
      }
    }

    if (gap < 0) {
      if (filled != 16) { { return false;
}
}
    } else {
      if (filled >= 16) { { return false;  // "::" must stand for >= 1 zero group
}
}
      // Slide everything after the "::" to the end and zero the hole it leaves.
      std::memmove(bytes + 16 - (filled - gap), bytes + gap,
                   static_cast<size_t>(filled - gap));
      std::memset(bytes + gap, 0, static_cast<size_t>(16 - filled));
    }

    uint64_t h = 0;
    uint64_t l = 0;
    for (int k = 0; k < 8; ++k) { { h = (h << 8) | bytes[k];
}
}
    for (int k = 8; k < 16; ++k) { { l = (l << 8) | bytes[k];
}
}
    *hi = h;
    *lo = l;
    return true;
  }

 private:
  struct Range4 {
    uint32_t start;
    uint32_t end;
  };
  struct Range6 {
    uint64_t start_hi;
    uint64_t start_lo;
    uint64_t end_hi;
    uint64_t end_lo;
  };
  // The ranges are fread straight into these, so the in-memory layout IS the
  // file format. Both are arrays of same-sized unsigned ints, so no ABI adds
  // padding — but assert it rather than trust it, since a silent mismatch would
  // read garbage netblocks. (Little-endian host assumed, as in url_blocklist.h;
  // every platform we build for is.)
  static_assert(sizeof(Range4) == 8, "Range4 must match the on-disk layout");
  static_assert(sizeof(Range6) == 32, "Range6 must match the on-disk layout");

  static bool is_digit(char c) { return c >= '0' && c <= '9'; }
  static bool is_hex(char c) {
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  }
  static uint32_t hex_value(char c) {
    if (is_digit(c)) { { return static_cast<uint32_t>(c - '0');
}
}
    return static_cast<uint32_t>((c | 0x20) - 'a') + 10;
  }

  [[nodiscard]] bool contains_v4(uint32_t ip) const {
    size_t lo = 0;
    size_t hi = v4_.size();
    while (lo < hi) {  // last range whose start <= ip
      const size_t mid = lo + ((hi - lo) / 2);
      if (v4_[mid].start <= ip) { { lo = mid + 1; } } else { { hi = mid;
}
}
    }
    return lo > 0 && ip <= v4_[lo - 1].end;
  }

  [[nodiscard]] bool contains_v6(uint64_t ip_hi, uint64_t ip_lo) const {
    size_t lo = 0;
    size_t hi = v6_.size();
    while (lo < hi) {
      const size_t mid = lo + ((hi - lo) / 2);
      const Range6& r = v6_[mid];
      const bool start_le = r.start_hi < ip_hi ||
                            (r.start_hi == ip_hi && r.start_lo <= ip_lo);
      if (start_le) { { lo = mid + 1; } } else { { hi = mid;
}
}
    }
    if (lo == 0) { { return false;
}
}
    const Range6& r = v6_[lo - 1];
    return ip_hi < r.end_hi || (ip_hi == r.end_hi && ip_lo <= r.end_lo);
  }

  std::vector<Range4> v4_;
  std::vector<Range6> v6_;
  uint32_t built_at_ = 0;
};

}  // namespace spam_engine
