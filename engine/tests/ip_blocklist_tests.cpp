// Unit tests for the origin-IP blocklist (TASK-113 — Spamhaus DROP). Dependency-free
// (no model), like url_blocklist_tests: builds a tiny .bin, loads it, checks lookups,
// and pins the address parser, which is the part with real edge cases.

#include "../ip_blocklist.h"
#include "must_fopen.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

namespace se = spam_engine;

namespace {
int g_fail = 0, g_checks = 0;
void check(bool c, const char* what) {
  ++g_checks;
  if (!c) { ++g_fail; std::printf("  [FAIL] %s\n", what); }
}

struct R4 { uint32_t start, end; };
struct R6 { uint64_t start_hi, start_lo, end_hi, end_lo; };

// Writes a header with the given counts followed by exactly `bytes` of payload,
// so a malformed artifact is expressed as "claims N, ships M" rather than another
// copy of the fwrite dance.
void write_raw(const char* path, uint32_t built_at, uint32_t n4, uint32_t n6,
               const void* payload, size_t bytes) {
  std::FILE* f = must_fopen(path, "wb");
  std::fwrite("KLARIP1\0", 1, 8, f);
  const uint32_t header[4] = {built_at, n4, n6, 0};
  std::fwrite(header, 4, 4, f);
  if (bytes > 0) { std::fwrite(payload, 1, bytes, f);
}
  std::fclose(f);
}

void write_bin(const char* path, uint32_t built_at,
               const std::vector<R4>& v4, const std::vector<R6>& v6) {
  std::vector<uint8_t> payload((v4.size() * sizeof(R4)) + (v6.size() * sizeof(R6)));
  std::memcpy(payload.data(), v4.data(), v4.size() * sizeof(R4));
  std::memcpy(payload.data() + (v4.size() * sizeof(R4)), v6.data(),
              v6.size() * sizeof(R6));
  write_raw(path, built_at, static_cast<uint32_t>(v4.size()),
            static_cast<uint32_t>(v6.size()), payload.data(), payload.size());
}

uint32_t ipv4(const char* s) {
  uint32_t v = 0;
  se::IpBlocklist::parse_ipv4(s, &v);
  return v;
}
}  // namespace

int main() {
  // 1. IPv4 parsing, including the forms a permissive parser gets wrong.
  uint32_t v = 0;
  check(se::IpBlocklist::parse_ipv4("203.0.113.7", &v) && v == 0xCB007107U,
        "parse dotted quad");
  check(se::IpBlocklist::parse_ipv4("0.0.0.0", &v) && v == 0U, "parse 0.0.0.0");
  check(se::IpBlocklist::parse_ipv4("255.255.255.255", &v) && v == 0xFFFFFFFFU,
        "parse broadcast");
  check(!se::IpBlocklist::parse_ipv4("010.0.0.1", &v),
        "leading-zero octet rejected (would be octal to some resolvers)");
  check(!se::IpBlocklist::parse_ipv4("256.0.0.1", &v), "octet > 255 rejected");
  check(!se::IpBlocklist::parse_ipv4("1.2.3", &v), "three octets rejected");
  check(!se::IpBlocklist::parse_ipv4("1.2.3.4.5", &v), "five octets rejected");
  check(!se::IpBlocklist::parse_ipv4("1.2.3.4 ", &v), "trailing space rejected");
  check(!se::IpBlocklist::parse_ipv4("", &v), "empty rejected");

  // 2. IPv6 parsing: compression, IPv4 tail, brackets, zone, malformed forms.
  uint64_t hi = 0;
  uint64_t lo = 0;
  check(se::IpBlocklist::parse_ipv6("2001:db8::1", &hi, &lo) &&
        hi == 0x20010db800000000ULL && lo == 1ULL, "parse compressed v6");
  check(se::IpBlocklist::parse_ipv6(
            "2001:0db8:0000:0000:0000:0000:0000:0001", &hi, &lo) &&
        hi == 0x20010db800000000ULL && lo == 1ULL, "parse full v6");
  check(se::IpBlocklist::parse_ipv6("::", &hi, &lo) && hi == 0 && lo == 0,
        "parse unspecified");
  check(se::IpBlocklist::parse_ipv6("::1", &hi, &lo) && hi == 0 && lo == 1,
        "parse loopback");
  check(se::IpBlocklist::parse_ipv6("::ffff:203.0.113.7", &hi, &lo) &&
        hi == 0 && lo == 0x0000ffffCB007107ULL, "parse v4-mapped tail");
  check(se::IpBlocklist::parse_ipv6("[2001:db8::1]", &hi, &lo) &&
        lo == 1ULL, "parse bracketed literal");
  check(se::IpBlocklist::parse_ipv6("fe80::1%en0", &hi, &lo) &&
        hi == 0xfe80000000000000ULL && lo == 1ULL, "parse zone suffix");
  check(!se::IpBlocklist::parse_ipv6("2001:db8::1::2", &hi, &lo),
        "two '::' rejected");
  check(!se::IpBlocklist::parse_ipv6("2001:db8:::1", &hi, &lo), "':::' rejected");
  check(!se::IpBlocklist::parse_ipv6("2001:db8::1:", &hi, &lo),
        "trailing single ':' rejected");
  check(!se::IpBlocklist::parse_ipv6(":2001:db8::1", &hi, &lo),
        "leading single ':' rejected");
  check(!se::IpBlocklist::parse_ipv6("12345::1", &hi, &lo), "5-hex group rejected");
  check(!se::IpBlocklist::parse_ipv6("203.0.113.7", &hi, &lo),
        "v4 text is not v6");
  check(!se::IpBlocklist::parse_ipv6("", &hi, &lo), "empty rejected");
  check(!se::IpBlocklist::parse_ipv6(
            "1:2:3:4:5:6:7:8:9", &hi, &lo), "nine groups rejected");

  // 3. round-trip a small blocklist: boundaries, gaps, both families.
  const char* p = "/tmp/klar_ipblk_test.bin";
  const auto now = static_cast<uint32_t>(std::time(nullptr));
  write_bin(p, now,
            {{ipv4("192.0.2.0"), ipv4("192.0.2.255")},      // 192.0.2.0/24
             {ipv4("203.0.113.16"), ipv4("203.0.113.31")}}, // 203.0.113.16/28
            {{0x20010db800000000ULL, 0, 0x20010db8ffffffffULL,
              0xffffffffffffffffULL}});
  se::IpBlocklist bl;
  check(bl.load(p), "load ok");
  check(bl.size() == 3, "size == 3 ranges");
  check(bl.contains("192.0.2.0"), "first address of a range hits");
  check(bl.contains("192.0.2.255"), "last address of a range hits");
  check(bl.contains("192.0.2.128"), "middle of a range hits");
  check(!bl.contains("192.0.1.255"), "address just below a range misses");
  check(!bl.contains("192.0.3.0"), "address just above a range misses");
  check(bl.contains("203.0.113.16") && bl.contains("203.0.113.31"),
        "second range boundaries hit");
  check(!bl.contains("203.0.113.15") && !bl.contains("203.0.113.32"),
        "second range neighbours miss");
  // An IPv4-mapped v6 literal must reach the IPv4 table: a dual-stack MTA hands
  // the milter this form for a plain IPv4 connection, and searching the v6 table
  // would silently disable the signal for every IPv4 range.
  check(bl.contains("::ffff:192.0.2.1"), "v4-mapped literal hits the v4 range");
  check(bl.contains("::ffff:c000:201"), "v4-mapped in hex form hits the v4 range");
  check(!bl.contains("::ffff:192.0.3.1"), "unlisted v4-mapped misses");
  check(bl.contains("2001:db8::1"), "listed v6 hits");
  check(!bl.contains("2001:db9::1"), "unlisted v6 misses");
  check(!bl.contains("not-an-ip"), "garbage input is not a hit");
  check(!bl.contains(""), "empty input is not a hit");

  // 4. staleness is reported, never fatal: an old list still only contains
  //    netblocks Spamhaus listed.
  check(!bl.stale(7, static_cast<std::time_t>(now)), "fresh list is not stale");
  check(bl.stale(7, static_cast<std::time_t>(now) + (static_cast<std::time_t>(8 * 86400))),
        "8-day-old list is stale at a 7-day budget");
  check(bl.contains("192.0.2.1"), "a stale list still answers lookups");

  // 5. missing / malformed file is safe — the signal is just disabled.
  se::IpBlocklist bad;
  check(!bad.load("/tmp/klar_ip_does_not_exist.bin"), "missing file -> false");
  check(bad.empty() && !bad.contains("192.0.2.1"), "unloaded -> contains false");
  check(bad.built_at() == 0 && bad.stale(7, std::time(nullptr)),
        "unloaded -> no build time, reported stale");

  // 6. a count larger than the file's payload must be rejected BEFORE reserving
  //    (a 4-billion count would allocate to OOM) — same guard as url_blocklist.
  const char* lying = "/tmp/klar_ipblk_lying_count.bin";
  const R4 one = {ipv4("192.0.2.0"), ipv4("192.0.2.255")};
  write_raw(lying, now, /*n4=*/4000000000U, /*n6=*/0, &one, sizeof(R4));
  se::IpBlocklist lie;
  check(!lie.load(lying), "lying count -> load returns false, no OOM");
  check(lie.empty(), "lying count -> stays empty");

  // 7. a truncated IPv6 section is caught too (the v4 half must not survive it).
  const char* trunc = "/tmp/klar_ipblk_trunc_v6.bin";
  uint8_t partial[sizeof(R4) + 8] = {0};  // the v4 range + 8 of the 32 v6 bytes
  std::memcpy(partial, &one, sizeof(R4));
  write_raw(trunc, now, /*n4=*/1, /*n6=*/1, partial, sizeof(partial));
  se::IpBlocklist cut;
  check(!cut.load(trunc), "truncated v6 section -> load returns false");
  check(cut.empty(), "truncated v6 section -> stays empty");

  std::printf("\n%d checks, %d failures\n", g_checks, g_fail);
  return g_fail == 0 ? 0 : 1;
}
