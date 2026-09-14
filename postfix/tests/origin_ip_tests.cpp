// Unit tests for the trusted-relay origin walk (TASK-387).
//
// The whole value of this signal rests on one claim: the address we pull out of
// the Received chain was written by a host the operator trusts, not by the
// sender. These tests exist to hold that claim, so the forged-hop cases matter
// more than the happy path.

#include "origin_ip_blocklist.h"

#include <cstdio>
#include <string>
#include <vector>

namespace {
int g_fail = 0, g_checks = 0;
void check(bool c, const char* what) {
  ++g_checks;
  if (!c) { ++g_fail; std::printf("  [FAIL] %s\n", what); }
}

klar::TrustedRelays relays(const std::vector<std::string>& cidrs) {
  klar::TrustedRelays r;
  std::string err;
  if (!r.load(cidrs, &err)) std::printf("  [SETUP FAIL] %s\n", err.c_str());
  return r;
}

// Our staging shape: Stalwart on the host relays into the Postfix pod, so the
// milter's peer is the podman bridge gateway and the real client is one hop down.
const char* kOurHop =
    "from 10.88.0.1 (unknown [10.88.0.1]) by klar-postfix (Postfix) with ESMTP "
    "id AAA; Thu, 30 Jul 2026 12:00:00 +0000";
const char* kRelayHop =
    "from spammer.example ([203.0.113.7]) by mail.klar.im (Stalwart SMTP) with "
    "ESMTP id BBB; Thu, 30 Jul 2026 12:00:00 +0000";
}  // namespace

int main() {
  // 1. CIDR parsing, including the forms an operator will actually write.
  std::string err;
  klar::TrustedRelays r;
  check(r.load({"10.88.0.0/24"}, &err), "parses an IPv4 CIDR");
  check(r.contains("10.88.0.1") && r.contains("10.88.0.255"), "CIDR covers its range");
  check(!r.contains("10.88.1.1"), "CIDR does not cover the next range");
  check(r.load({"192.0.2.7"}, &err) && r.contains("192.0.2.7") && !r.contains("192.0.2.8"),
        "a bare address is its own /32");
  check(r.load({"2001:db8::/32"}, &err) && r.contains("2001:db8::1") &&
        !r.contains("2001:db9::1"), "parses an IPv6 CIDR");
  check(r.load({"10.0.0.0/8"}, &err) && r.contains("::ffff:10.1.2.3"),
        "a v4-mapped literal matches an IPv4 range (dual-stack MTAs send these)");
  check(r.load({}, &err) && r.empty(), "an empty list is empty, not an error");
  check(!r.load({"10.88.0.0/99"}, &err), "prefix > 32 rejected");
  check(!r.load({"not-an-ip"}, &err), "garbage rejected");
  check(!r.load({"10.88.0.0/x"}, &err), "non-numeric prefix rejected");
  check(!err.empty(), "a rejection explains itself");

  // 2. Hop extraction: the address, out of the free-text soup MTAs write.
  check(klar::received_hop_ip(kRelayHop) == "203.0.113.7", "bracketed address extracted");
  check(klar::received_hop_ip("from x (unknown [198.51.100.9]) by y") == "198.51.100.9",
        "address inside a parenthesised clause extracted");
  check(klar::received_hop_ip("from x ([IPv6:2001:db8::5]) by y") == "2001:db8::5",
        "IPv6: prefix stripped");
  check(klar::received_hop_ip("from localhost ([127.0.0.1]) by y").empty(),
        "loopback is not an origin");
  check(klar::received_hop_ip("from x ([10.0.0.5]) by y").empty(),
        "a private hop is not an origin");
  check(klar::received_hop_ip("by mail.example with local id 42").empty(),
        "a hop with no address yields nothing");
  check(klar::received_hop_ip("from x ([999.1.1.1]) by y").empty(),
        "a non-address in brackets is not an origin");
  check(klar::received_hop_ip("from x (203.0.113.7) by y") == "203.0.113.7",
        "a bare parenthesised address is accepted");
  // THE SPOOF: the HELO name is chosen by the sender. A scan that took the first
  // IP-looking token in the line would read it as the origin.
  check(klar::received_hop_ip(
            "from 192.0.2.5 (unknown [203.0.113.7]) by mail.klar.im id AAA") ==
        "203.0.113.7",
        "a sender-chosen HELO that looks like an IP does not beat the bracketed one");

  // 3. The walk. With no trusted relay configured, headers are never consulted:
  //    the observed peer IS the origin.
  const std::vector<std::string> chain = {kOurHop, kRelayHop};
  check(klar::resolve_origin_ip("198.51.100.1", chain, relays({})) == "198.51.100.1",
        "no trusted relay -> the observed peer is the origin, headers ignored");
  check(klar::resolve_origin_ip("198.51.100.1", chain, relays({"10.88.0.0/24"})) ==
        "198.51.100.1",
        "an untrusted peer is the origin even when relays ARE configured");

  // Behind our relay: the observed peer is ours, so walk to the first hop that
  // is not. This is the case the whole task exists for.
  check(klar::resolve_origin_ip("10.88.0.1", chain, relays({"10.88.0.0/24"})) ==
        "203.0.113.7",
        "behind a trusted relay the origin comes from the chain");

  // Several of our own hops in a row are all skipped.
  const std::vector<std::string> long_chain = {
      kOurHop, "from 10.88.0.2 ([10.88.0.2]) by inner (Postfix) id CCC", kRelayHop};
  check(klar::resolve_origin_ip("10.88.0.1", long_chain, relays({"10.88.0.0/24"})) ==
        "203.0.113.7", "consecutive trusted hops are walked through");

  // 4. THE ABUSE CASE. A sender writes its own Received lines; they sit BELOW the
  //    first untrusted hop, so they must never be read. Otherwise anyone could
  //    forge a DROP-listed hop onto a reply or a mailing-list post and get
  //    somebody else's mail condemned.
  const std::vector<std::string> forged = {
      kOurHop,
      kRelayHop,                                        // real client, untrusted
      "from evil ([1.10.16.1]) by fake.example id XXX", // attacker-written
      "from worse ([1.10.16.2]) by fake.example id YYY"};
  check(klar::resolve_origin_ip("10.88.0.1", forged, relays({"10.88.0.0/24"})) ==
        "203.0.113.7",
        "the walk stops at the first untrusted hop; forged lines below are ignored");

  // The same forgery when the message arrives DIRECTLY (no relay): still ignored,
  // because without a trusted relay the chain is never consulted at all.
  check(klar::resolve_origin_ip("198.51.100.1", forged, relays({})) == "198.51.100.1",
        "a direct connection never reads the chain, forged or not");

  // An attacker who forges a hop that LOOKS like our relay cannot promote his own
  // next line: the walk skips trusted addresses, so his forged 'trusted' hop is
  // skipped too and the real untrusted client is still what we land on.
  const std::vector<std::string> impersonating = {
      kOurHop,
      kRelayHop,                                          // real client
      "from x ([10.88.0.9]) by fake.example id ZZZ",      // pretends to be ours
      "from evil ([1.10.16.1]) by fake.example id WWW"};
  check(klar::resolve_origin_ip("10.88.0.1", impersonating, relays({"10.88.0.0/24"})) ==
        "203.0.113.7",
        "a forged 'trusted' hop below the real client cannot promote the line under it");

  // 5. Degenerate chains resolve to nothing rather than to something wrong.
  check(klar::resolve_origin_ip("10.88.0.1", {}, relays({"10.88.0.0/24"})).empty(),
        "behind a relay with no Received lines -> no origin");
  check(klar::resolve_origin_ip("10.88.0.1", {kOurHop}, relays({"10.88.0.0/24"})).empty(),
        "a chain that is entirely our own hops -> no origin");
  check(klar::resolve_origin_ip("", chain, relays({"10.88.0.0/24"})).empty(),
        "no observed peer (unix socket) -> no origin");

  std::printf("\n%d checks, %d failures\n", g_checks, g_fail);
  return g_fail == 0 ? 0 : 1;
}
