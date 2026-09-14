// Unit tests for the `auth_results = "ignore"` switch (postfix/src/auth_results.cpp)
// and its config validation. No engine, milter or sqlite: links auth_results.cpp
// and config.cpp only. The engine-level consequence (a forged AR no longer buys
// the kb_brand_dmarc rescue) is asserted with the real model in
// postfix/scripts/test_auth_results.sh.

#include "auth_results.h"
#include "config.h"

#include <cstdio>
#include <string>

using klar::Config;

static int g_failures = 0;

static void check(bool ok, const char* what) {
  std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", what);
  if (!ok) ++g_failures;
}

int main() {
  // --- header-name predicate -------------------------------------------------
  check(klar::is_auth_results_header("Authentication-Results"), "matches Authentication-Results");
  check(klar::is_auth_results_header("authentication-results"), "case-insensitive");
  check(klar::is_auth_results_header("ARC-Authentication-Results"), "matches ARC-Authentication-Results");
  check(!klar::is_auth_results_header("Received-SPF"), "Received-SPF is left alone");
  check(!klar::is_auth_results_header("X-Authentication-Results-Note"), "no prefix matching");
  check(!klar::is_auth_results_header(nullptr), "null is not a header");

  // --- whole-message strip ---------------------------------------------------
  const std::string raw =
      "Received: from a.example by mail.klar.im\r\n"
      "Authentication-Results: mail.klar.im;\r\n"
      "\tdkim=pass header.d=apple.com header.s=k1;\r\n"
      "\tdmarc=pass\r\n"
      "From: Apple <no_reply@email.apple.com>\r\n"
      "authentication-results: other.example; spf=pass\r\n"
      "ARC-Authentication-Results: i=1; relay.example; dkim=pass\r\n"
      "Subject: hi\r\n"
      "\r\n"
      "Authentication-Results: this is body text and must survive\r\n"
      "bye\r\n";
  const std::string expect =
      "Received: from a.example by mail.klar.im\r\n"
      "From: Apple <no_reply@email.apple.com>\r\n"
      "Subject: hi\r\n"
      "\r\n"
      "Authentication-Results: this is body text and must survive\r\n"
      "bye\r\n";
  const std::string got = klar::strip_authentication_results(raw);
  check(got == expect, "strips every AR header with its folded lines, body untouched");
  if (got != expect) std::printf("--- got ---\n%s--- expect ---\n%s", got.c_str(), expect.c_str());

  const std::string clean = "From: a@b.example\nSubject: x\n\nbody\n";
  check(klar::strip_authentication_results(clean) == clean, "a message without AR is unchanged (LF endings)");

  const std::string headers_only = "Authentication-Results: x; dkim=pass\r\nFrom: a@b.example\r\n";
  check(klar::strip_authentication_results(headers_only) == "From: a@b.example\r\n",
        "no blank line at all: still strips, still keeps the rest");

  // --- config ---------------------------------------------------------------
  Config c;
  check(!klar::ignores_auth_results(c), "default is trust-topmost");
  check(klar::validate_config(c).empty(), "default validates");
  c.auth_results = "ignore";
  check(klar::ignores_auth_results(c), "ignore is recognised");
  check(klar::validate_config(c).empty(), "ignore validates");
  c.auth_results = "Ignore";
  check(!klar::validate_config(c).empty(), "a misspelling is refused, never read as the default");

  if (g_failures) {
    std::printf("\n%d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("\nall auth_results tests passed\n");
  return 0;
}
