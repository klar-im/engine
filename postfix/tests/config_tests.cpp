// Unit tests for config validation (postfix/src/config.cpp). validate_config
// has no engine/milter/sqlite dependency, so this links only config.cpp.

#include "config.h"

#include <cstdio>
#include <string>
#include <vector>

using klar::Config;
using klar::validate_config;

static int g_failures = 0;

static void expect_ok(const std::string& listen, bool allow) {
  Config c;
  c.health_listen = listen;
  c.health_allow_public = allow;
  const std::string e = validate_config(c);
  if (e.empty()) {
    std::printf("[PASS] accept health_listen='%s' allow_public=%d\n",
                listen.c_str(), allow);
  } else {
    std::printf("[FAIL] expected accept health_listen='%s' allow_public=%d: %s\n",
                listen.c_str(), allow, e.c_str());
    ++g_failures;
  }
}

static void expect_err(const std::string& listen, bool allow) {
  Config c;
  c.health_listen = listen;
  c.health_allow_public = allow;
  const std::string e = validate_config(c);
  if (!e.empty()) {
    std::printf("[PASS] reject health_listen='%s' allow_public=%d -> %s\n",
                listen.c_str(), allow, e.c_str());
  } else {
    std::printf("[FAIL] expected reject health_listen='%s' allow_public=%d\n",
                listen.c_str(), allow);
    ++g_failures;
  }
}

int main() {
  // Regression for TASK-206 #2: the unauthenticated /metrics endpoint must not
  // be silently exposed on all interfaces.
  expect_ok("127.0.0.1:8892", false);   // safe loopback default
  expect_ok("[::1]:8892", false);        // IPv6 loopback (brackets stripped)
  expect_ok("0.0.0.0:8892", true);       // explicit opt-in
  expect_ok("[::]:8892", true);          // IPv6 wildcard + opt-in
  expect_err("0.0.0.0:8892", false);     // wildcard without opt-in
  expect_err("[::]:8892", false);        // IPv6 wildcard without opt-in
  expect_err("8892", false);             // bare port (would bind 0.0.0.0)
  expect_err(":8892", false);            // empty host
  expect_err("127.0.0.1:", false);       // empty port
  expect_err("127.0.0.1:abc", false);    // non-numeric port
  expect_err("127.0.0.1:70000", false);  // port out of range

  // health disabled: health_listen is not validated.
  {
    Config c;
    c.health_enabled = false;
    c.health_listen = "0.0.0.0:8892";
    c.health_allow_public = false;
    if (validate_config(c).empty()) {
      std::printf("[PASS] health_enabled=false skips health_listen check\n");
    } else {
      std::printf("[FAIL] health_enabled=false should skip health_listen\n");
      ++g_failures;
    }
  }

  // TASK-113: the DROP-list staleness budget. A list nobody refreshes decays, so
  // the budget must be a real number of days — but only when a list is actually
  // configured, since an empty path means the signal is off.
  {
    struct Case { const char* what; std::string path; int days; bool ok; };
    const Case cases[] = {
        {"default budget accepted", "/var/lib/klar/model/ip_blocklist.bin", 14, true},
        {"1 day accepted", "/var/lib/klar/model/ip_blocklist.bin", 1, true},
        {"365 days accepted", "/var/lib/klar/model/ip_blocklist.bin", 365, true},
        {"0 days rejected", "/var/lib/klar/model/ip_blocklist.bin", 0, false},
        {"negative rejected", "/var/lib/klar/model/ip_blocklist.bin", -1, false},
        {"366 days rejected", "/var/lib/klar/model/ip_blocklist.bin", 366, false},
        {"no list -> budget unchecked", "", 0, true},
    };
    for (const Case& tc : cases) {
      Config c;
      c.ip_blocklist_path = tc.path;
      c.ip_blocklist_max_age_days = tc.days;
      const bool got_ok = validate_config(c).empty();
      if (got_ok == tc.ok) {
        std::printf("[PASS] ip_blocklist: %s\n", tc.what);
      } else {
        std::printf("[FAIL] ip_blocklist: %s\n", tc.what);
        ++g_failures;
      }
    }
  }

  // TASK-387: a typo in trusted_relay_cidrs does NOT fail safe — it would drop a
  // relay out of the trusted set and make an untrusted Received line read as if
  // our own MTA had written it. So it must be a config error, not a warning.
  {
    struct Case { const char* what; std::vector<std::string> cidrs; bool ok; };
    const Case cases[] = {
        {"empty list accepted (feature off)", {}, true},
        {"IPv4 CIDR accepted", {"10.88.0.0/24"}, true},
        {"bare address accepted", {"192.0.2.7"}, true},
        {"IPv6 CIDR accepted", {"2001:db8::/32"}, true},
        {"several accepted", {"10.88.0.0/24", "127.0.0.1"}, true},
        {"garbage rejected", {"not-an-ip"}, false},
        {"oversized IPv4 prefix rejected", {"10.0.0.0/33"}, false},
        {"non-numeric prefix rejected", {"10.0.0.0/x"}, false},
        {"one bad entry poisons the list", {"10.88.0.0/24", "nope"}, false},
    };
    for (const Case& tc : cases) {
      Config c;
      c.trusted_relay_cidrs = tc.cidrs;
      const bool got_ok = validate_config(c).empty();
      if (got_ok == tc.ok) {
        std::printf("[PASS] trusted_relay_cidrs: %s\n", tc.what);
      } else {
        std::printf("[FAIL] trusted_relay_cidrs: %s\n", tc.what);
        ++g_failures;
      }
    }
  }

  return g_failures == 0 ? 0 : 1;
}
