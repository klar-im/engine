// Unit tests for config validation (postfix/src/config.cpp). validate_config
// has no engine/milter/sqlite dependency, so this links only config.cpp.

#include "config.h"

#include <cstdio>
#include <string>

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

  return g_failures == 0 ? 0 : 1;
}
