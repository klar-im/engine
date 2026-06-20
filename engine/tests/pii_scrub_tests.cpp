// Unit tests for the on-device PII scrub (engine/pii_scrub.cpp).
// pii_scrub.cpp depends only on the C++ standard library (<regex>), so this
// links nothing model-related and runs in milliseconds.

#include "../pii_scrub.h"

#include <chrono>
#include <cstddef>
#include <cstdio>
#include <string>

using spam_engine::scrub_body_text;

static int g_failures = 0;

static void check(bool cond, const std::string& name,
                  const std::string& detail = "") {
  if (cond) {
    std::printf("[PASS] %s\n", name.c_str());
  } else {
    std::printf("[FAIL] %s%s%s\n", name.c_str(), detail.empty() ? "" : ": ",
                detail.c_str());
    ++g_failures;
  }
}

int main() {
  // Normal redaction still works after the input cap was added.
  {
    const std::string out = scrub_body_text(
        "contact john.doe@example.com and call +1 415 555 1234", {});
    check(out.find("john.doe@example.com") == std::string::npos &&
              out.find("<email>") != std::string::npos &&
              out.find("<phone>") != std::string::npos,
          "redacts email and phone", out);
  }

  // Regression for TASK-206 #1: the body is attacker-controlled. libc++
  // std::regex on libstdc++ recurses per matched byte, so an unbounded run of
  // matching characters from an attacker body would stack-overflow the host
  // in-process. The scrub bounds every quantifier (and caps its input), so each
  // of these 4 MB pathological bodies must complete quickly without crashing.
  // One case per dangerous pattern: hex/colon (IPv6), digits (phone/card), and a
  // data: URI payload (the linear strip). A regression here is a SEGFAULT, not a
  // soft failure — the test crashing IS the signal.
  auto stress = [&](const std::string& label, const std::string& evil) {
    const auto t0 = std::chrono::steady_clock::now();
    const std::string out = scrub_body_text(evil, {});
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0)
                        .count();
    check(ms < 5000, label, std::to_string(ms) + " ms, " +
                                std::to_string(out.size()) + " bytes out");
  };
  {
    const std::size_t n = 4 * 1024 * 1024;
    std::string hexcolon(n, '1');
    for (std::size_t i = 0; i < n; i += 2) hexcolon[i] = ':';
    stress("pathological hex/colon body bounded (IPv6 regex)", hexcolon);
    stress("pathological digit body bounded (phone/card regex)", std::string(n, '1'));
    stress("pathological data: URI body bounded (linear strip)", "data:" + std::string(n, 'A'));
  }

  return g_failures == 0 ? 0 : 1;
}
