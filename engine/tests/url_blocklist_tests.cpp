// Unit tests for the phishing URL blocklist (TASK-201). Dependency-free (no model),
// like decision_layer_tests — builds a tiny .bin, loads it, checks lookups, and pins
// FNV-1a cross-language parity with pythonDiscovery/scripts/build_phishing_blocklist.py.

#include "../url_blocklist.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace se = spam_engine;

namespace {
int g_fail = 0, g_checks = 0;
void check(bool c, const char* what) {
  ++g_checks;
  if (!c) { ++g_fail; std::printf("  [FAIL] %s\n", what); }
}

void write_bin(const char* path, const std::vector<std::string>& domains) {
  std::vector<uint64_t> h;
  for (const auto& d : domains) h.push_back(se::fnv1a64(d));
  std::sort(h.begin(), h.end());
  std::FILE* f = std::fopen(path, "wb");
  std::fwrite("KLARPB1\0", 1, 8, f);
  uint32_t bits = 64, count = static_cast<uint32_t>(h.size());
  std::fwrite(&bits, 4, 1, f);
  std::fwrite(&count, 4, 1, f);
  std::fwrite(h.data(), sizeof(uint64_t), count, f);
  std::fclose(f);
}
}  // namespace

int main() {
  // 1. FNV-1a parity with the Python builder (values computed there).
  check(se::fnv1a64("klar.im") == 8089896514840204515ULL, "fnv1a64 parity klar.im");
  check(se::fnv1a64("evil.example") == 10770985678317078571ULL, "fnv1a64 parity evil.example");

  // 2. round-trip a small blocklist.
  const char* p = "/tmp/klar_ublk_test.bin";
  write_bin(p, {"evil.example", "login.evil.pages.dev", "bad-bank.test"});
  se::UrlBlocklist bl;
  check(bl.load(p), "load ok");
  check(bl.size() == 3, "size == 3");
  check(bl.contains("evil.example"), "contains listed standalone domain");
  check(bl.contains("login.evil.pages.dev"), "contains listed free-host FQDN");
  check(!bl.contains("good.example"), "does not contain unlisted");
  check(!bl.contains("pages.dev"), "free-host parent NOT matched (FQDN-exact, no over-block)");
  check(!bl.contains(""), "empty host -> false");

  // 3. missing / malformed file is safe — the signal is just disabled, never a crash.
  se::UrlBlocklist bad;
  check(!bad.load("/tmp/klar_does_not_exist.bin"), "missing file -> load returns false");
  check(!bad.loaded() && !bad.contains("evil.example"), "unloaded -> contains false");

  std::printf("\n%d checks, %d failures\n", g_checks, g_fail);
  return g_fail == 0 ? 0 : 1;
}
