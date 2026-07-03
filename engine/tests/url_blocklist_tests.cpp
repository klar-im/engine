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
  for (const auto& d : domains) h.push_back(se::fnv1a_lower(d));
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
  check(se::fnv1a_lower("klar.im") == 8089896514840204515ULL, "fnv1a parity klar.im");
  check(se::fnv1a_lower("evil.example") == 10770985678317078571ULL, "fnv1a parity evil.example");

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

  // 4. a header count larger than the file's actual payload must be rejected BEFORE
  //    the resize (a 4-billion count would allocate 32 GiB to OOM) (TASK-251).
  const char* lying = "/tmp/klar_ublk_lying_count.bin";
  std::FILE* lf = std::fopen(lying, "wb");
  std::fwrite("KLARPB1\0", 1, 8, lf);
  uint32_t lbits = 64, lcount = 4000000000u;  // claims 4e9 hashes...
  std::fwrite(&lbits, 4, 1, lf);
  std::fwrite(&lcount, 4, 1, lf);
  const uint64_t one = se::fnv1a_lower("evil.example");
  std::fwrite(&one, sizeof(uint64_t), 1, lf);  // ...but ships only one
  std::fclose(lf);
  se::UrlBlocklist lie;
  check(!lie.load(lying), "lying count (payload too short) -> load returns false, no OOM");
  check(!lie.loaded(), "lying count -> stays empty");

  std::printf("\n%d checks, %d failures\n", g_checks, g_fail);
  return g_fail == 0 ? 0 : 1;
}
