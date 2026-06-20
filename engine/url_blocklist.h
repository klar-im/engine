#pragma once

// Phishing-domain blocklist lookup (TASK-201 — URL/link reputation).
//
// Loads the bundled sorted-hash artifact built by
// pythonDiscovery/scripts/build_phishing_blocklist.py (the MIT Phishing.Database
// ACTIVE list) and answers contains(host) by FNV-1a hash + binary search — fully
// offline, no per-message network (the SURBL/URIBL privacy constraint).
//
// FQDN-EXACT keys, never the org_domain-reduced form: the list is dominated by
// phishing on shared free hosts (pages.dev, github.io, appspot.com, web.app, …),
// so reducing to eTLD+1 would blocklist those whole hosts and flag every legit
// site on them (measured — see TASK-201). Match the full host.
//
// FNV-1a is used (not a crypto hash) so this stays dependency-free and matches the
// Python builder exactly; collisions are non-adversarial here and ~2e-14/lookup.
//
// Binary format: magic "KLARPB1\0" (8B) | u32 bits(=64) | u32 count | count × u64
// little-endian FNV-1a hashes, ascending.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace spam_engine {

// 64-bit FNV-1a. MUST match pythonDiscovery/scripts/build_phishing_blocklist.py.
inline uint64_t fnv1a64(const std::string& s) {
  uint64_t h = 0xCBF29CE484222325ULL;
  for (unsigned char c : s) {
    h ^= c;
    h *= 0x100000001B3ULL;  // wraps mod 2^64
  }
  return h;
}

class UrlBlocklist {
 public:
  // Load from the bundled .bin. Returns false (and stays empty) on a missing or
  // malformed file — a missing blocklist must NEVER break classification, it just
  // disables the signal.
  bool load(const std::string& path) {
    hashes_.clear();
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) return false;
    char magic[8];
    uint32_t bits = 0, count = 0;
    bool ok = std::fread(magic, 1, 8, f) == 8 &&
              std::memcmp(magic, "KLARPB1\0", 8) == 0 &&
              std::fread(&bits, 4, 1, f) == 1 && std::fread(&count, 4, 1, f) == 1 &&
              bits == 64;
    if (ok && count > 0) {
      hashes_.resize(count);
      ok = std::fread(hashes_.data(), sizeof(uint64_t), count, f) == count;
    }
    std::fclose(f);
    if (!ok) {
      hashes_.clear();
      return false;
    }
    return true;
  }

  bool loaded() const { return !hashes_.empty(); }
  std::size_t size() const { return hashes_.size(); }

  // Exact FQDN match (host must be lowercased by the caller). Binary search over
  // the ascending hash array.
  bool contains(const std::string& host) const {
    if (hashes_.empty() || host.empty()) return false;
    const uint64_t h = fnv1a64(host);
    std::size_t lo = 0, hi = hashes_.size();
    while (lo < hi) {
      const std::size_t mid = lo + (hi - lo) / 2;
      if (hashes_[mid] < h) lo = mid + 1;
      else hi = mid;
    }
    return lo < hashes_.size() && hashes_[lo] == h;
  }

 private:
  std::vector<uint64_t> hashes_;  // sorted ascending
};

}  // namespace spam_engine
