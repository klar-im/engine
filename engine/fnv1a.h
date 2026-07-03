#pragma once

// Shared 64-bit FNV-1a over the LOWERCASED bytes of the input — the single hash
// behind every exact-membership lookup in the engine: brand_names.h
// (display-name impersonation, TASK-214), brand_reputation.h (DKIM-signer
// reputation, TASK-170), and url_blocklist.h (phishing-host blocklist,
// TASK-201). Each pairs with a Python generator whose hashes are built from
// already-lowercased keys, so lowercasing in-loop keeps cross-language parity
// while removing the caller's obligation to pre-lowercase (idempotent on input
// that is already lowercase).
//
// EXACT membership by design, never a bloom/cuckoo filter: the only error of a
// probabilistic filter is a false positive, which on a ham allowlist would
// rescue spam and on a blocklist would flag clean mail. A sorted-array binary
// search over these hashes has no such error.
//
// Constants are the canonical FNV-1a 64-bit offset basis / prime. Cross-language
// parity is pinned by pythonDiscovery/test_decision_layer_sync.py (brand data)
// and engine/tests/url_blocklist_tests.cpp (host hashes).

#include <cstdint>
#include <string>

namespace spam_engine {

inline std::uint64_t fnv1a_lower(const std::string& s) {
  std::uint64_t h = 0xCBF29CE484222325ULL;
  for (unsigned char c : s) {
    if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c - 'A' + 'a');
    h ^= c;
    h *= 0x100000001B3ULL;  // wraps mod 2^64
  }
  return h;
}

}  // namespace spam_engine
