#pragma once

// Shared by the dependency-free test binaries (url_blocklist_tests,
// ip_blocklist_tests): a single fopen() failure here means the test
// environment itself is broken (unwritable /tmp), not the code under test,
// so abort loudly instead of writing through a null FILE*. Kept in its own
// header, not test_support.h, so these binaries stay free of test_support.h's
// model-path/GGUF-fixture surface.

#include <cstdio>
#include <cstdlib>

inline std::FILE* must_fopen(const char* path, const char* mode) {
  std::FILE* f = std::fopen(path, mode);
  if (f == nullptr) {
    std::perror(path);
    std::abort();
  }
  return f;
}
