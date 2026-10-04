// spam_classifier: classify one message the way every Klar consumer does,
// through the public C ABI's single verdict call, and print the verdict.
//
//   spam_classifier <model_dir> <message.eml>
//
// The first line is the label (spam, ham or marketing); the next two say how
// the engine got there: the spam side after the structural offsets, and which
// offsets fired ("!" marks the one that flipped the verdict).

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include "spam_engine_c_api.h"

int main(int argc, char* argv[]) {
  if (argc != 3) {
    std::cerr << "usage: " << argv[0] << " <model_dir> <message.eml>\n";
    return 2;
  }
  std::ifstream in(argv[2], std::ios::binary);
  if (!in) {
    std::cerr << "cannot read " << argv[2] << '\n';
    return 1;
  }
  const std::string raw((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());

  // The engine and ggml log to stderr (tests/backend_isolation_test.sh reads
  // the backend lines there); the verdict is the only thing on stdout.
  spam_engine_handle_t* handle = spam_engine_create();
  if (handle == nullptr) {
    std::cerr << "cannot create an engine handle\n";
    return 1;
  }
  int rc = 1;
  spam_engine_full_result_t result{};
  if (spam_engine_load(handle, argv[1], 0.0F, nullptr) != SPAM_ENGINE_STATUS_OK ||
      spam_engine_classify_full(handle, raw.data(), raw.size(), nullptr, nullptr,
                                "ensemble", nullptr, &result) != SPAM_ENGINE_STATUS_OK) {
    const char* err = spam_engine_get_last_error(handle);
    std::cerr << "error: " << (err != nullptr ? err : "unknown") << '\n';
  } else {
    const std::string fired = result.decision.fired_offsets;
    std::cout << result.decision.label << '\n'
              << "adjusted_spam_side: " << result.decision.adjusted_spam_side << '\n'
              << "fired_offsets: " << (fired.empty() ? "(none)" : fired) << '\n';
    rc = 0;
  }
  // Destroy before returning from main: spam_engine_c_api.h's lifetime contract.
  spam_engine_destroy(handle);
  return rc;
}
