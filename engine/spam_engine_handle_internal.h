#pragma once

#include <mutex>
#include <string>
#include <vector>

#include "spam_engine.h"
#include "spam_engine_c_api.h"

struct spam_engine_training_sample {
  std::string raw_email;
  // Caller-supplied sender metadata for the train/inference parity contract
  // (see engine/PARITY_PLAN.md). Empty strings fall back to the parsed
  // From header inside SpamEngine::train_rfc822.
  std::string sender_name;
  std::string sender_email;
  int correct_label = -1;
};

// Internal handle shared by base and training C ABIs.
// Keep this in one header to avoid layout drift across translation units.
struct spam_engine_handle {
  spam_engine::SpamEngine engine;
  std::string last_error;
  mutable std::mutex mutex;
  std::vector<spam_engine_training_sample> pending_training_samples;
};

// The error contract every C ABI entry point shares: set (or clear) the
// handle's last_error under its mutex and hand the status back, so a caller
// can `return set_error_locked(...)` in one line. One definition here rather
// than a copy per translation unit.
inline spam_engine_status_t set_error_locked(
    spam_engine_handle_t* handle,
    spam_engine_status_t code,
    const std::string& message) {
  if (handle != nullptr) {
    handle->last_error = message;
  }
  return code;
}

inline void clear_error_locked(spam_engine_handle_t* handle) {
  if (handle != nullptr) {
    handle->last_error.clear();
  }
}
