#pragma once

#include <exception>
#include <mutex>
#include <string>
#include <system_error>
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

// The boundary every status-returning entry point that takes a handle shares
// (TASK-540): reject a NULL handle, run `body` under the handle's lock, and
// turn anything it throws into a status, because an exception must never
// unwind into a C or Swift caller. `body` validates, clears the error when it
// is past validation, and returns its status. `where` names the entry point in
// the message for a non-std exception.
//
// A std::system_error reports no message on purpose: the likeliest one is the
// lock itself failing, which means the handle may be invalid and must not be
// touched. A body that can throw one for another reason (load's filesystem
// errors) catches it itself and reports it while the lock is still held.
template <class F>
spam_engine_status_t guarded(spam_engine_handle_t* handle, const char* where, const F& body) {
  if (handle == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }
  try {
    std::scoped_lock const lock(handle->mutex);
    return body();
  } catch (const std::system_error&) {
    return SPAM_ENGINE_STATUS_RUNTIME_ERROR;
  } catch (const std::exception& e) {
    return set_error_locked(handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, e.what());
  } catch (...) {
    return set_error_locked(handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR,
                            std::string("Unknown runtime error in ") + where);
  }
}
