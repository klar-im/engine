#include "spam_engine_training_c_api.h"

#include <exception>
#include <string>
#include <system_error>
#include <iterator>
#include <utility>
#include <vector>

#include "spam_engine_handle_internal.h"

namespace {

bool is_valid_label(int correct_label) {
  return correct_label >= 0 && correct_label <= 3;
}

spam_engine::CustomerInfo customer_from_c_strings(
    const char* sender_name, const char* sender_email) {
  return spam_engine::CustomerInfo{
      sender_name != nullptr ? sender_name : "",
      sender_email != nullptr ? sender_email : "",
      false,
  };
}

spam_engine_status_t validate_rfc822_training_input_locked(
    spam_engine_handle_t* handle,
    const char* raw_email,
    size_t raw_email_len,
    int correct_label) {
  if (raw_email == nullptr) {
    return set_error_locked(
        handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "raw_email cannot be null");
  }
  if (raw_email_len == 0) {
    return set_error_locked(
        handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "raw_email_len must be > 0");
  }
  if (!is_valid_label(correct_label)) {
    return set_error_locked(
        handle,
        SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
        "correct_label must be 0-3 (gibberish/marketing/regular/spam)");
  }
  return SPAM_ENGINE_STATUS_OK;
}

}  // namespace

extern "C" {

spam_engine_status_t spam_engine_train(
    spam_engine_handle_t* handle,
    const char* text,
    int correct_label,
    float* out_loss) {
  if (handle == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::scoped_lock const lock(handle->mutex);

    if (text == nullptr) {
      return set_error_locked(
          handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "text cannot be null");
    }
    if (!is_valid_label(correct_label)) {
      return set_error_locked(
          handle,
          SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
          "correct_label must be 0-3 (gibberish/marketing/regular/spam)");
    }

    clear_error_locked(handle);

    // The loaded artifact selects the same neural representation used by
    // inference; FTRL independently retains its legacy envelope.
    const float loss = handle->engine.train_text(text, correct_label);
    if (out_loss != nullptr) {
      *out_loss = loss;
    }
    return SPAM_ENGINE_STATUS_OK;
  } catch (const std::system_error&) {
    return SPAM_ENGINE_STATUS_RUNTIME_ERROR;
  } catch (const std::exception& e) {
    return set_error_locked(handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, e.what());
  } catch (...) {
    return set_error_locked(
        handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, "Unknown runtime error in spam_engine_train");
  }
}

spam_engine_status_t spam_engine_train_rfc822(
    spam_engine_handle_t* handle,
    const char* raw_email,
    size_t raw_email_len,
    const char* sender_name,
    const char* sender_email,
    int correct_label,
    float* out_loss) {
  if (handle == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::scoped_lock const lock(handle->mutex);

    if (const auto validation_status = validate_rfc822_training_input_locked(
            handle, raw_email, raw_email_len, correct_label);
        validation_status != SPAM_ENGINE_STATUS_OK) {
      return validation_status;
    }

    clear_error_locked(handle);

    const float loss = handle->engine.train_rfc822(
        std::string(raw_email, raw_email_len),
        customer_from_c_strings(sender_name, sender_email),
        correct_label);
    if (out_loss != nullptr) {
      *out_loss = loss;
    }
    return SPAM_ENGINE_STATUS_OK;
  } catch (const std::system_error&) {
    return SPAM_ENGINE_STATUS_RUNTIME_ERROR;
  } catch (const std::exception& e) {
    return set_error_locked(handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, e.what());
  } catch (...) {
    return set_error_locked(
        handle,
        SPAM_ENGINE_STATUS_RUNTIME_ERROR,
        "Unknown runtime error in spam_engine_train_rfc822");
  }
}

spam_engine_status_t spam_engine_add_training_sample(
    spam_engine_handle_t* handle,
    const char* raw_email,
    size_t raw_email_len,
    const char* sender_name,
    const char* sender_email,
    int correct_label) {
  if (handle == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::scoped_lock const lock(handle->mutex);

    if (const auto validation_status = validate_rfc822_training_input_locked(
            handle, raw_email, raw_email_len, correct_label);
        validation_status != SPAM_ENGINE_STATUS_OK) {
      return validation_status;
    }

    clear_error_locked(handle);
    handle->pending_training_samples.push_back(
        spam_engine_training_sample{
            std::string(raw_email, raw_email_len),
            sender_name != nullptr ? std::string(sender_name) : std::string(),
            sender_email != nullptr ? std::string(sender_email) : std::string(),
            correct_label,
        });
    return SPAM_ENGINE_STATUS_OK;
  } catch (const std::system_error&) {
    return SPAM_ENGINE_STATUS_RUNTIME_ERROR;
  } catch (const std::exception& e) {
    return set_error_locked(handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, e.what());
  } catch (...) {
    return set_error_locked(
        handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR,
        "Unknown runtime error in spam_engine_add_training_sample");
  }
}

spam_engine_status_t spam_engine_train_incremental_mode(
    spam_engine_handle_t* handle,
    spam_engine_training_mode_t mode,
    float* out_avg_loss,
    size_t* out_trained_count) {
  if (handle == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }
  if (mode != SPAM_ENGINE_TRAIN_HEAD_AND_FTRL &&
      mode != SPAM_ENGINE_TRAIN_FTRL_ONLY) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::scoped_lock const lock(handle->mutex);
    clear_error_locked(handle);

    if (out_avg_loss != nullptr) {
      *out_avg_loss = 0.0F;
    }
    if (out_trained_count != nullptr) {
      *out_trained_count = 0;
    }

    if (handle->pending_training_samples.empty()) {
      return SPAM_ENGINE_STATUS_OK;
    }

    // Drain queue up-front to avoid duplicate re-application if a later sample fails.
    std::vector<spam_engine_training_sample> samples = std::move(handle->pending_training_samples);
    handle->pending_training_samples.clear();

    size_t processed = 0;
    float loss_sum = 0.0F;
    try {
      for (; processed < samples.size(); ++processed) {
        const auto& sample = samples[processed];
        const auto customer = spam_engine::CustomerInfo{
            sample.sender_name, sample.sender_email, false};
        if (mode == SPAM_ENGINE_TRAIN_FTRL_ONLY) {
          handle->engine.train_ftrl_rfc822(
              sample.raw_email, customer, sample.correct_label);
        } else {
          loss_sum += handle->engine.train_rfc822(
              sample.raw_email, customer, sample.correct_label);
        }
      }
    } catch (...) {
      // A sample failed mid-batch. The already-trained ones stay applied (re-queuing
      // them would double-count); the failing sample (index `processed`) is dropped,
      // since retrying a poison sample would wedge the queue; the untried tail is
      // re-queued so it is not silently lost as it was before (TASK-251).
      if (processed + 1 < samples.size()) {
        handle->pending_training_samples.assign(
            std::make_move_iterator(samples.begin() + processed + 1),
            std::make_move_iterator(samples.end()));
      }
      // Report the head that WAS trained and applied, so the caller doesn't read
      // the RUNTIME_ERROR as "nothing applied" and re-train those samples.
      if (out_trained_count != nullptr) { *out_trained_count = processed;
}
      if (out_avg_loss != nullptr && processed > 0) {
        *out_avg_loss = loss_sum / static_cast<float>(processed);
      }
      throw;  // outer handler sets last_error + RUNTIME_ERROR
    }

    if (out_trained_count != nullptr) {
      *out_trained_count = processed;
    }
    if (out_avg_loss != nullptr && processed > 0) {
      *out_avg_loss = loss_sum / static_cast<float>(processed);
    }
    return SPAM_ENGINE_STATUS_OK;
  } catch (const std::system_error&) {
    return SPAM_ENGINE_STATUS_RUNTIME_ERROR;
  } catch (const std::exception& e) {
    return set_error_locked(
        handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR,
        std::string("train_incremental failed: ") + e.what());
  } catch (...) {
    return set_error_locked(
        handle,
        SPAM_ENGINE_STATUS_RUNTIME_ERROR,
        "Unknown runtime error in spam_engine_train_incremental");
  }
}

spam_engine_status_t spam_engine_train_incremental(
    spam_engine_handle_t* handle,
    float* out_avg_loss,
    size_t* out_trained_count) {
  return spam_engine_train_incremental_mode(
      handle,
      SPAM_ENGINE_TRAIN_HEAD_AND_FTRL,
      out_avg_loss,
      out_trained_count);
}

spam_engine_status_t spam_engine_head_drift(
    spam_engine_handle_t* handle,
    float* out_saturation,
    float* out_relative_drift) {
  if (handle == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::scoped_lock const lock(handle->mutex);
    clear_error_locked(handle);

    if (out_saturation != nullptr) {
      *out_saturation = handle->engine.head_drift_saturation();
    }
    if (out_relative_drift != nullptr) {
      *out_relative_drift = handle->engine.head_relative_drift();
    }
    return SPAM_ENGINE_STATUS_OK;
  } catch (const std::exception& e) {
    return set_error_locked(handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, e.what());
  } catch (...) {
    return set_error_locked(
        handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR,
        "Unknown runtime error in spam_engine_head_drift");
  }
}

spam_engine_status_t spam_engine_head_optimizer_steps(
    spam_engine_handle_t* handle,
    size_t* out_steps) {
  if (handle == nullptr || out_steps == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }
  try {
    std::scoped_lock const lock(handle->mutex);
    clear_error_locked(handle);
    *out_steps = static_cast<size_t>(handle->engine.head_optimizer_steps());
    return SPAM_ENGINE_STATUS_OK;
  } catch (const std::system_error&) {
    return SPAM_ENGINE_STATUS_RUNTIME_ERROR;
  } catch (const std::exception& e) {
    return set_error_locked(handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, e.what());
  } catch (...) {
    return set_error_locked(
        handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR,
        "Unknown runtime error in spam_engine_head_optimizer_steps");
  }
}

spam_engine_status_t spam_engine_save(
    spam_engine_handle_t* handle,
    const char* model_path) {
  if (handle == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::scoped_lock const lock(handle->mutex);
    clear_error_locked(handle);

    const std::string path = (model_path != nullptr) ? model_path : "";
    handle->engine.save(path);
    return SPAM_ENGINE_STATUS_OK;
  } catch (const std::system_error&) {
    return SPAM_ENGINE_STATUS_RUNTIME_ERROR;
  } catch (const std::exception& e) {
    return set_error_locked(handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, e.what());
  } catch (...) {
    return set_error_locked(
        handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, "Unknown runtime error in spam_engine_save");
  }
}

spam_engine_status_t spam_engine_save_model(
    spam_engine_handle_t* handle,
    const char* model_path) {
  return spam_engine_save(handle, model_path);
}

int spam_engine_label_from_string(const char* label) {
  if (label == nullptr) {
    return -1;
  }
  return spam_engine::SpamEngine::label_from_string(label);
}

const char* spam_engine_label_to_string(int label) {
  static const char* labels[] = {"gibberish", "marketing", "regular", "spam"};
  if (label < 0 || label > 3) {
    return nullptr;
  }
  return labels[label];
}

}  // extern "C"
