#include "spam_engine_c_api.h"

#include <algorithm>
#include <cstring>
#include <exception>
#include <string>
#include <system_error>

#include "brand_reputation.h"
#include "decision_layer.h"
#include "email_preprocessor.h"
#include "spam_engine_handle_internal.h"

namespace {

spam_engine_status_t set_error_locked(
    spam_engine_handle_t* handle,
    spam_engine_status_t code,
    const std::string& message) {
  if (handle != nullptr) {
    handle->last_error = message;
  }
  return code;
}

void clear_error_locked(spam_engine_handle_t* handle) {
  if (handle != nullptr) {
    handle->last_error.clear();
  }
}

void fill_result(const spam_engine::ClassificationResult& result, spam_engine_result_t* out_result) {
  out_result->label = spam_engine::SpamEngine::label_from_string(result.class_name);
  out_result->confidence = result.confidence;
  out_result->scores.gibberish = result.scores.gibberish;
  out_result->scores.marketing = result.scores.marketing;
  out_result->scores.regular = result.scores.regular;
  out_result->scores.spam = result.scores.spam;
  std::strncpy(out_result->decided_by, result.decided_by.c_str(), sizeof(out_result->decided_by) - 1);
  out_result->decided_by[sizeof(out_result->decided_by) - 1] = '\0';
  out_result->ftrl_score = result.ftrl_score;
}

// classify mode is a required C-API argument (TASK-219). Reject NULL/empty/
// unknown up front so the caller gets INVALID_ARGUMENT, not a generic runtime
// error from the C++ validate_mode throw.
bool is_valid_mode(const char* mode) {
  return mode != nullptr &&
         (std::strcmp(mode, "ensemble") == 0 ||
          std::strcmp(mode, "neural") == 0 ||
          std::strcmp(mode, "ftrl") == 0);
}

void copy_id(char (&dst)[256], const std::string& src) {
  // RFC 5322 has no hard limit but production Message-IDs are <128 chars;
  // anything past the buffer is almost certainly malformed and unsafe to
  // truncate (a truncated ID would silently mismatch in Phase 2 lookups).
  if (src.empty() || src.size() >= sizeof(dst)) {
    dst[0] = '\0';
    return;
  }
  std::memcpy(dst, src.data(), src.size());
  dst[src.size()] = '\0';
}

void fill_thread_features(
    const spam_engine::ExtractedThreadFeatures& features,
    spam_engine_thread_features_t* out) {
  std::memset(out, 0, sizeof(*out));
  out->has_in_reply_to = features.has_in_reply_to ? 1 : 0;
  out->references_count = features.references_count;
  copy_id(out->in_reply_to, features.in_reply_to);
  copy_id(out->first_reference, features.first_reference);
  copy_id(out->self_message_id, features.self_message_id);
}

void fill_auth_features(
    const spam_engine::ExtractedAuthFeatures& features,
    spam_engine_auth_features_t* out) {
  std::memset(out, 0, sizeof(*out));
  copy_id(out->dkim_signing_domain, features.dkim_signing_domain);
  copy_id(out->from_org_domain, features.from_org_domain);
  out->dmarc_aligned = features.dmarc_aligned ? 1 : 0;
  copy_id(out->dkim_signing_fqdn, features.dkim_signing_fqdn);
  out->signer_throwaway = features.signer_throwaway ? 1 : 0;
  out->display_impersonation = features.display_impersonation ? 1 : 0;
}

}  // namespace

extern "C" {

const char* spam_engine_label_name(int label) {
  return spam_engine::SpamEngine::label_name(label);
}

spam_engine_handle_t* spam_engine_create(void) {
  try {
    return new spam_engine_handle_t();
  } catch (...) {
    return nullptr;
  }
}

void spam_engine_destroy(spam_engine_handle_t* handle) {
  delete handle;
}

spam_engine_status_t spam_engine_load(
    spam_engine_handle_t* handle,
    const char* model_path,
    float learning_rate,
    const char* ftrl_path) {
  if (handle == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::lock_guard<std::mutex> lock(handle->mutex);

    if (model_path == nullptr || model_path[0] == '\0') {
      return set_error_locked(
          handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "model_path cannot be null or empty");
    }

    clear_error_locked(handle);

    spam_engine::EngineConfig config;
    config.model_path = model_path;
    config.learning_rate = learning_rate;
    config.ftrl_path = (ftrl_path != nullptr) ? ftrl_path : "";
    try {
      handle->engine.load(config);
    } catch (const std::system_error& e) {
      // Thrown from inside load (e.g. std::filesystem_error when a ggml backend
      // plugin dir is unreadable under the Mail-extension sandbox) while we still
      // hold the lock, so reporting it is safe. Without this the status reaches
      // Swift as an empty last_error -> "Unknown error", hiding the real cause.
      return set_error_locked(
          handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR,
          std::string("system error during model load: ") + e.what());
    }
    handle->pending_training_samples.clear();
    return SPAM_ENGINE_STATUS_OK;
  } catch (const std::system_error&) {
    return SPAM_ENGINE_STATUS_RUNTIME_ERROR;  // lock itself failed — handle may be invalid, don't touch it
  } catch (const std::exception& e) {
    return set_error_locked(handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, e.what());
  } catch (...) {
    return set_error_locked(
        handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, "Unknown runtime error in spam_engine_load");
  }
}

spam_engine_status_t spam_engine_load_ggml(
    spam_engine_handle_t* handle,
    const char* model_path,
    const char* gguf_model_path,
    float learning_rate,
    const char* ftrl_path) {
  if (handle == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::lock_guard<std::mutex> lock(handle->mutex);

    if (model_path == nullptr || model_path[0] == '\0') {
      return set_error_locked(
          handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "model_path cannot be null or empty");
    }

    clear_error_locked(handle);

    spam_engine::EngineConfig config;
    config.model_path = model_path;
    config.gguf_model_path = (gguf_model_path != nullptr) ? gguf_model_path : "";
    config.learning_rate = learning_rate;
    config.ftrl_path = (ftrl_path != nullptr) ? ftrl_path : "";
    try {
      handle->engine.load(config);
    } catch (const std::system_error& e) {
      // See spam_engine_load: a system_error from inside load is thrown while the
      // lock is held, so report it rather than surfacing an empty "Unknown error".
      return set_error_locked(
          handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR,
          std::string("system error during model load: ") + e.what());
    }
    handle->pending_training_samples.clear();
    return SPAM_ENGINE_STATUS_OK;
  } catch (const std::system_error&) {
    return SPAM_ENGINE_STATUS_RUNTIME_ERROR;  // lock itself failed — handle may be invalid, don't touch it
  } catch (const std::exception& e) {
    return set_error_locked(handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, e.what());
  } catch (...) {
    return set_error_locked(
        handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, "Unknown runtime error in spam_engine_load_ggml");
  }
}

spam_engine_status_t spam_engine_unload(spam_engine_handle_t* handle) {
  if (handle == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::lock_guard<std::mutex> lock(handle->mutex);
    clear_error_locked(handle);
    handle->engine.unload();
    handle->pending_training_samples.clear();
    return SPAM_ENGINE_STATUS_OK;
  } catch (const std::system_error&) {
    return SPAM_ENGINE_STATUS_RUNTIME_ERROR;
  } catch (const std::exception& e) {
    return set_error_locked(handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, e.what());
  } catch (...) {
    return set_error_locked(
        handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, "Unknown runtime error in spam_engine_unload");
  }
}

int spam_engine_is_loaded(const spam_engine_handle_t* handle) {
  if (handle == nullptr) {
    return 0;
  }

  try {
    std::lock_guard<std::mutex> lock(handle->mutex);
    return handle->engine.is_loaded() ? 1 : 0;
  } catch (...) {
    return 0;
  }
}

int spam_engine_n_embd(const spam_engine_handle_t* handle) {
  if (handle == nullptr) {
    return 0;
  }

  try {
    std::lock_guard<std::mutex> lock(handle->mutex);
    return handle->engine.n_embd();
  } catch (...) {
    return 0;
  }
}

namespace {

// Reject an undersized output buffer up front, before any inference, and set
// *out_n_embd to the dimension every embed buffer must hold. The embedding
// dimension is fixed per loaded model (callers size once via
// spam_engine_n_embd()), so a smaller buffer is a programming error and a
// partial embedding is meaningless — a hard error, not a truncation. Returns
// OK when the buffer fits AND when not loaded (n_embd()==0): the latter lets
// the subsequent embed() call raise the canonical "not loaded" error instead
// of this capacity error masking it. The single guard both embed entry points
// share, so they can't disagree on what "too small" means.
spam_engine_status_t check_embed_capacity_locked(
    spam_engine_handle_t* handle, size_t out_capacity, int* out_n_embd) {
  const int model_n_embd = handle->engine.n_embd();
  *out_n_embd = model_n_embd;
  if (model_n_embd > 0 && out_capacity < static_cast<size_t>(model_n_embd)) {
    return set_error_locked(
        handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
        "out buffer too small for embedding dimension (call spam_engine_n_embd)");
  }
  return SPAM_ENGINE_STATUS_OK;
}

// Precondition: check_embed_capacity_locked has already validated out_embedding
// holds at least n_embd floats, so this copy is bounded.
spam_engine_status_t embed_calibrated_locked(
    spam_engine_handle_t* handle,
    const spam_engine::CalibratedInputText& input,
    float* out_embedding) {
  const auto emb = handle->engine.embed(input);
  std::copy(emb.begin(), emb.end(), out_embedding);
  return SPAM_ENGINE_STATUS_OK;
}

}  // namespace

spam_engine_status_t spam_engine_embed_rfc822(
    spam_engine_handle_t* handle,
    const char* raw_email,
    size_t raw_email_len,
    const char* sender_name,
    const char* sender_email,
    float* out_plain_embedding,
    int* out_plain_filled,
    float* out_html_embedding,
    int* out_html_filled,
    size_t out_capacity,
    int* out_n_embd) {
  if (out_plain_filled != nullptr) *out_plain_filled = 0;
  if (out_html_filled != nullptr) *out_html_filled = 0;
  if (handle == nullptr || raw_email == nullptr || raw_email_len == 0 ||
      out_n_embd == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }
  *out_n_embd = 0;
  if (out_plain_embedding == nullptr && out_html_embedding == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }
  try {
    std::lock_guard<std::mutex> lock(handle->mutex);
    clear_error_locked(handle);

    if (auto s = check_embed_capacity_locked(handle, out_capacity, out_n_embd);
        s != SPAM_ENGINE_STATUS_OK) {
      return s;
    }

    // Run the same preprocessor classify_rfc822 / train_rfc822 use, then
    // wrap each non-empty body part via the canonical builder. The result
    // is bit-identical to what production feeds the head — and the
    // sender-reconciliation logic comes from the same shared helper, so
    // there's no risk of drift between the C ABI and the C++ entry points.
    const auto preprocessed = spam_engine::preprocess_rfc822(
        std::string(raw_email, raw_email_len));
    spam_engine::CustomerInfo customer{
        sender_name != nullptr ? sender_name : "",
        sender_email != nullptr ? sender_email : "",
        false,
    };
    spam_engine::apply_preprocessed_to_customer(customer, preprocessed);

    bool filled_any = false;
    if (out_plain_embedding != nullptr && !preprocessed.normalized_plain_text.empty()) {
      const auto wrapped = spam_engine::build_input_text(
          {{"user", preprocessed.normalized_plain_text, "email"}}, customer);
      const auto emb = handle->engine.embed(wrapped);
      std::copy(emb.begin(), emb.end(), out_plain_embedding);
      if (out_plain_filled != nullptr) *out_plain_filled = 1;
      filled_any = true;
    }
    if (out_html_embedding != nullptr && !preprocessed.normalized_html_text.empty() &&
        preprocessed.normalized_html_text != preprocessed.normalized_plain_text) {
      const auto wrapped = spam_engine::build_input_text(
          {{"user", preprocessed.normalized_html_text, "email"}}, customer);
      const auto emb = handle->engine.embed(wrapped);
      std::copy(emb.begin(), emb.end(), out_html_embedding);
      if (out_html_filled != nullptr) *out_html_filled = 1;
      filled_any = true;
    }

    // Fallback: if neither plain nor HTML body was extracted (e.g. single-
    // part message with no explicit Content-Type), use normalized_text —
    // mirrors the fallback in SpamEngine::classify_rfc822 / train_rfc822.
    if (!filled_any && !preprocessed.normalized_text.empty()) {
      const auto wrapped = spam_engine::build_input_text(
          {{"user", preprocessed.normalized_text, "email"}}, customer);
      const auto emb = handle->engine.embed(wrapped);
      // Write to whichever buffer the caller provided (prefer plain).
      float* dest = out_plain_embedding != nullptr ? out_plain_embedding : out_html_embedding;
      std::copy(emb.begin(), emb.end(), dest);
      if (dest == out_plain_embedding && out_plain_filled != nullptr) *out_plain_filled = 1;
      if (dest == out_html_embedding && out_html_filled != nullptr) *out_html_filled = 1;
    }

    return SPAM_ENGINE_STATUS_OK;
  } catch (const std::exception& e) {
    return set_error_locked(handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, e.what());
  } catch (...) {
    return set_error_locked(handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR,
                             "Unknown error in spam_engine_embed_rfc822");
  }
}

spam_engine_status_t spam_engine_embed_text(
    spam_engine_handle_t* handle,
    const char* text,
    const char* sender_name,
    const char* sender_email,
    float* out_embedding,
    size_t out_capacity,
    int* out_n_embd) {
  if (handle == nullptr || text == nullptr ||
      out_embedding == nullptr || out_n_embd == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }
  *out_n_embd = 0;
  try {
    std::lock_guard<std::mutex> lock(handle->mutex);
    clear_error_locked(handle);
    // Reject an undersized buffer before the (expensive) inference, same as
    // spam_engine_embed_rfc822.
    if (auto s = check_embed_capacity_locked(handle, out_capacity, out_n_embd);
        s != SPAM_ENGINE_STATUS_OK) {
      return s;
    }
    spam_engine::CustomerInfo customer{
        sender_name != nullptr ? sender_name : "",
        sender_email != nullptr ? sender_email : "",
        false,
    };
    const auto calibrated = spam_engine::build_input_text(
        {{"user", text, "email"}}, customer);
    return embed_calibrated_locked(handle, calibrated, out_embedding);
  } catch (const std::exception& e) {
    return set_error_locked(handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, e.what());
  } catch (...) {
    return set_error_locked(handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR,
                             "Unknown error in spam_engine_embed_text");
  }
}

spam_engine_status_t spam_engine_classify(
    spam_engine_handle_t* handle,
    const char* text,
    const char* sender_name,
    const char* sender_email,
    const char* mode,
    spam_engine_result_t* out_result) {
  if (handle == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::lock_guard<std::mutex> lock(handle->mutex);

    if (text == nullptr) {
      return set_error_locked(handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "text cannot be null");
    }
    if (!is_valid_mode(mode)) {
      return set_error_locked(handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
                              "mode must be \"ensemble\", \"neural\", or \"ftrl\"");
    }
    if (out_result == nullptr) {
      return set_error_locked(
          handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "out_result cannot be null");
    }

    clear_error_locked(handle);

    const auto result = handle->engine.classify(
        text,
        (sender_name != nullptr) ? sender_name : "",
        (sender_email != nullptr) ? sender_email : "",
        spam_engine::ClassifyOptions{mode});
    fill_result(result, out_result);
    return SPAM_ENGINE_STATUS_OK;
  } catch (const std::system_error&) {
    return SPAM_ENGINE_STATUS_RUNTIME_ERROR;
  } catch (const std::exception& e) {
    return set_error_locked(handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, e.what());
  } catch (...) {
    return set_error_locked(
        handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, "Unknown runtime error in spam_engine_classify");
  }
}

spam_engine_status_t spam_engine_classify_rfc822(
    spam_engine_handle_t* handle,
    const char* raw_email,
    size_t raw_email_len,
    const char* sender_name,
    const char* sender_email,
    const char* mode,
    spam_engine_result_t* out_result,
    spam_engine_parsed_signals_t* out_signals) {
  // Optional out-param: zero it up front so a caller that passes a buffer always
  // gets a safe "no signals" default, even on an early error return.
  if (out_signals != nullptr) std::memset(out_signals, 0, sizeof(*out_signals));

  if (handle == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::lock_guard<std::mutex> lock(handle->mutex);

    if (raw_email == nullptr) {
      return set_error_locked(
          handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "raw_email cannot be null");
    }
    if (raw_email_len == 0) {
      return set_error_locked(
          handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "raw_email_len must be > 0");
    }
    if (!is_valid_mode(mode)) {
      return set_error_locked(handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
                              "mode must be \"ensemble\", \"neural\", or \"ftrl\"");
    }
    if (out_result == nullptr) {
      return set_error_locked(
          handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "out_result cannot be null");
    }

    clear_error_locked(handle);

    const auto result = handle->engine.classify_rfc822(
        std::string(raw_email, raw_email_len),
        (sender_name != nullptr) ? sender_name : "",
        (sender_email != nullptr) ? sender_email : "",
        spam_engine::ClassifyOptions{mode});
    fill_result(result, out_result);
    if (out_signals != nullptr) {
      fill_thread_features(result.thread_features, &out_signals->thread);
      fill_auth_features(result.auth_features, &out_signals->auth);
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
        "Unknown runtime error in spam_engine_classify_rfc822");
  }
}

spam_engine_status_t spam_engine_extract_contribution(
    spam_engine_handle_t* handle,
    const char* raw_rfc822,
    size_t raw_rfc822_len,
    const char* sender_name,
    const char* sender_email,
    uint64_t hash_key,
    uint32_t* out_buckets,
    float* out_weights,
    size_t capacity,
    size_t* out_count) {
  if (out_count != nullptr) *out_count = 0;

  if (handle == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::lock_guard<std::mutex> lock(handle->mutex);

    if (raw_rfc822 == nullptr || raw_rfc822_len == 0) {
      return set_error_locked(
          handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "raw_rfc822 cannot be empty");
    }
    if (out_count == nullptr) {
      return set_error_locked(
          handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "out_count cannot be null");
    }
    if (capacity > 0 && (out_buckets == nullptr || out_weights == nullptr)) {
      return set_error_locked(
          handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "output buffers cannot be null");
    }

    clear_error_locked(handle);

    const auto bag = handle->engine.extract_contribution(
        std::string(raw_rfc822, raw_rfc822_len),
        (sender_name != nullptr) ? sender_name : "",
        (sender_email != nullptr) ? sender_email : "",
        hash_key);

    *out_count = bag.size();
    size_t i = 0;
    for (const auto& kv : bag) {
      if (i >= capacity) break;  // truncated; caller re-calls with *out_count capacity
      out_buckets[i] = kv.first;
      out_weights[i] = kv.second;
      ++i;
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
        "Unknown runtime error in spam_engine_extract_contribution");
  }
}

spam_engine_status_t spam_engine_scrub_rfc822(
    spam_engine_handle_t* handle,
    const char* raw_rfc822,
    size_t raw_rfc822_len,
    char* out_buf,
    size_t capacity,
    size_t* out_len) {
  if (out_len != nullptr) *out_len = 0;

  if (handle == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::lock_guard<std::mutex> lock(handle->mutex);

    if (raw_rfc822 == nullptr || raw_rfc822_len == 0) {
      return set_error_locked(
          handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "raw_rfc822 cannot be empty");
    }
    if (out_len == nullptr) {
      return set_error_locked(
          handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "out_len cannot be null");
    }

    clear_error_locked(handle);

    const std::string scrubbed =
        handle->engine.scrub_contribution(std::string(raw_rfc822, raw_rfc822_len));

    *out_len = scrubbed.size();
    if (capacity > 0 && out_buf != nullptr) {
      const size_t n = std::min(capacity, scrubbed.size());  // truncated; caller re-calls
      std::memcpy(out_buf, scrubbed.data(), n);
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
        "Unknown runtime error in spam_engine_scrub_rfc822");
  }
}

const char* spam_engine_get_last_error(const spam_engine_handle_t* handle) {
  if (handle == nullptr) {
    return nullptr;
  }

  try {
    std::lock_guard<std::mutex> lock(handle->mutex);
    if (handle->last_error.empty()) {
      return nullptr;
    }

    // Return a thread-local snapshot to avoid exposing handle-owned mutable storage.
    thread_local std::string error_snapshot;
    error_snapshot = handle->last_error;
    return error_snapshot.c_str();
  } catch (...) {
    return nullptr;
  }
}

namespace {

char* strdup_or_null(const std::string& s) {
  if (s.empty()) {
    return nullptr;
  }
  char* copy = static_cast<char*>(std::malloc(s.size() + 1));
  if (copy != nullptr) {
    std::memcpy(copy, s.data(), s.size());
    copy[s.size()] = '\0';
  }
  return copy;
}

}  // namespace

int spam_engine_extract_body(
    const char* raw_email,
    size_t raw_email_len,
    spam_engine_email_body_t* out_body) {
  if (raw_email == nullptr || raw_email_len == 0 || out_body == nullptr) {
    return -1;
  }

  try {
    const auto extracted = spam_engine::extract_email_body(std::string(raw_email, raw_email_len));

    out_body->html_body = strdup_or_null(extracted.html_body);
    out_body->plain_body = strdup_or_null(extracted.plain_body);
    out_body->subject = strdup_or_null(extracted.subject);
    out_body->from = strdup_or_null(extracted.from);
    out_body->text_preview = strdup_or_null(extracted.text_preview);
    out_body->date = strdup_or_null(extracted.date);

    return 0;
  } catch (...) {
    out_body->html_body = nullptr;
    out_body->plain_body = nullptr;
    out_body->subject = nullptr;
    out_body->from = nullptr;
    out_body->text_preview = nullptr;
    out_body->date = nullptr;
    return -1;
  }
}

void spam_engine_free_string(char* str) {
  std::free(str);
}

char* spam_engine_extract_url_domains(const char* raw_email, size_t raw_email_len) {
  if (raw_email == nullptr || raw_email_len == 0) {
    return nullptr;
  }
  try {
    const auto domains =
        spam_engine::extract_url_domains(std::string(raw_email, raw_email_len));
    std::string joined;
    for (size_t i = 0; i < domains.size(); ++i) {
      if (i != 0) joined += '\n';
      joined += domains[i];
    }
    // Always allocate (even for ""), so "" = parsed, no URLs vs NULL = failure.
    char* copy = static_cast<char*>(std::malloc(joined.size() + 1));
    if (copy == nullptr) return nullptr;
    std::memcpy(copy, joined.data(), joined.size());
    copy[joined.size()] = '\0';
    return copy;
  } catch (...) {
    return nullptr;
  }
}

int spam_engine_extract_thread_features(
    const char* raw_email,
    size_t raw_email_len,
    spam_engine_thread_features_t* out_features) {
  if (out_features == nullptr) {
    return -1;
  }
  std::memset(out_features, 0, sizeof(*out_features));
  // Null pointer is still a contract violation; empty input is not — the
  // inner C++ implementation handles size==0 by returning empty features.
  if (raw_email == nullptr) {
    return -1;
  }

  try {
    fill_thread_features(
        spam_engine::extract_thread_features(std::string(raw_email, raw_email_len)),
        out_features);
    return 0;
  } catch (...) {
    std::memset(out_features, 0, sizeof(*out_features));
    return -1;
  }
}

int spam_engine_extract_auth_features(
    const char* raw_email,
    size_t raw_email_len,
    spam_engine_auth_features_t* out_features) {
  if (out_features == nullptr) {
    return -1;
  }
  std::memset(out_features, 0, sizeof(*out_features));
  if (raw_email == nullptr) {
    return -1;
  }

  try {
    fill_auth_features(
        spam_engine::extract_auth_features(std::string(raw_email, raw_email_len)),
        out_features);
    return 0;
  } catch (...) {
    std::memset(out_features, 0, sizeof(*out_features));
    return -1;
  }
}

void spam_engine_decision_input_from_signals(
    spam_engine_decision_input_t* din,
    const spam_engine_scores_t* scores,
    const spam_engine_parsed_signals_t* signals) {
  if (din == nullptr || scores == nullptr || signals == nullptr) return;
  din->scores = *scores;
  // The fold reads ml_label as the model's own spam-side DECISION, not a raw
  // argmax: a gibberish-argmax mail the engine scores as a deliver must not set
  // ml_said_spam here when it doesn't in the engine and Swift (TASK-251 C5). Use
  // the shared neural_decision so all three paths agree.
  const spam_engine::decision::NeuralDecision nd = spam_engine::decision::neural_decision(
      {scores->gibberish, scores->marketing, scores->regular, scores->spam});
  din->ml_label = nd.label;
  din->ml_confidence = static_cast<float>(nd.confidence);
  din->has_in_reply_to = signals->thread.has_in_reply_to;
  din->references_count = signals->thread.references_count;
  din->dkim_signing_org_domain = signals->auth.dkim_signing_domain;
  din->signer_throwaway = signals->auth.signer_throwaway;
  din->display_impersonation = signals->auth.display_impersonation;
  // Caller-state fields (phase2_match, exact/domain_send_count, profile) left as is.
}

int spam_engine_decide(const spam_engine_decision_input_t* in,
                       spam_engine_decision_result_t* out) {
  if (in == nullptr || out == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }
  std::memset(out, 0, sizeof(*out));

  namespace dl = spam_engine::decision;

  dl::Scores scores;
  scores.gibberish = in->scores.gibberish;
  scores.marketing = in->scores.marketing;
  scores.regular = in->scores.regular;
  scores.spam = in->scores.spam;

  // Offsets in the canonical audit order (thread, phase2, sender-history,
  // sender-auth, sender-reputation) — same order ClassificationService appends them.
  std::vector<dl::Offset> offsets;
  offsets.push_back({"thread_headers",
                     dl::thread_header_offset(in->has_in_reply_to != 0,
                                              in->references_count),
                     dl::Direction::Ham});
  if (in->phase2_match != 0) {
    offsets.push_back({"thread_history", dl::kPhase2Match, dl::Direction::Ham});
  }
  offsets.push_back({"sender_history",
                     dl::sender_history_magnitude(in->exact_send_count,
                                                  in->domain_send_count),
                     dl::Direction::Ham});
  const std::string signer =
      in->dkim_signing_org_domain != nullptr ? in->dkim_signing_org_domain : "";
  offsets.push_back({"sender_auth",
                     dl::sender_auth_offset(signer, in->signer_throwaway != 0),
                     dl::Direction::Spam});
  // Display-name brand impersonation (TASK-214): spam-ward, mirror of sender_auth.
  // The flag is computed in extract_auth_features (dictionary-filtered brand-name
  // match vs the From org-domain); strong magnitude to carry a low-neural phish
  // (the Scaleway clone scored 0.06) over the gate, like the free-host push.
  offsets.push_back({"display_impersonation",
                     in->display_impersonation != 0 ? dl::kDisplayImpersonation : 0.0,
                     dl::Direction::Spam});
  // Established-brand / clean-ESP ham rescue (TASK-170): the ham-ward mirror of
  // the sender_auth spam push. Gating + short-circuit live in the named helper
  // (brand_reputation.h), mirrored by AuthFeatures.hamConfidenceOffset in Swift.
  // KNOWN INTERACTION: in ensemble mode scores.spam is the escalate-only spam
  // side, so a warm-FTRL escalation of brand/ESP-signed personalized spam into
  // [0.90, ceiling) is undone by this -0.15 rescue (reputation wins over
  // personalization below the 0.97 ceiling). Bounded + rare (brand-signed mail
  // the user marked spam); the ceiling backstops the confident cases. Revisit if
  // the flywheel shows brand-signed graymail the user keeps re-marking.
  const double raw_spam_side = in->scores.spam + in->scores.gibberish;
  offsets.push_back({"sender_reputation",
                     spam_engine::brand_reputation::brand_reputation_offset(
                         signer, raw_spam_side, dl::is_free_host_signed(signer),
                         in->signer_throwaway != 0),
                     dl::Direction::Ham});

  dl::Profile profile = dl::Profile::Standard;
  if (in->profile == SPAM_ENGINE_PROFILE_CAUTIOUS) profile = dl::Profile::Cautious;
  else if (in->profile == SPAM_ENGINE_PROFILE_LEARNING) profile = dl::Profile::Learning;

  const std::string ml_label = in->ml_label != nullptr ? in->ml_label : "";
  const dl::Verdict v = dl::fold(scores, offsets,
                                 dl::threshold_for_profile(profile),
                                 ml_label, in->ml_confidence);

  std::strncpy(out->label, v.label.c_str(), sizeof(out->label) - 1);
  out->label[sizeof(out->label) - 1] = '\0';
  out->confidence = v.confidence;
  out->adjusted_spam_side = v.adjusted_spam_side;
  out->train_ml = v.train_ml ? 1 : 0;
  out->condemn_offset_fired = 0;
  for (const auto& f : v.fired) {
    if (f.direction == dl::Direction::Spam) { out->condemn_offset_fired = 1; break; }
  }
  return SPAM_ENGINE_STATUS_OK;
}

spam_engine_status_t spam_engine_classify_full(
    spam_engine_handle_t* handle,
    const char* raw_email,
    size_t raw_email_len,
    const char* sender_name,
    const char* sender_email,
    const char* mode,
    const spam_engine_caller_state_t* caller_state,
    spam_engine_full_result_t* out) {
  if (out != nullptr) std::memset(out, 0, sizeof(*out));
  if (handle == nullptr || out == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::lock_guard<std::mutex> lock(handle->mutex);

    if (raw_email == nullptr || raw_email_len == 0) {
      return set_error_locked(
          handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "raw_email cannot be empty");
    }
    if (!is_valid_mode(mode)) {
      return set_error_locked(handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
                              "mode must be \"ensemble\", \"neural\", or \"ftrl\"");
    }
    clear_error_locked(handle);

    // Stages 1+2(+2.5): FTRL P(spam) → neural → ensemble blend, one parse.
    const auto r = handle->engine.classify_rfc822(
        std::string(raw_email, raw_email_len),
        (sender_name != nullptr) ? sender_name : "",
        (sender_email != nullptr) ? sender_email : "",
        spam_engine::ClassifyOptions{mode});

    out->ftrl_score = r.ftrl_score;
    out->neural_scores.gibberish = r.scores.gibberish;
    out->neural_scores.marketing = r.scores.marketing;
    out->neural_scores.regular = r.scores.regular;
    // scores.spam is the ensemble-blended spam side; neural_spam is the pre-blend
    // neural value (== scores.spam when FTRL didn't contribute).
    out->neural_scores.spam = (r.neural_spam >= 0.0f) ? r.neural_spam : r.scores.spam;
    out->ensemble_spam = r.scores.spam;
    std::strncpy(out->decided_by, r.decided_by.c_str(), sizeof(out->decided_by) - 1);
    out->decided_by[sizeof(out->decided_by) - 1] = '\0';
    fill_thread_features(r.thread_features, &out->signals.thread);
    fill_auth_features(r.auth_features, &out->signals.auth);

    // Stage 3: fold the structural offsets onto the ENSEMBLE spam side. Reuse
    // spam_engine_decide so the fold can never drift from the standalone path.
    // Fold uses the engine's scores as-is: gibberish/marketing/regular are raw
    // neural and scores.spam is already the ensemble-blended side (combine_scores).
    const spam_engine_scores_t scores = {r.scores.gibberish, r.scores.marketing,
                                         r.scores.regular, r.scores.spam};
    spam_engine_decision_input_t din{};
    spam_engine_decision_input_from_signals(&din, &scores, &out->signals);
    if (caller_state != nullptr) {
      din.phase2_match = caller_state->phase2_match;
      din.exact_send_count = caller_state->exact_send_count;
      din.domain_send_count = caller_state->domain_send_count;
      din.profile = caller_state->profile;
    }
    spam_engine_decide(&din, &out->decision);
    return SPAM_ENGINE_STATUS_OK;
  } catch (const std::system_error&) {
    return SPAM_ENGINE_STATUS_RUNTIME_ERROR;
  } catch (const std::exception& e) {
    return set_error_locked(handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR, e.what());
  } catch (...) {
    return set_error_locked(
        handle, SPAM_ENGINE_STATUS_RUNTIME_ERROR,
        "Unknown runtime error in spam_engine_classify_full");
  }
}

}  // extern "C"
