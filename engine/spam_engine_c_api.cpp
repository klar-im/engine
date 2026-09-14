#include "spam_engine_c_api.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <exception>
#include <string>
#include <system_error>

#include "brand_reputation.h"
#include "decision_layer.h"
#include "email_preprocessor.h"
#include "spam_engine_handle_internal.h"

namespace {

// Writes `src`, truncated to `capacity`, into `out_buf` and sets *out_len to
// src's true length so the caller can detect truncation and re-call with a
// bigger buffer. out_buf is a length-prefixed byte copy, not expected to be
// null-terminated: this is the shared contract behind every C API function
// that returns a variable-length string this way.
void copy_length_prefixed(const std::string& src, char* out_buf, size_t capacity, size_t* out_len) {
  *out_len = src.size();
  if (out_buf != nullptr && capacity > 0) {
    // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
    std::memcpy(out_buf, src.data(), std::min(capacity, src.size()));
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
  out->kb_brand_dmarc_pass = features.kb_brand_dmarc_pass ? 1 : 0;
  out->dmarc_pass = features.dmarc_pass ? 1 : 0;
}

void fill_body_features(
    const spam_engine::ExtractedBodyFeatures& features,
    spam_engine_body_features_t* out) {
  std::memset(out, 0, sizeof(*out));
  out->gtube_test = features.gtube_test ? 1 : 0;
  out->callback_shape = features.callback_shape ? 1 : 0;
  out->no_contact_instruction = features.no_contact_instruction ? 1 : 0;
}

void fill_url_features(
    const spam_engine::ExtractedUrlFeatures& features,
    spam_engine_url_features_t* out) {
  std::memset(out, 0, sizeof(*out));
  out->raw_ip_url = features.raw_ip_url ? 1 : 0;
}

void fill_attachment_features(
    const spam_engine::ExtractedAttachmentFeatures& features,
    spam_engine_attachment_features_t* out) {
  std::memset(out, 0, sizeof(*out));
  out->total_count = features.total_count;
  out->total_bytes = features.total_bytes;
  out->archive_member_count = features.archive_member_count;
  out->disguised_executable = features.disguised_executable ? 1 : 0;
  out->archive_disguised_executable =
      features.archive_disguised_executable ? 1 : 0;
  out->dangerous_type = features.dangerous_type ? 1 : 0;
  out->archive_dangerous_type = features.archive_dangerous_type ? 1 : 0;
  out->macro_document = features.macro_document ? 1 : 0;
  out->encrypted_archive = features.encrypted_archive ? 1 : 0;
  out->truncated = features.truncated ? 1 : 0;
  out->parse_failed = features.parse_failed ? 1 : 0;
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

// Deliberately non-const, even though `delete` doesn't need it to be: this is
// a public C API function, and postfix/tests/model_runtime_calibration_tests.cpp
// declares its own stub with this exact non-const signature. Const-ing it
// here (as an earlier pass in this PR did) is a source-compatibility break
// for that independent build target, caught by codex review, TASK-478.
// NOLINTNEXTLINE(misc-const-correctness)
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
    std::scoped_lock const lock(handle->mutex);

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
    std::scoped_lock const lock(handle->mutex);

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
    std::scoped_lock const lock(handle->mutex);
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
    std::scoped_lock const lock(handle->mutex);
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
    std::scoped_lock const lock(handle->mutex);
    return handle->engine.n_embd();
  } catch (...) {
    return 0;
  }
}

namespace {
// Always NUL-terminated, and a value longer than the field is truncated rather
// than dropped: a truncated uuid is still recognisable in a log, and silently
// reporting "" would read as "no manifest".
void copy_fixed(char* dst, std::size_t cap, const std::string& src) {
  const std::size_t n = src.size() < cap - 1 ? src.size() : cap - 1;
  std::memcpy(dst, src.data(), n);
  dst[n] = '\0';
}
}  // namespace

int spam_engine_model_info(const spam_engine_handle_t* handle,
                           spam_engine_model_info_t* out) {
  if (handle == nullptr || out == nullptr) {
    return 0;
  }

  try {
    std::scoped_lock const lock(handle->mutex);
    // An unloaded handle has no artifact to describe. Reporting success with a
    // zeroed struct would hand the caller a confident "hidden_size 0, uuid
    // unknown" that reads like a real answer.
    if (!handle->engine.is_loaded()) {
      return 0;
    }
    const auto info = handle->engine.model_info();
    copy_fixed(out->uuid, sizeof(out->uuid), info.uuid);
    copy_fixed(out->source_model, sizeof(out->source_model), info.source_model);
    out->hidden_size = info.hidden_size;
    out->num_labels = info.num_labels;
    out->raw_input = info.raw_input ? 1 : 0;
    out->structural_markers = info.structural_markers ? 1 : 0;
    out->spam_side_calibration_knot = info.spam_side_calibration_knot;
    out->attachment_context = info.attachment_context ? 1 : 0;
    return 1;
  } catch (...) {
    return 0;
  }
}

int spam_engine_uses_gpu(const spam_engine_handle_t* handle) {
  if (handle == nullptr) {
    return 0;
  }

  try {
    std::scoped_lock const lock(handle->mutex);
    return handle->engine.uses_gpu() ? 1 : 0;
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
  if (out_plain_filled != nullptr) { *out_plain_filled = 0;
}
  if (out_html_filled != nullptr) { *out_html_filled = 0;
}
  if (handle == nullptr || raw_email == nullptr || raw_email_len == 0 ||
      out_n_embd == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }
  *out_n_embd = 0;
  if (out_plain_embedding == nullptr && out_html_embedding == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }
  try {
    std::scoped_lock const lock(handle->mutex);
    clear_error_locked(handle);

    if (auto const s = check_embed_capacity_locked(handle, out_capacity, out_n_embd);
        s != SPAM_ENGINE_STATUS_OK) {
      return s;
    }

    // Run the same preprocessor classify_rfc822 / train_rfc822 use, then
    // wrap each non-empty body part via the canonical builder. The result
    // is bit-identical to what production feeds the head — and the
    // sender-reconciliation logic comes from the same shared helper, so
    // there's no risk of drift between the C ABI and the C++ entry points.
    const auto preprocessed = spam_engine::preprocess_rfc822(
        std::string(raw_email, raw_email_len),
        handle->engine.uses_attachment_context());
    spam_engine::CustomerInfo customer{
        sender_name != nullptr ? sender_name : "",
        sender_email != nullptr ? sender_email : "",
        false,
    };
    spam_engine::apply_preprocessed_to_customer(customer, preprocessed);

    bool filled_any = false;
    if (out_plain_embedding != nullptr && !preprocessed.normalized_plain_text.empty()) {
      const auto wrapped = handle->engine.calibrate_preprocessed_input(
          preprocessed.normalized_plain_text,
          preprocessed.structural_marker_prefix,
          preprocessed.attachment_features.context, customer);
      const auto emb = handle->engine.embed(wrapped);
      std::copy(emb.begin(), emb.end(), out_plain_embedding);
      if (out_plain_filled != nullptr) { *out_plain_filled = 1;
}
      filled_any = true;
    }
    if (out_html_embedding != nullptr && !preprocessed.normalized_html_text.empty() &&
        preprocessed.normalized_html_text != preprocessed.normalized_plain_text) {
      const auto wrapped = handle->engine.calibrate_preprocessed_input(
          preprocessed.normalized_html_text,
          preprocessed.structural_marker_prefix,
          preprocessed.attachment_features.context, customer);
      const auto emb = handle->engine.embed(wrapped);
      std::copy(emb.begin(), emb.end(), out_html_embedding);
      if (out_html_filled != nullptr) { *out_html_filled = 1;
}
      filled_any = true;
    }

    // Fallback: if neither plain nor HTML body was extracted (e.g. single-
    // part message with no explicit Content-Type), use normalized_text —
    // mirrors the fallback in SpamEngine::classify_rfc822 / train_rfc822.
    if (!filled_any && !preprocessed.normalized_text.empty()) {
      const auto wrapped = handle->engine.calibrate_preprocessed_input(
          preprocessed.normalized_text,
          preprocessed.structural_marker_prefix,
          preprocessed.attachment_features.context, customer);
      const auto emb = handle->engine.embed(wrapped);
      // Write to whichever buffer the caller provided (prefer plain).
      float* dest = out_plain_embedding != nullptr ? out_plain_embedding : out_html_embedding;
      std::copy(emb.begin(), emb.end(), dest);
      if (dest == out_plain_embedding && out_plain_filled != nullptr) { *out_plain_filled = 1;
}
      if (dest == out_html_embedding && out_html_filled != nullptr) { *out_html_filled = 1;
}
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
    std::scoped_lock const lock(handle->mutex);
    clear_error_locked(handle);
    // Reject an undersized buffer before the (expensive) inference, same as
    // spam_engine_embed_rfc822.
    if (auto const s = check_embed_capacity_locked(handle, out_capacity, out_n_embd);
        s != SPAM_ENGINE_STATUS_OK) {
      return s;
    }
    spam_engine::CustomerInfo const customer{
        sender_name != nullptr ? sender_name : "",
        sender_email != nullptr ? sender_email : "",
        false,
    };
    const auto calibrated = handle->engine.calibrate_input(
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
    std::scoped_lock const lock(handle->mutex);

    if (text == nullptr) {
      return set_error_locked(handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "text cannot be null");
    }
    if (!is_valid_mode(mode)) {
      return set_error_locked(handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
                              R"(mode must be "ensemble", "neural", or "ftrl")");
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
  if (out_signals != nullptr) { std::memset(out_signals, 0, sizeof(*out_signals));
}

  if (handle == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::scoped_lock const lock(handle->mutex);

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
                              R"(mode must be "ensemble", "neural", or "ftrl")");
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
      fill_url_features(result.url_features, &out_signals->url);
      fill_body_features(result.body_features, &out_signals->body);
      fill_attachment_features(result.attachment_features, &out_signals->attachment);
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
  if (out_count != nullptr) { *out_count = 0;
}

  if (handle == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::scoped_lock const lock(handle->mutex);

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
      if (i >= capacity) { break;  // truncated; caller re-calls with *out_count capacity
}
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
  if (out_len != nullptr) { *out_len = 0;
}

  if (handle == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::scoped_lock const lock(handle->mutex);

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

    copy_length_prefixed(scrubbed, out_buf, capacity, out_len);
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

spam_engine_status_t spam_engine_html_to_text(
    const char* html,
    size_t html_len,
    char* out_buf,
    size_t capacity,
    size_t* out_len) {
  if (out_len != nullptr) { *out_len = 0;
}

  // No handle here, so there is nowhere to record an error string; callers get
  // the status code only.
  if (out_len == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }
  if (html == nullptr && html_len != 0) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    const std::string text =
        spam_engine::html_to_text(std::string(html == nullptr ? "" : html, html_len));
    copy_length_prefixed(text, out_buf, capacity, out_len);
    return SPAM_ENGINE_STATUS_OK;
  } catch (...) {
    return SPAM_ENGINE_STATUS_RUNTIME_ERROR;
  }
}

const char* spam_engine_get_last_error(const spam_engine_handle_t* handle) {
  if (handle == nullptr) {
    return nullptr;
  }

  try {
    std::scoped_lock const lock(handle->mutex);
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
  // malloc, not new[]: the caller frees this across the C ABI boundary with
  // spam_engine_free_string(), which must use a matching std::free().
  // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
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

spam_engine_status_t spam_engine_make_replay_rfc822(
    const char* raw_email,
    size_t raw_email_len,
    char* out_buf,
    size_t capacity,
    size_t* out_len) {
  if (raw_email == nullptr || raw_email_len == 0 || out_len == nullptr ||
      (out_buf == nullptr && capacity != 0)) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }
  try {
    const std::string replay = spam_engine::make_replay_rfc822(
        std::string(raw_email, raw_email_len));
    copy_length_prefixed(replay, out_buf, capacity, out_len);
    return SPAM_ENGINE_STATUS_OK;
  } catch (...) {
    *out_len = 0;
    return SPAM_ENGINE_STATUS_RUNTIME_ERROR;
  }
}

void spam_engine_free_string(char* str) {
  // Matches the std::malloc() in strdup_or_null() / spam_engine_extract_url_domains()
  // across the C ABI boundary.
  // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
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
      if (i != 0) { joined += '\n';
}
      joined += domains[i];
    }
    // Always allocate (even for ""), so "" = parsed, no URLs vs NULL = failure.
    // malloc, not new[]: caller frees with spam_engine_free_string()'s std::free().
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
    char* copy = static_cast<char*>(std::malloc(joined.size() + 1));
    if (copy == nullptr) {
      return nullptr;
    }
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

int spam_engine_extract_body_features(
    const char* raw_email,
    size_t raw_email_len,
    spam_engine_body_features_t* out_features) {
  if (out_features == nullptr) {
    return -1;
  }
  std::memset(out_features, 0, sizeof(*out_features));
  if (raw_email == nullptr) {
    return -1;
  }

  try {
    fill_body_features(
        spam_engine::extract_body_features(std::string(raw_email, raw_email_len)),
        out_features);
    return 0;
  } catch (...) {
    std::memset(out_features, 0, sizeof(*out_features));
    return -1;
  }
}

spam_engine_status_t spam_engine_extract_attachment_context(
    const char* raw_email,
    size_t raw_email_len,
    spam_engine_attachment_features_t* out_features,
    char* out_buf,
    size_t capacity,
    size_t* out_len) {
  if (out_features != nullptr) { std::memset(out_features, 0, sizeof(*out_features));
}
  if (out_len != nullptr) { *out_len = 0;
}
  if (raw_email == nullptr || out_len == nullptr ||
      (out_buf == nullptr && capacity != 0)) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }
  try {
    const auto features = spam_engine::extract_attachment_features(
        std::string(raw_email, raw_email_len));
    if (out_features != nullptr) { fill_attachment_features(features, out_features);
}
    copy_length_prefixed(features.context, out_buf, capacity, out_len);
    return SPAM_ENGINE_STATUS_OK;
  } catch (...) {
    if (out_features != nullptr) { std::memset(out_features, 0, sizeof(*out_features));
}
    *out_len = 0;
    return SPAM_ENGINE_STATUS_RUNTIME_ERROR;
  }
}

void spam_engine_decision_input_from_signals(
    spam_engine_decision_input_t* din,
    const spam_engine_scores_t* scores,
    const spam_engine_parsed_signals_t* signals) {
  if (din == nullptr || scores == nullptr || signals == nullptr) { return;
}
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
  din->raw_ip_url = signals->url.raw_ip_url;
  din->gtube_test = signals->body.gtube_test;
  din->callback_shape = signals->body.callback_shape;
  din->no_contact_instruction = signals->body.no_contact_instruction;
  din->dmarc_pass = signals->auth.dmarc_pass;
  din->kb_brand_dmarc_pass = signals->auth.kb_brand_dmarc_pass;
  din->attachment_disguised_executable =
      signals->attachment.disguised_executable;
  din->archive_disguised_executable =
      signals->attachment.archive_disguised_executable;
  din->attachment_dangerous_type = signals->attachment.dangerous_type;
  din->archive_dangerous_type = signals->attachment.archive_dangerous_type;
  // Caller-state fields (phase2_match, exact/domain_send_count, profile) left as is.
  // connect_ip_blocked too, and that is load-bearing rather than incidental: no
  // amount of parsing may switch on a condemn-capable transport offset. A
  // consumer that never observed a connection (the Mail extension) leaves it
  // zero-initialized and the signal is simply off (TASK-113).
}

void spam_engine_get_abi_sizes(spam_engine_abi_sizes_t* out) {
  if (out == nullptr) { return;
}
  out->field_count = 8;
  out->parsed_signals = static_cast<uint32_t>(sizeof(spam_engine_parsed_signals_t));
  out->decision_input = static_cast<uint32_t>(sizeof(spam_engine_decision_input_t));
  out->decision_result = static_cast<uint32_t>(sizeof(spam_engine_decision_result_t));
  out->caller_state = static_cast<uint32_t>(sizeof(spam_engine_caller_state_t));
  out->full_result = static_cast<uint32_t>(sizeof(spam_engine_full_result_t));
  out->result = static_cast<uint32_t>(sizeof(spam_engine_result_t));
  out->scores = static_cast<uint32_t>(sizeof(spam_engine_scores_t));
  out->attachment_features =
      static_cast<uint32_t>(sizeof(spam_engine_attachment_features_t));
  out->caller_state_phase2_match =
      static_cast<uint32_t>(offsetof(spam_engine_caller_state_t, phase2_match));
  out->caller_state_exact_send_count =
      static_cast<uint32_t>(offsetof(spam_engine_caller_state_t, exact_send_count));
  out->caller_state_domain_send_count =
      static_cast<uint32_t>(offsetof(spam_engine_caller_state_t, domain_send_count));
  out->caller_state_profile =
      static_cast<uint32_t>(offsetof(spam_engine_caller_state_t, profile));
  out->caller_state_connect_ip_blocked =
      static_cast<uint32_t>(offsetof(spam_engine_caller_state_t, connect_ip_blocked));
  out->caller_state_attachment_risk_enabled =
      static_cast<uint32_t>(offsetof(spam_engine_caller_state_t,
                                     attachment_risk_enabled));
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
  // Bare-IP body link (TASK-257): a structural phishing tell. Modest magnitude,
  // it corroborates rather than solo-condemns a clean message (a lone raw-IP link
  // on an otherwise-ham score won't cross the gate), and the ablation showed no
  // measured lift on the corpus, so this is precision-first insurance for the
  // out-of-sample raw-IP phish the model misses, not a corpus-tuned catch.
  offsets.push_back({"url_raw_ip",
                     in->raw_ip_url != 0 ? dl::kUrlRawIp : 0.0,
                     dl::Direction::Spam});
  // Brand-independent callback phishing (TASK-440): billing language, a number to
  // call, and no link at all, from a sender the receiver could NOT verify.
  //
  // The auth condition is measured, not assumed, and it was added after the
  // first version of this offset had been written without it. Over 3,621
  // invoice-ish messages from the founder's four real mailboxes:
  //
  //   billing + phone + no_link                 15 false positives (0.4%)
  //   billing + phone + no_link + no dmarc=pass  0 false positives, same 203 hits
  //
  // A real invoice from a small biller does have a phone number and often no
  // portal link; what it also has, most of the time, is an authenticated sender.
  // The auth condition costs nothing measurable on the spam side and removes
  // every false positive, so it is required rather than preferred.
  //
  // KNOWN BLIND SPOT, stated because it is real: a lure sent from a COMPROMISED
  // domain that authenticates (the TASK-439 family does exactly this) passes the
  // auth test and is not reached here. That variant needs the model, not this.
  //
  // Corroborating magnitude on purpose: 0 of 3,621 bounds the true rate near
  // 0.08% rather than at zero, and an invoice is the most damaging single
  // message to junk. It can carry a message the model already doubts over the
  // gate and can never junk one the model likes. See callback_shape.h.
  offsets.push_back({"callback_shape",
                     (in->callback_shape != 0 && in->dmarc_pass == 0)
                         ? dl::kCallbackShape : 0.0,
                     dl::Direction::Spam});

  // The bank-advisor scam's second message (TASK-460): the body tells the
  // recipient not to check with their bank, from a sender the receiver could not
  // verify.
  //
  // NO AUTH CONDITION HERE, deliberately, and the callback shape's is the
  // instructive contrast rather than the precedent.
  //
  // This offset was first written with `dmarc_pass == 0` copied from the
  // callback shape, justified as "free: it costs zero recall". That claim could
  // not have been false: NONE of the nine authored variants carries an
  // Authentication-Results header, so no_dmarc was trivially true for every one
  // of them. The panel structurally could not disconfirm the condition it was
  // being used to justify.
  //
  // The condition is worse than unjustified, it is an evasion. DMARC proves the
  // sender controls the domain they sent from; it says nothing about whether
  // they are the recipient's bank. A scammer who registers
  // banque-verification-client.net and publishes SPF/DKIM/DMARC for it -- an
  // afternoon's work -- would have suppressed the ONLY signal that reaches this
  // genre, returning a 0.0268 message to the inbox.
  //
  // The callback shape's condition is different in kind: it was MEASURED to
  // remove 15 real false positives from 3,621 invoices, because a real invoice
  // usually authenticates. Here there were no false positives to remove, on any
  // panel, with or without it. So it buys nothing and costs the whole signal.
  //
  // Unlike the callback shape this magnitude CAN carry a message the model likes
  // over the gate, which is deliberate and is the only reason the signal exists
  // (the genre's model floor is 0.0268). What it may not do is authorize a
  // bounce: the id is absent from the authoritative allowlist below, on purpose.
  offsets.push_back({"no_contact_instruction",
                     in->no_contact_instruction != 0
                         ? dl::kNoContactInstruction : 0.0,
                     dl::Direction::Spam});
  // GTUBE (TASK-391): an operator proving the filter is live. Condemn-capable so
  // the answer does not depend on what the model thinks of the surrounding text.
  offsets.push_back({"gtube_test",
                     in->gtube_test != 0 ? dl::kGtubeTest : 0.0,
                     dl::Direction::Spam});
  // Connecting IP in a Spamhaus DROP netblock (TASK-113): unlike every other
  // offset here this is not derived from the message at all — the caller observed
  // it about the TCP peer, which is why it is condemn-capable at 0.99. Measured
  // 3.25% of spam / 0 of 3,994 real ham; see the block in decision_layer.h,
  // including why a Received-header IP must never be routed into this field.
  offsets.push_back({"connect_ip_drop",
                     in->connect_ip_blocked != 0 ? dl::kOriginIpDrop : 0.0,
                     dl::Direction::Spam});
  // Same DROP evidence recovered from the Received chain behind a trusted relay
  // (TASK-387). Weaker because its provenance depends on the operator's trusted-
  // relay list rather than on the socket; it corroborates, never solo-condemns.
  // Suppressed when the observed-IP version already fired, so one message cannot
  // collect the same evidence twice.
  offsets.push_back({"header_ip_drop",
                     (in->header_ip_blocked != 0 && in->connect_ip_blocked == 0)
                         ? dl::kOriginIpDropHeader : 0.0,
                     dl::Direction::Spam});
  // TASK-347 deterministic attachment experiment. Only the strongest tier is
  // emitted, so several weak facts cannot add into a condemn. Default off: no
  // shipping caller changes until the locked attachment panel passes. The
  // strong deception tier may move an opted-in message to Junk, but the
  // authoritative-offset whitelist below deliberately excludes it, so it
  // cannot authorize an SMTP reject/bounce.
  if (in->attachment_risk_enabled != 0) {
    if (in->attachment_disguised_executable != 0) {
      offsets.push_back({"attachment_disguised_executable",
                         dl::kAttachmentDisguisedExecutableExperimental,
                         dl::Direction::Spam});
    } else if (in->archive_disguised_executable != 0) {
      offsets.push_back({"archive_disguised_executable",
                         dl::kAttachmentDisguisedExecutableExperimental,
                         dl::Direction::Spam});
    } else if (in->attachment_dangerous_type != 0) {
      offsets.push_back({"attachment_dangerous_type",
                         dl::kAttachmentDangerousTypeExperimental,
                         dl::Direction::Spam});
    } else if (in->archive_dangerous_type != 0) {
      offsets.push_back({"archive_dangerous_type",
                         dl::kAttachmentDangerousTypeExperimental,
                         dl::Direction::Spam});
    }
  }
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
  // Authenticated KB-brand rescue (TASK-337/334): the receiving MTA verified
  // dmarc=pass for a From org-domain the curated KB knows as a brand's own
  // sending domain. Strong (0.90) and NOT ceiling-gated, unlike the -0.15
  // reputation nudge above: the transactional FPs it rescues sit at 0.97-0.999.
  // Safe because the precondition is receiver-verified DMARC as the brand
  // itself; measured 203 FP rescued / 0 caught spam lost on real AR-stamped
  // mail. Guarded by the throwaway/free-host signer tells so a corroborated
  // phish shape never gets the rescue on top of its condemn.
  const bool kb_rescue_blocked =
      in->signer_throwaway != 0 || dl::is_free_host_signed(signer);
  offsets.push_back({"kb_brand_dmarc",
                     (in->kb_brand_dmarc_pass != 0 && !kb_rescue_blocked)
                         ? dl::kKbBrandDmarcPass : 0.0,
                     dl::Direction::Ham});

  dl::Profile profile = dl::Profile::Standard;
  if (in->profile == SPAM_ENGINE_PROFILE_CAUTIOUS) { profile = dl::Profile::Cautious;
  } else if (in->profile == SPAM_ENGINE_PROFILE_LEARNING) { profile = dl::Profile::Learning;
}

  const std::string ml_label = in->ml_label != nullptr ? in->ml_label : "";
  const dl::Verdict v = dl::fold(scores, offsets,
                                 dl::threshold_for_profile(profile),
                                 ml_label, in->ml_confidence,
                                 in->spam_side_knot);

  std::strncpy(out->label, v.label.c_str(), sizeof(out->label) - 1);
  out->label[sizeof(out->label) - 1] = '\0';
  out->confidence = v.confidence;
  out->adjusted_spam_side = v.adjusted_spam_side;
  out->calibrated_spam_side = v.calibrated_spam_side;
  out->train_ml = v.train_ml ? 1 : 0;
  // condemn_offset_fired is the "independent strong signal" a consumer (the
  // milter) requires before a destructive REJECT/bounce, so it must reflect only
  // AUTHORITATIVE spam-ward offsets, ones whose magnitude alone can carry a
  // zero-neural message over the standard gate (free-host / throwaway / display-
  // impersonation / DROP-listed connecting IP). The 0.30 raw-IP corroborator
  // (TASK-257) fires but
  // deliberately never solo-condemns, so it must NOT authorize a bounce on its
  // own (a legit bare-IP link the model FPs would otherwise get bounced).
  // The fold's own account of what fired, for consumers that must record WHY a
  // verdict happened (TASK-388). Built here, from the Verdict, so it can never
  // disagree with the decision it explains.
  std::string fired;
  for (const auto& f : v.fired) {
    if (!fired.empty()) { fired += ',';
}
    fired += f.classifier_id;
    if (!f.flipped_label.empty()) { fired += '!';
}
  }
  std::strncpy(out->fired_offsets, fired.c_str(), sizeof(out->fired_offsets) - 1);
  out->fired_offsets[sizeof(out->fired_offsets) - 1] = '\0';

  // Which offsets may authorize a destructive REJECT/bounce. This was
  // `magnitude >= kThresholdStandard` until the TASK-347 attachment experiment
  // needed an offset that is strong enough to junk (0.99) and deliberately not
  // strong enough to bounce. Magnitude can no longer express that, so the
  // authority is an explicit named list: ADD A NEW OFFSET HERE ON PURPOSE, and
  // never assume a large constant grants it. Locked by
  // test_authoritative_condemn_allowlist in spam_engine_c_api_tests.cpp.
  out->condemn_offset_fired = 0;
  for (const auto& f : v.fired) {
    const bool authoritative =
        f.classifier_id == "sender_auth" ||
        f.classifier_id == "display_impersonation" ||
        f.classifier_id == "gtube_test" ||
        f.classifier_id == "connect_ip_drop";
    if (f.direction == dl::Direction::Spam && authoritative) {
      out->condemn_offset_fired = 1;
      break;
    }
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
  if (out != nullptr) { std::memset(out, 0, sizeof(*out));
}
  if (handle == nullptr || out == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }

  try {
    std::scoped_lock const lock(handle->mutex);

    if (raw_email == nullptr || raw_email_len == 0) {
      return set_error_locked(
          handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "raw_email cannot be empty");
    }
    if (!is_valid_mode(mode)) {
      return set_error_locked(handle, SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
                              R"(mode must be "ensemble", "neural", or "ftrl")");
    }
    clear_error_locked(handle);

    // Stages 1+2(+2.5): FTRL P(spam) → neural → ensemble blend, one parse.
    // Public v0 does not pay the attachment/ZIP parse unless this experiment's
    // caller flag is explicitly on; an attachment-context artifact opts itself
    // in inside SpamEngine::classify_rfc822.
    const bool attachment_risk_enabled =
        caller_state != nullptr && caller_state->attachment_risk_enabled != 0;
    const auto r = handle->engine.classify_rfc822(
        std::string(raw_email, raw_email_len),
        (sender_name != nullptr) ? sender_name : "",
        (sender_email != nullptr) ? sender_email : "",
        spam_engine::ClassifyOptions{mode}, attachment_risk_enabled);

    out->ftrl_score = r.ftrl_score;
    out->neural_scores.gibberish = r.scores.gibberish;
    out->neural_scores.marketing = r.scores.marketing;
    out->neural_scores.regular = r.scores.regular;
    // scores.spam is the ensemble-blended spam side; neural_spam is the pre-blend
    // neural value (== scores.spam when FTRL didn't contribute).
    out->neural_scores.spam = (r.neural_spam >= 0.0F) ? r.neural_spam : r.scores.spam;
    out->ensemble_spam = r.scores.spam;
    std::strncpy(out->decided_by, r.decided_by.c_str(), sizeof(out->decided_by) - 1);
    out->decided_by[sizeof(out->decided_by) - 1] = '\0';
    fill_thread_features(r.thread_features, &out->signals.thread);
    fill_auth_features(r.auth_features, &out->signals.auth);
    fill_url_features(r.url_features, &out->signals.url);
    fill_body_features(r.body_features, &out->signals.body);
    fill_attachment_features(r.attachment_features, &out->signals.attachment);

    // Stage 3: fold the structural offsets onto the ENSEMBLE spam side. Reuse
    // spam_engine_decide so the fold can never drift from the standalone path.
    // Fold uses the engine's scores as-is: gibberish/marketing/regular are raw
    // neural and scores.spam is already the ensemble-blended side (combine_scores).
    const spam_engine_scores_t scores = {r.scores.gibberish, r.scores.marketing,
                                         r.scores.regular, r.scores.spam};
    spam_engine_decision_input_t din{};
    spam_engine_decision_input_from_signals(&din, &scores, &out->signals);
    // The loaded artifact's own scale. Undeclared (0) is the identity, so
    // public-v0 folds exactly as it always has. Filled here rather than left to
    // the caller because classify_full is the path that KNOWS which model
    // produced these scores; a standalone spam_engine_decide caller has to copy
    // it from spam_engine_model_info itself.
    din.spam_side_knot = handle->engine.model_info().spam_side_calibration_knot;
    if (caller_state != nullptr) {
      din.phase2_match = caller_state->phase2_match;
      din.exact_send_count = caller_state->exact_send_count;
      din.domain_send_count = caller_state->domain_send_count;
      din.profile = caller_state->profile;
      din.connect_ip_blocked = caller_state->connect_ip_blocked;
      din.attachment_risk_enabled = caller_state->attachment_risk_enabled;
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
