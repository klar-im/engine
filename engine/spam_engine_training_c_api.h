#pragma once

#include "spam_engine_c_api.h"

#ifdef __cplusplus
extern "C" {
#endif

// Training ABI (premium feature).
// Requires a loaded engine handle from the base ABI.

// Train on plain text with a correct label.
// Labels: 0=gibberish, 1=marketing, 2=regular, 3=spam
// Returns the training loss value in out_loss (can be NULL if not needed).
spam_engine_status_t spam_engine_train(
    spam_engine_handle_t* handle,
    const char* text,
    int correct_label,
    float* out_loss);

// Train on raw RFC822 email data with a correct label.
// Labels: 0=gibberish, 1=marketing, 2=regular, 3=spam
// Returns the training loss value in out_loss (can be NULL if not needed).
//
// sender_name / sender_email: caller-supplied sender metadata (matches the
//   classify_rfc822 parameters); pass NULL or empty to fall back to the
//   parsed From header. CRITICAL for parity: if you classify with one
//   sender shape and train with another, the head's calibration drifts.
//   See engine/PARITY_PLAN.md.
//
// Uses the same RFC822 preprocessing + model-declared calibration path as
// classify_rfc822 — bit-for-bit identical, enforced at the C++ type
// level via CalibratedInputText.
spam_engine_status_t spam_engine_train_rfc822(
    spam_engine_handle_t* handle,
    const char* raw_email,
    size_t raw_email_len,
    const char* sender_name,
    const char* sender_email,
    int correct_label,
    float* out_loss);

// Queue one RFC822 sample for later incremental training.
// Labels: 0=gibberish, 1=marketing, 2=regular, 3=spam
// sender_name / sender_email semantics match spam_engine_train_rfc822.
spam_engine_status_t spam_engine_add_training_sample(
    spam_engine_handle_t* handle,
    const char* raw_email,
    size_t raw_email_len,
    const char* sender_name,
    const char* sender_email,
    int correct_label);

// Train queued samples. On success the queue is empty. If one sample fails,
// already-applied prefix updates are reported in out_trained_count, the failing
// sample is dropped from the native queue, and the untried tail remains queued
// for the next call. out_avg_loss and out_trained_count can be NULL.
spam_engine_status_t spam_engine_train_incremental(
    spam_engine_handle_t* handle,
    float* out_avg_loss,
    size_t* out_trained_count);

// Which online learner receives a queued correction.
//
// FTRL is folded escalate-only at classification time, so FTRL_ONLY can learn
// personalized spam evidence but can never lower the frozen neural spam side.
// HEAD_AND_FTRL preserves the existing Klar Plus behavior.
typedef enum spam_engine_training_mode {
  SPAM_ENGINE_TRAIN_HEAD_AND_FTRL = 0,
  SPAM_ENGINE_TRAIN_FTRL_ONLY = 1,
} spam_engine_training_mode_t;

// Train queued samples with an explicit learner role. FTRL_ONLY returns an
// average loss of 0 because the FTRL update has no neural cross-entropy loss.
// Queue/error semantics match spam_engine_train_incremental.
spam_engine_status_t spam_engine_train_incremental_mode(
    spam_engine_handle_t* handle,
    spam_engine_training_mode_t mode,
    float* out_avg_loss,
    size_t* out_trained_count);

// Trust-region telemetry (doc-26). Either out-param may be NULL.
//   out_saturation — ‖w-w0‖ as a fraction of the max_drift budget, maxed over
//                    the head's four tensors. 1.0 = pinned to the boundary, so
//                    further corrections displace earlier ones rather than
//                    adding to them, and the learning rate stops mattering.
//   out_relative_drift — the same distance without the budget in the
//                    denominator (‖w-w0‖/‖w0‖).
// Both read 0 before any training. Diagnostic only; classification ignores them.
spam_engine_status_t spam_engine_head_drift(
    spam_engine_handle_t* handle,
    float* out_saturation,
    float* out_relative_drift);

// Number of Adam updates applied in this loaded training session. Each
// successfully applied RFC822 correction contributes one update; distinct
// plain and HTML bodies form one averaged batch.
spam_engine_status_t spam_engine_head_optimizer_steps(
    spam_engine_handle_t* handle,
    size_t* out_steps);

// Save the trained model weights.
// If model_path is NULL or empty, saves to the original load path.
spam_engine_status_t spam_engine_save(
    spam_engine_handle_t* handle,
    const char* model_path);

// Alias for spam_engine_save, keeps naming aligned with training workflow.
spam_engine_status_t spam_engine_save_model(
    spam_engine_handle_t* handle,
    const char* model_path);

// Convert label string to int.
// Returns -1 if unknown.
int spam_engine_label_from_string(const char* label);

// Convert label int to string.
// Returns NULL if unknown.
const char* spam_engine_label_to_string(int label);

#ifdef __cplusplus
}
#endif
