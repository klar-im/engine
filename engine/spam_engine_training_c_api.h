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
// Uses the same RFC822 preprocessing + canonical wrapping path as
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

// Train on all queued samples and clear the queue.
// out_avg_loss and out_trained_count can be NULL if not needed.
spam_engine_status_t spam_engine_train_incremental(
    spam_engine_handle_t* handle,
    float* out_avg_loss,
    size_t* out_trained_count);

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
