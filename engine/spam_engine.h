#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "email_preprocessor.h"  // ExtractedThreadFeatures / ExtractedAuthFeatures

namespace spam_engine {

struct TranscriptMessage {
  std::string from_type;
  std::string text;
  std::string origin;
};

// Sender / context metadata that gets serialized into the head's input
// `Customer Info:` block. Today carries name + email + a single derived
// signal (replyto_differs); see engine/PARITY_PLAN.md for the next batch
// of signals (in_address_book, prior_corrections, envelope_mismatch, ...).
//
// New fields are wire-format-additive: they're emitted only when the
// signal is present, so old training distributions stay valid until the
// next retrain teaches the head the new tokens.
struct CustomerInfo {
  std::string name;
  std::string email;
  // True if the message has a Reply-To header that differs from the From
  // header. Common spam pattern (legitimate senders rarely need to differ).
  // Computed inside email_preprocessor::preprocess_rfc822.
  bool replyto_differs = false;
};

// Opaque wrapper around a string in the canonical "head input" shape — i.e.,
// what `classify_rfc822` produces and what the classifier head was trained
// against. Holding one is a structural guarantee that you went through the
// canonical wrapping pipeline.
//
// Cannot be constructed from arbitrary `std::string`. The only constructor
// is the `build_input_text` friend function below, which produces the
// production shape by construction. Anyone passing raw text to `embed()`
// gets a compile error — the bug class "training and inference fed the
// head different distributions" becomes structurally unrepresentable.
//
// See engine/PARITY_PLAN.md for the design rationale.
class CalibratedInputText {
 public:
  CalibratedInputText() = delete;
  const std::string& str() const noexcept { return text_; }
  size_t size() const noexcept { return text_.size(); }

 private:
  explicit CalibratedInputText(std::string t) : text_(std::move(t)) {}

  friend CalibratedInputText build_input_text(
      const std::vector<TranscriptMessage>& transcript,
      const CustomerInfo& customer);

  std::string text_;
};

// Canonical wrapper: produces the head-shaped string from a transcript +
// sender metadata. The same function is used by every code path that wants
// to embed text — runtime classification, runtime training, retraining,
// tests, and demos.
CalibratedInputText build_input_text(
    const std::vector<TranscriptMessage>& transcript,
    const CustomerInfo& customer);

// Parse a "Foo Bar <foo@bar.com>" or bare "foo@bar.com" string into
// (display_name, email_address). Used by every code path that needs to
// reconcile a caller-supplied CustomerInfo with the From header GMime
// parsed out of the raw RFC822 bytes. Public so the C ABI doesn't have to
// re-inline the same logic.
std::pair<std::string, std::string> parse_from_header(const std::string& from);

// Apply preprocessor-derived signals (currently `replyto_differs` and the
// From-header sender fallback) to a caller-supplied CustomerInfo, in
// place. Caller-provided name+email always wins over the From header;
// preprocessor-derived signals always override caller-supplied values for
// fields the caller couldn't have known (replyto_differs).
//
// This is the single source of truth for "merge what the caller passed
// with what GMime found" — used by classify_rfc822, train_rfc822, and
// the C ABI's spam_engine_embed_rfc822.
struct PreprocessedEmail;  // forward declared in email_preprocessor.h
void apply_preprocessed_to_customer(
    CustomerInfo& customer,
    const PreprocessedEmail& preprocessed);

struct ClassScores {
  float gibberish = 0.0f;
  float marketing = 0.0f;
  float regular = 0.0f;
  float spam = 0.0f;
};

struct ClassificationResult {
  std::string class_name;
  float confidence = 0.0f;
  ClassScores scores;               // Neural model scores (zero if neural was skipped)
  std::string decided_by = "neural"; // Which classifier decided: "ftrl", "neural", "ftrl+neural"
  float ftrl_score = -1.0f;        // FTRL P(spam), -1 = not available
  // Structural features from classify_rfc822's parse (TASK-173). Empty for the
  // text-only classify() path. Stamped after the decision so all early-return
  // paths carry them; surfaced through the C ABI's optional out-params so the
  // Swift decision layer reads them off this result instead of re-parsing.
  ExtractedThreadFeatures thread_features;
  ExtractedAuthFeatures   auth_features;
};

/// Hint to force a specific classifier path. Extensible via string.
/// "auto" (default), "ftrl", or "neural".
struct ClassifyOptions {
  std::string mode = "auto";
};

struct EngineConfig {
  std::string model_path = "./model";
  float learning_rate = 0.0001f;  // Balance: learns well + prevents forgetting
  float l2_lambda = 0.1f;         // Moderate L2 to prevent forgetting on corrections
  float max_grad_norm = 1.0f;     // Gradient clipping threshold (global L2 norm)
  float max_drift = 0.015f;       // Trust-region radius around frozen origin weights
                                  // (‖w-w0‖ <= max_drift*‖w0‖). Stops a one-sided
                                  // correction stream from collapsing a class (TASK-193).
  // FTRL statistical pre-filter
  std::string ftrl_path = "";          // Path to FTRL weights file. Empty = start fresh.
  float ftrl_spam_threshold = 0.95f;   // Above this: skip neural, return spam
  float ftrl_ham_threshold = 0.05f;    // Below this: skip neural, return ham
  uint32_t ftrl_min_learns = 10;       // FTRL only contributes once total_learns >= this
                                        // (cold-start guard against a freshly-loaded,
                                        // not-yet-warm FTRL routing weird verdicts).
  // Path to GGUF encoder. Empty = model_path + "/gguf/encoder-q4_k_m.gguf".
  std::string gguf_model_path = "";
  // Hard cap on encoder input length (tokens incl. BOS/EOS). 128 covers
  // the discriminative head of the message (subject + first ~3 sentences);
  // see docs/FAST.md "Encoder input cap" for the FPR/latency tradeoff.
  //
  // External override is via the env var SPAM_ENGINE_MAX_TOKENS only — the
  // C ABI doesn't grow a parameter for this. SpamEngine::load logs to stderr
  // whenever the env var fires so accidental shell leakage is visible.
  // Validated against [GgmlEncoder::kMinMaxTokens, model->n_ctx_train] —
  // out-of-range values throw at load().
  int encoder_max_tokens = 128;
};

// Stable API for embedding, classification, feedback training, and save.
class SpamEngine {
 public:
  SpamEngine();
  explicit SpamEngine(const EngineConfig& config);
  ~SpamEngine();

  SpamEngine(SpamEngine&&) noexcept;
  SpamEngine& operator=(SpamEngine&&) noexcept;

  SpamEngine(const SpamEngine&) = delete;
  SpamEngine& operator=(const SpamEngine&) = delete;

  void load(const EngineConfig& config);
  void unload() noexcept;
  bool is_loaded() const noexcept;

  // Embedding dimension of the loaded encoder (0 if not loaded). Fixed per
  // model, so C-ABI callers size embed() output buffers from this once.
  int n_embd() const noexcept;

  ClassificationResult classify(
      const std::string& text,
      const std::string& sender_name = "",
      const std::string& sender_email = "",
      const ClassifyOptions& options = {});

  ClassificationResult classify_rfc822(
      const std::string& raw_rfc822,
      const std::string& sender_name = "",
      const std::string& sender_email = "",
      const ClassifyOptions& options = {});

  ClassificationResult classify_transcript(
      const std::vector<TranscriptMessage>& transcript,
      const CustomerInfo& customer = {},
      const ClassifyOptions& options = {});

  // Encoder API. The string types here are CalibratedInputText, NOT
  // std::string — the compiler enforces that anything fed to the head
  // went through `build_input_text` first (the only constructor). See
  // engine/PARITY_PLAN.md for the rationale.
  std::vector<float> embed(const CalibratedInputText& input);
  std::vector<std::vector<float>> embed_batch(
      const std::vector<CalibratedInputText>& inputs);
  ClassScores classify_embedding(
      const std::vector<float>& embedding,
      bool cache_for_training = false);

  float train(const CalibratedInputText& input, int correct_label);
  float train_rfc822(const std::string& raw_rfc822,
                     const CustomerInfo& customer,
                     int correct_label);
  float train_embedding(const std::vector<float>& embedding, int correct_label);

  void save(const std::string& model_path = "");

  // Flywheel (TASK-134): the PORTABLE, state-independent contribution bag for an
  // RFC822 message — `{ bucket -> signed ln(1+count) }`, the same derived
  // representation the FTRL head trains on, bucketed identically on every device.
  // Built from the same preprocessed text as train_rfc822 (plain/html parts
  // merged). `hash_key != 0` keys the buckets (HMAC-style). This is the ONLY
  // thing the flywheel ever uploads — hash buckets + weights, never raw text.
  // Inert: it just computes a value; nothing in the engine transmits it.
  std::map<uint32_t, float> extract_contribution(
      const std::string& raw_rfc822,
      const std::string& sender_name = "",
      const std::string& sender_email = "",
      uint64_t hash_key = 0) const;

  // The PII-scrubbed body text that extract_contribution hashes — exposed so the
  // scrub can be audited at scale (offline PII harness) and
  // unit-tested end-to-end. GMime has already dropped attachments and split real
  // headers; this is the representative body part with quoted/forwarded
  // recipient-routing headers redacted and inline `data:` URIs stripped. The
  // contribution bag is computed from exactly this text, so anything absent here
  // is absent from the upload.
  std::string scrub_contribution(const std::string& raw_rfc822) const;

  void set_learning_rate(float learning_rate);
  float learning_rate() const;

  static int label_from_string(const std::string& label);
  static std::string label_to_string(int label);

 private:
  class Impl;

  ClassificationResult decision_from_scores(const ClassScores& scores) const;
  void ensure_loaded() const;

  EngineConfig config_;
  std::unique_ptr<Impl> impl_;
  bool loaded_ = false;
};

}  // namespace spam_engine
