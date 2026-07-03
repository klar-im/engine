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
  // The five answer fields, disambiguated (TASK-219):
  //  class_name   — the engine's own spam/regular call from `scores`.
  //  confidence   — confidence in THAT call (e.g. 1 - P(spam)), not scores[class].
  //  scores       — 4-class probabilities. In "ensemble" mode `scores.spam` is
  //                 the ESCALATE-ONLY spam side max(neural, w*ftrl+(1-w)*neural)
  //                 — i.e. what the structural decision layer should fold — while
  //                 gibberish/marketing/regular stay raw neural. It equals raw
  //                 neural unless FTRL escalated. `neural_spam` keeps the
  //                 pre-blend neural spam so each stage stays inspectable.
  //  decided_by   — "neural" | "ftrl" | "ftrl+neural" (which scorers ran).
  //  ftrl_score   — FTRL P(spam), or -1 when FTRL was not consulted/cold.
  std::string class_name;
  float confidence = 0.0f;
  ClassScores scores;               // 4-class; scores.spam is ensemble-blended (see above)
  std::string decided_by = "neural"; // "ftrl", "neural", or "ftrl+neural"
  float ftrl_score = -1.0f;        // FTRL P(spam), -1 = not available
  float neural_spam = -1.0f;       // raw neural P(spam) before the ensemble blend
  // Structural features from classify_rfc822's parse (TASK-173). Empty for the
  // text-only classify() path. Stamped after the decision so all early-return
  // paths carry them; surfaced through the C ABI's optional out-params so the
  // Swift decision layer reads them off this result instead of re-parsing.
  ExtractedThreadFeatures thread_features;
  ExtractedAuthFeatures   auth_features;
};

/// Which scorers produce the verdict. REQUIRED — there is no silent default
/// (TASK-219: a hidden "auto" mode let a cold FTRL bypass the neural head).
///   "ensemble" — run neural AND fold FTRL P(spam) into the spam side
///                ESCALATE-ONLY: scores.spam' = max(neural, w*ftrl+(1-w)*neural).
///                FTRL can only RAISE the spam side (catch personalized spam),
///                never exonerate. The recommended production mode. FTRL only
///                contributes once it is warm (total_learns >= ftrl_min_learns)
///                AND more suspicious than neural; otherwise the verdict is pure
///                neural.
///   "neural"   — neural head only; FTRL is never consulted (ftrl_score = -1).
///   "ftrl"     — FTRL P(spam) only; neural is skipped. Diagnostic / A-B use.
/// Unknown or empty mode throws std::invalid_argument.
struct ClassifyOptions {
  std::string mode;  // no default — callers MUST choose (see C API `mode` param)
};

struct EngineConfig {
  std::string model_path = "./model";
  float learning_rate = 0.0001f;  // Balance: learns well + prevents forgetting
  float l2_lambda = 0.1f;         // Moderate L2 to prevent forgetting on corrections
  float max_grad_norm = 1.0f;     // Gradient clipping threshold (global L2 norm)
  float max_drift = 0.015f;       // Trust-region radius around frozen origin weights
                                  // (‖w-w0‖ <= max_drift*‖w0‖). Stops a one-sided
                                  // correction stream from collapsing a class (TASK-193).
  // FTRL statistical pre-filter (ENSEMBLE, not a bypass — TASK-219).
  std::string ftrl_path = "";          // Path to FTRL weights file. Empty = start fresh.
  // Weight of FTRL P(spam) in the ESCALATE-ONLY "ensemble" fold of the spam side:
  //   scores.spam' = max(neural.spam, w*ftrl + (1-w)*neural.spam)
  // The blend is applied only when it RAISES the spam side, so FTRL can add
  // suspicion but never exonerate. FTRL trains only on the founder's small,
  // spam-poor personal mbox, so a cold ftrl≈0 is absence-of-evidence, not a ham
  // vote — a SYMMETRIC blend at this weight dragged confident-neural spam below
  // the condemn threshold (0/5 recall on the blatant slice, measure_escalate_only.py
  // 2026-06-25). Escalate-only keeps neural's recall while still letting a warm
  // FTRL catch personalized spam. Revisit the weight only with new data.
  float ftrl_ensemble_weight = 0.2f;
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

  // `options.mode` is REQUIRED (ensemble|neural|ftrl) — no silent default.
  ClassificationResult classify(
      const std::string& text,
      const std::string& sender_name,
      const std::string& sender_email,
      const ClassifyOptions& options);

  ClassificationResult classify_rfc822(
      const std::string& raw_rfc822,
      const std::string& sender_name,
      const std::string& sender_email,
      const ClassifyOptions& options);

  ClassificationResult classify_transcript(
      const std::vector<TranscriptMessage>& transcript,
      const CustomerInfo& customer,
      const ClassifyOptions& options);

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
  // Canonical int->name mapping as a static string literal (single source of
  // truth for label_to_string and the C API's spam_engine_label_name).
  static const char* label_name(int label);

 private:
  class Impl;

  ClassificationResult decision_from_scores(const ClassScores& scores) const;
  // Fold FTRL P(spam) + neural scores into one pre-structural verdict per `mode`
  // (ensemble|neural|ftrl). `ftrl_score` < 0 means FTRL unavailable/cold. The
  // single place the bypass-vs-ensemble policy lives, shared by every classify
  // entry point so they cannot drift.
  ClassificationResult combine_scores(
      const ClassScores& neural, float ftrl_score, const std::string& mode) const;
  void ensure_loaded() const;

  EngineConfig config_;
  std::unique_ptr<Impl> impl_;
  bool loaded_ = false;
};

}  // namespace spam_engine
