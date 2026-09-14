#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "email_preprocessor.h"  // ExtractedThreadFeatures / ExtractedAuthFeatures

class TrainableClassifierHead;

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

enum class ModelInputFormat : std::uint8_t {
  kLegacyWrapped,
  kRaw,
};

// Opaque wrapper around a string in the model-declared head input shape.
// Holding one guarantees that a caller chose raw or legacy-wrapped explicitly.
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
  [[nodiscard]] const std::string& str() const noexcept { return text_; }
  [[nodiscard]] size_t size() const noexcept { return text_.size(); }

 private:
  explicit CalibratedInputText(std::string t) : text_(std::move(t)) {}

  friend CalibratedInputText build_input_text(
      const std::vector<TranscriptMessage>& transcript,
      const CustomerInfo& customer,
      ModelInputFormat format);

  std::string text_;
};

// Explicit representation builder. Production callers use
// SpamEngine::calibrate_input(), which selects from classifier_config.json.
CalibratedInputText build_input_text(
    const std::vector<TranscriptMessage>& transcript,
    const CustomerInfo& customer,
    ModelInputFormat format);

// Parse a "Foo Bar <foo@bar.com>" or bare "foo@bar.com" string into
// (display_name, email_address). Used by every code path that needs to
// reconcile a caller-supplied CustomerInfo with the From header GMime
// parsed out of the raw RFC822 bytes. Public so the C ABI doesn't have to
// re-inline the same logic.
std::pair<std::string, std::string> parse_from_header(const std::string& from);

// The bare gguf filename an artifact declares in classifier_config.json
// (`gguf_encoder_file`), or "encoder-q4_k_m.gguf" when it declares none.
// Public so the C ABI and tests read the same declaration the engine loads.
std::string default_gguf_encoder_file(const std::string& model_path);

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
  float gibberish = 0.0F;
  float marketing = 0.0F;
  float regular = 0.0F;
  float spam = 0.0F;
};

struct ClassificationResult {
  // The five answer fields, disambiguated (TASK-219):
  //  class_name   — the engine's own spam/regular call from `scores`.
  //  confidence   — confidence in THAT call (e.g. 1 - P(spam)), not scores[class].
  //  scores       — the stable four-slot semantic envelope
  //                 {gibberish, marketing, regular, spam}. A model may have
  //                 fewer physical rows; unavailable semantics are zero. In
  //                 "ensemble" mode `scores.spam` is
  //                 the ESCALATE-ONLY spam side max(neural, w*ftrl+(1-w)*neural)
  //                 — i.e. what the structural decision layer should fold — while
  //                 gibberish/marketing/regular stay raw neural. It equals raw
  //                 neural unless FTRL escalated. `neural_spam` keeps the
  //                 pre-blend neural spam so each stage stays inspectable.
  //  decided_by   — "neural" | "ftrl" | "ftrl+neural" (which scorers ran).
  //  ftrl_score   — FTRL P(spam), or -1 when FTRL was not consulted/cold.
  std::string class_name;
  float confidence = 0.0F;
  ClassScores scores;               // stable semantic envelope; see above
  std::string decided_by = "neural"; // "ftrl", "neural", or "ftrl+neural"
  float ftrl_score = -1.0F;        // FTRL P(spam), -1 = not available
  float neural_spam = -1.0F;       // raw neural P(spam) before the ensemble blend
  // Structural features from classify_rfc822's parse (TASK-173). Empty for the
  // text-only classify() path. Stamped after the decision so all early-return
  // paths carry them; surfaced through the C ABI's optional out-params so the
  // Swift decision layer reads them off this result instead of re-parsing.
  ExtractedThreadFeatures thread_features;
  ExtractedAuthFeatures   auth_features;
  ExtractedUrlFeatures    url_features;
  ExtractedBodyFeatures   body_features;
  ExtractedAttachmentFeatures attachment_features;
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
  float learning_rate = 0.0001F;  // Balance: learns well + prevents forgetting
  float l2_lambda = 0.1F;         // Moderate L2 to prevent forgetting on corrections
  float max_grad_norm = 1.0F;     // Gradient clipping threshold (global L2 norm)
  // Trust-region radius around the frozen origin weights, measured in Adam
  // optimizer updates: the head may accumulate at most this many steps' worth of
  // movement (‖w-w0‖ <= max_drift_steps * learning_rate * sqrt(n) per tensor).
  // One RFC822 correction issues one averaged head update even when distinct
  // plain and HTML bodies are both represented.
  // Stops a one-sided correction stream from collapsing a class (TASK-193).
  //
  // This replaces `max_drift`, a fraction of ‖w0‖, which was the wrong unit:
  // ‖w0‖ has no fixed relationship to Adam's step norm, so the old 0.006 came
  // out as a budget of 1.2 steps on the weight matrices and 0.09 steps on the
  // biases — the head could not retain even a single correction, which is why
  // personalization measured +0.000 for two model generations (doc-26,
  // TASK-417). See trainable_classifier.h for the measured table.
  //
  // The origin is persisted in personalized snapshots, so reloads do not reset
  // the lifetime bound.
  //
  // STRESS-PANEL DIAGNOSTIC, regenerated 2026-08-21 on the shipping checkpoint
  // (21bcd2ff, public-v0) via `make engine/drift-sweep`. Base spam/ham recall on
  // the 200-message SpamAssassin panel is 0.89/0.95.
  //
  //     steps   skew30 spam   skew90 spam   balanced acc   balanced ham
  //      0.09       0.89          0.89          0.92           0.95
  //      1.0        0.84          0.84          0.935          0.94
  //      3.0        0.68          0.75          0.94           0.94   <- SHIPPED
  //      10         0.53          0.66          0.94           0.94
  //      30         0.46          0.41          0.94           0.94
  //      100        0.46          0.41          0.94           0.94
  //      off        0.46          0.41          0.94           0.94
  //
  // At 3.0 the 30-deep synthetic stream costs 21pp of spam recall and fails the
  // class-skew qualification threshold. That is not evidence that the trust
  // region stopped bounding parameter drift: the corpus-free
  // head_trust_region_bounds_a_long_stream test covers that mechanism.
  //
  // This panel does NOT select the production radius. The 3.0 value is the
  // predeclared candidate from doc-27; the source/mailbox/time-grouped sweep in
  // model-lab/qualification/drift-sweep records the product trade: it stays
  // inside its 2pp untouched-spam budget and fixes 45/77 held-out false
  // positives, while 1.0 fixes 19/77. Any change must be selected on tuning
  // folds and clear untouched confirmation panels once. TASK-441 records the
  // unresolved disagreement between the two panels.
  float max_drift_steps = 3.0F;
  // Function-space trust region (TASK-193 AC#8/#9, doc-30 Phase B). Empty
  // path (the default) leaves the weight-space projection above unchanged.
  // Non-empty REPLACES it: every step() bounds drift by the change in the
  // head's output on this frozen anchor set instead of by ‖w-w0‖. Path is a
  // flat binary file of anchor_count * hidden_size floats (row-major per
  // anchor CLS embedding); function_space_budget is the mean-absolute-drift
  // ceiling in that same output space (see trainable_classifier.h's
  // anchor_drift()). Both must be set together — a budget with no anchor path
  // does nothing, and vice versa.
  std::string function_space_anchor_path;
  float function_space_budget = 0.0F;
  // FTRL statistical pre-filter (ENSEMBLE, not a bypass — TASK-219).
  std::string ftrl_path;          // Path to FTRL weights file. Empty = start fresh.
  // Weight of FTRL P(spam) in the ESCALATE-ONLY "ensemble" fold of the spam side:
  //   scores.spam' = max(neural.spam, w*ftrl + (1-w)*neural.spam)
  // The blend is applied only when it RAISES the spam side, so FTRL can add
  // suspicion but never exonerate. FTRL trains only on the founder's small,
  // spam-poor personal mbox, so a cold ftrl≈0 is absence-of-evidence, not a ham
  // vote — a SYMMETRIC blend at this weight dragged confident-neural spam below
  // the condemn threshold (0/5 recall on the blatant slice, measure_escalate_only.py
  // 2026-06-25). Escalate-only keeps neural's recall while still letting a warm
  // FTRL catch personalized spam. Revisit the weight only with new data.
  float ftrl_ensemble_weight = 0.2F;
  uint32_t ftrl_min_learns = 10;       // FTRL only contributes once total_learns >= this
                                        // (cold-start guard against a freshly-loaded,
                                        // not-yet-warm FTRL routing weird verdicts).
  // Path to GGUF encoder. Empty = model_path + "/gguf/" + the artifact's own
  // classifier_config.json `gguf_encoder_file` (default encoder-q4_k_m.gguf);
  // see default_gguf_encoder_file().
  std::string gguf_model_path;
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
  [[nodiscard]] bool is_loaded() const noexcept;

  // Embedding dimension of the loaded encoder (0 if not loaded). Fixed per
  // model, so C-ABI callers size embed() output buffers from this once.
  [[nodiscard]] int n_embd() const noexcept;

  // Actual encoder backend after load, including automatic Metal->CPU fallback.
  [[nodiscard]] bool uses_gpu() const noexcept;

  // What the loaded artifact says it is.
  //
  // `uuid` comes from a MANIFEST.json sitting in the model directory, which
  // download-models.sh installs after verifying every byte. It is empty for a
  // hand-assembled directory, and an empty uuid means "unknown", never "fine".
  // The rest is read from classifier_config.json, so it is present for any model
  // the engine can load at all.
  //
  // This exists because "which model is this host running?" had no answer. It
  // took hashing files on the box and comparing them against every historical
  // UUID on S3 to discover the public demo had been serving an artifact that was
  // never released, five wrong verdicts and all, for a month.
  struct ModelInfo {
    std::string uuid;          // "" when the directory carries no manifest
    std::string source_model;  // "" when the artifact does not declare one
    int hidden_size = 0;
    int num_labels = 0;
    bool raw_input = false;         // false = the public-v0 legacy envelope
    bool structural_markers = false;
    bool attachment_context = false;
    // 0 when the artifact declares no calibration: the identity map, which is
    // what public-v0 uses. See decision_layer.h calibrate_spam_side.
    double spam_side_calibration_knot = 0.0;
  };
  [[nodiscard]] ModelInfo model_info() const;

  // Does the loaded artifact declare attachment_context=true? Same answer as
  // model_info().attachment_context, without that call's MANIFEST.json stat +
  // parse: the bulk embed path asks this once per message, so reading a file to
  // learn a flag already held in memory would be a per-message cost.
  [[nodiscard]] bool uses_attachment_context() const noexcept { return attachment_context_; }

  // Build the neural input shape declared by classifier_config.json. Public-v0
  // uses the legacy User/Customer envelope; successor models use raw enriched
  // text. Keeping this model-bound prevents a comparison or rollout from
  // silently feeding one model the other model's representation.
  [[nodiscard]] CalibratedInputText calibrate_input(
      const std::vector<TranscriptMessage>& transcript,
      const CustomerInfo& customer) const;

  // Model-bound RFC822 representation. normalized_text is always the legacy,
  // marker-free base; marker_prefix is prepended only when the loaded artifact
  // declares structural_markers=true. FTRL receives normalized_text directly.
  [[nodiscard]] CalibratedInputText calibrate_preprocessed_input(
      const std::string& normalized_text,
      const std::string& marker_prefix,
      const std::string& attachment_context,
      const CustomerInfo& customer) const;

  // Compatibility convenience for generic callers/tests with no attachment
  // parse. Model-bound RFC822 paths use the four-argument form above.
  [[nodiscard]] CalibratedInputText calibrate_preprocessed_input(
      const std::string& normalized_text,
      const std::string& marker_prefix,
      const CustomerInfo& customer) const {
    return calibrate_preprocessed_input(
        normalized_text, marker_prefix, "", customer);
  }

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
      const ClassifyOptions& options,
      bool extract_attachment_signals = false);

  ClassificationResult classify_transcript(
      const std::vector<TranscriptMessage>& transcript,
      const CustomerInfo& customer,
      const ClassifyOptions& options);

  // Encoder API. The string types here are CalibratedInputText, NOT
  // std::string — the compiler enforces that anything fed to the head
  // went through an explicit `build_input_text` choice first. See
  // engine/PARITY_PLAN.md for the rationale.
  std::vector<float> embed(const CalibratedInputText& input);
  std::vector<std::vector<float>> embed_batch(
      const std::vector<CalibratedInputText>& inputs);
  ClassScores classify_embedding(
      const std::vector<float>& embedding,
      bool cache_for_training = false);

  float train_text(const std::string& text, int correct_label);
  float train_rfc822(const std::string& raw_rfc822,
                     const CustomerInfo& customer,
                     int correct_label);
  // Train only the additive, escalate-only FTRL learner. The neural head is
  // neither embedded nor updated. This is the role-specific Klar Plus arm:
  // personalized spam evidence may raise the spam side, but a spam-poor early
  // mailbox cannot teach the base neural classifier that spam is ham.
  void train_ftrl_rfc822(const std::string& raw_rfc822,
                         const CustomerInfo& customer,
                         int correct_label);
  float train_embedding(const std::vector<float>& embedding, int correct_label);

  // The loaded neural head itself, nullptr until load(). What a caller that
  // drives the head outside classify/train (its own objective or optimizer,
  // through the head's public training kernel) reaches it by; the head's
  // label_index() is also how such a caller maps a label name to the head's
  // own index, which is not the 0-3 semantic of train_embedding.
  [[nodiscard]] TrainableClassifierHead* trainable_head() noexcept;

  // Trust-region telemetry (doc-26). `head_drift_saturation` is ‖w-w0‖ as a
  // fraction of the `max_drift` budget, maxed over the head's four tensors:
  // 1.0 means the head is pinned to the boundary, so further corrections
  // displace earlier ones instead of adding to them. `head_relative_drift` is
  // the same distance without the budget in the denominator. Both are 0 before
  // any training. Diagnostic only — nothing in the classify path reads them.
  [[nodiscard]] float head_drift_saturation() const;
  [[nodiscard]] float head_relative_drift() const;
  [[nodiscard]] int head_optimizer_steps() const;

  void save(const std::string& model_path = "");

  // Flywheel (TASK-134): the PORTABLE, state-independent contribution bag for an
  // RFC822 message — `{ bucket -> signed ln(1+count) }`, the same derived
  // representation the FTRL head trains on, bucketed identically on every device.
  // Built from the same preprocessed text as train_rfc822 (plain/html parts
  // merged). `hash_key != 0` keys the buckets (HMAC-style). This is the ONLY
  // thing the flywheel ever uploads — hash buckets + weights, never raw text.
  // Inert: it just computes a value; nothing in the engine transmits it.
  [[nodiscard]] std::map<uint32_t, float> extract_contribution(
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
  [[nodiscard]] std::string scrub_contribution(const std::string& raw_rfc822) const;

  void set_learning_rate(float learning_rate);
  [[nodiscard]] float learning_rate() const;

  static int label_from_string(const std::string& label);
  static std::string label_to_string(int label);
  // Canonical int->name mapping as a static string literal (single source of
  // truth for label_to_string and the C API's spam_engine_label_name).
  static const char* label_name(int label);

 private:
  class Impl;

  static ClassificationResult decision_from_scores(const ClassScores& scores) ;
  // Fold FTRL P(spam) + neural scores into one pre-structural verdict per `mode`
  // (ensemble|neural|ftrl). `ftrl_score` < 0 means FTRL unavailable/cold. The
  // single place the bypass-vs-ensemble policy lives, shared by every classify
  // entry point so they cannot drift.
  [[nodiscard]] ClassificationResult combine_scores(
      const ClassScores& neural, float ftrl_score, const std::string& mode) const;
  ClassificationResult classify_inputs(
      const CalibratedInputText& neural_input,
      const CalibratedInputText& ftrl_input,
      const ClassifyOptions& options);
  void ensure_loaded() const;
  float train_inputs(
      const CalibratedInputText& neural_input,
      const CalibratedInputText& ftrl_input,
      int correct_label);
  float train_prepared_input(
      const std::vector<float>& embedding,
      const CalibratedInputText& ftrl_input,
      int correct_label);
  [[nodiscard]] std::vector<std::pair<CalibratedInputText, CalibratedInputText>>
  prepare_rfc822_training_inputs(
      const std::string& raw_rfc822,
      const CustomerInfo& customer) const;

  EngineConfig config_;
  std::unique_ptr<Impl> impl_;
  bool loaded_ = false;
  ModelInputFormat input_format_ = ModelInputFormat::kLegacyWrapped;
  bool structural_markers_ = false;
  bool attachment_context_ = false;
};

}  // namespace spam_engine
