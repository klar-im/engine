#include "spam_engine.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <stdexcept>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "decision_layer.h"
#include "email_preprocessor.h"
#include "ftrl_classifier.h"
#include "pii_scrub.h"
#include "ggml_encoder.h"
#include "trainable_classifier.h"

namespace spam_engine {

namespace {

// The one log sink of the process (engine_runtime.h says why it is defined
// here and not inline in the header).
struct LogSinkState {
  std::mutex mutex;
  LogSink fn = nullptr;
  void* user = nullptr;
};

LogSinkState& log_sink_state() {
  static LogSinkState state;
  return state;
}

}  // namespace

void set_log_sink(LogSink fn, void* user) {
  auto& state = log_sink_state();
  std::scoped_lock const lock(state.mutex);
  state.fn = fn;
  state.user = user;
}

void log_line(LogLevel level, const char* text) {
  if (text == nullptr) { return; }
  LogSink fn = nullptr;
  void* user = nullptr;
  {
    auto& state = log_sink_state();
    std::scoped_lock const lock(state.mutex);
    fn = state.fn;
    user = state.user;
  }
  if (fn != nullptr) {
    fn(static_cast<int>(level), text, user);
  } else {
    std::fputs(text, stderr);
  }
}

// Which quantized encoder an artifact ships, read from its own
// classifier_config.json (`gguf_encoder_file`, written by
// export_classifier_weights.py). Absent means the historical default, so
// every artifact exported before the key existed loads unchanged. One bare
// filename under gguf/, never a path: the same string the manifest lists and
// the Swift ModelStore checks for, so all three read one declaration.
std::string default_gguf_encoder_file(const std::string& model_path) {
  static constexpr const char* kFallback = "encoder-q4_k_m.gguf";
  std::ifstream config_file(model_path + "/classifier_config.json");
  if (!config_file) {
    return kFallback;
  }
  nlohmann::json config;
  try {
    config_file >> config;
  } catch (const nlohmann::json::exception&) {
    return kFallback;  // the head's own parse reports the malformed file
  }
  if (!config.contains("gguf_encoder_file")) {
    return kFallback;
  }
  if (!config["gguf_encoder_file"].is_string()) {
    throw std::invalid_argument(
        "classifier_config.json: gguf_encoder_file must be a string");
  }
  const std::string name = config["gguf_encoder_file"].get<std::string>();
  const bool bare_name = !name.empty() && name.find('/') == std::string::npos &&
                         name.find('\\') == std::string::npos && name != "." &&
                         name != "..";
  if (!bare_name) {
    throw std::invalid_argument(
        "classifier_config.json: gguf_encoder_file must be a bare filename under gguf/");
  }
  return name;
}

// Parse "Foo Bar <foo@example.com>" or "foo@example.com" into (name, email).
// Public so the C ABI doesn't have to re-inline this logic.
std::pair<std::string, std::string> parse_from_header(const std::string& from) {
  if (from.empty()) {
    return {"", ""};
  }
  const size_t lt = from.find('<');
  const size_t gt = from.find('>');
  if (lt != std::string::npos && gt != std::string::npos && gt > lt) {
    std::string name = from.substr(0, lt);
    while (!name.empty() && (name.front() == '"' || name.front() == ' ')) {
      name.erase(0, 1);
    }
    while (!name.empty() && (name.back() == '"' || name.back() == ' ')) {
      name.pop_back();
    }
    return {name, from.substr(lt + 1, gt - lt - 1)};
  }
  return {"", from};
}

// Single source of truth for "merge what the caller passed with what GMime
// parsed out of the headers". Used by classify_rfc822, train_rfc822, and
// the C ABI's spam_engine_embed_rfc822 — three sites that previously had
// the same reconciliation logic copy-pasted.
//
// - replyto_differs is always overridden from the parse (it's a property
//   of the message, not the caller).
// - name + email are filled from the From header only if the caller passed
//   neither — caller-supplied values always win, since Apple Mail's
//   MEMessage sender is more reliable than the parsed From for the cases
//   where they differ.
void apply_preprocessed_to_sender(
    SenderInfo& sender,
    const PreprocessedEmail& preprocessed) {
  sender.replyto_differs = preprocessed.replyto_differs;
  if (sender.name.empty() && sender.email.empty() && !preprocessed.from.empty()) {
    auto parsed = parse_from_header(preprocessed.from);
    sender.name = std::move(parsed.first);
    sender.email = std::move(parsed.second);
  }
}

// === CalibratedInputText constructor =====================================
//
// `build_input_text` is the ONLY way a CalibratedInputText comes into
// existence. The model artifact selects one of two explicit shapes:
//
//   "User (email): <body>\n[Customer Info:\nName: ...\nEmail: ...]
//    [ReplyToDiffers: yes]\n"
//
// Legacy public-v0 uses the envelope above (its wording is what that model was
// trained on, so it stays byte-for-byte); successor models use the raw text.
// Optional legacy fields appear only when present.

CalibratedInputText build_input_text(
    const std::string& text,
    const SenderInfo& sender,
    ModelInputFormat format) {
  if (format == ModelInputFormat::kRaw) {
    return CalibratedInputText(text + '\n');
  }

  std::string input_text = "User (email): " + text + "\n";
  const bool has_any_sender_signal =
      !sender.name.empty() || !sender.email.empty() || sender.replyto_differs;
  if (has_any_sender_signal) {
    input_text += "Customer Info:\n";
    if (!sender.name.empty()) { input_text += "Name: " + sender.name + "\n";
}
    if (!sender.email.empty()) { input_text += "Email: " + sender.email + "\n";
}
    if (sender.replyto_differs) { input_text += "ReplyToDiffers: yes\n";
}
  }
  return CalibratedInputText(std::move(input_text));
}

class SpamEngine::Impl {
 public:
  std::unique_ptr<GgmlEncoder> encoder;
  std::unique_ptr<TrainableClassifierHead> trainable_head;
  std::unique_ptr<FTRLClassifier> ftrl;
  std::string model_uuid;  // from MANIFEST.json, read once at load; "" = unknown
};

namespace {

// A missing or unreadable manifest yields "" rather than throwing: not knowing
// which artifact this is must never be the reason a load (or a classify)
// fails. The empty string is the honest answer and callers report it as
// unknown.
std::string read_manifest_uuid(const std::string& model_path) {
  const std::filesystem::path manifest = std::filesystem::path(model_path) / "MANIFEST.json";
  std::error_code ec;
  if (!std::filesystem::exists(manifest, ec)) { return ""; }
  try {
    std::ifstream in(manifest);
    nlohmann::json doc;
    in >> doc;
    return doc.value("model_uuid", "");
  } catch (const std::exception& e) {
    log_printf(LogLevel::kWarn, "[spam_engine] ignoring unreadable MANIFEST.json (%s)", e.what());
    return "";
  }
}

}  // namespace

SpamEngine::SpamEngine() : impl_(std::make_unique<Impl>()) {}

SpamEngine::SpamEngine(const EngineConfig& config) : SpamEngine() {
  load(config);
}

SpamEngine::~SpamEngine() = default;

SpamEngine::SpamEngine(SpamEngine&&) noexcept = default;
SpamEngine& SpamEngine::operator=(SpamEngine&&) noexcept = default;

void SpamEngine::load(const EngineConfig& config) {
  unload();
  config_ = config;

  if (config_.model_path.empty()) {
    throw std::invalid_argument("model_path cannot be empty");
  }

  const auto validate_max_drift_steps = [](float value) {
    if (!std::isfinite(value) || value < 0.0F || value > 100000.0F) {
      throw std::invalid_argument(
          "max_drift_steps must be finite and in [0, 100000]; 0 disables the cap");
    }
  };
  // EngineConfig is a public C++ entry point, so validate it independently of
  // the optional environment override. Otherwise a non-finite programmatic
  // value reaches the trust-region projection even when no env var is set.
  validate_max_drift_steps(config_.max_drift_steps);
  // Same reasoning for the function-space budget: a programmatic caller can
  // set EngineConfig::function_space_budget directly, bypassing the env-var
  // parser's finiteness check below. An unvalidated +inf/NaN budget is worse
  // than a bad max_drift_steps: every drift_at(alpha) > budget comparison is
  // false, so the projection never fires, while function_space_enabled_ still
  // switches off the weight-space projection entirely -- silently disabling
  // BOTH safety mechanisms at once (codex review, 2026-08-29).
  if (!config_.function_space_anchor_path.empty() &&
      !std::isfinite(config_.function_space_budget)) {
    throw std::invalid_argument(
        "function_space_budget must be finite when function_space_anchor_path "
        "is set");
  }

  if (config_.gguf_model_path.empty()) {
    config_.gguf_model_path =
        config_.model_path + "/gguf/" + default_gguf_encoder_file(config_.model_path);
  }

  // GgmlEncoder::load() also calls setenv() once per process (see
  // ensure_ggml_env_configured()). Trigger that call_once here too, before
  // any of the getenv() calls below, so two SpamEngine instances loading
  // concurrently for the first time serialize on it instead of one thread's
  // getenv() racing another's setenv() (codex review, TASK-478).
  ensure_ggml_env_configured();

  // Env-var override for the token cap — A/B knob against a single compiled
  // dylib. The value is validated downstream by GgmlEncoder against
  // [kMinMaxTokens, model->n_ctx_train]; here we only parse and log so an
  // accidental shell leak (CI, dev .envrc) doesn't silently retune production.
  // ensure_ggml_env_configured() above makes this race-free; see its comment.
  // NOLINTNEXTLINE(concurrency-mt-unsafe)
  if (const char* env = std::getenv("SPAM_ENGINE_MAX_TOKENS")) {
    try {
      const int parsed = std::stoi(env);
      log_printf(LogLevel::kInfo,
          "[spam_engine] SPAM_ENGINE_MAX_TOKENS=%s overrides encoder_max_tokens %d -> %d",
          env, config_.encoder_max_tokens, parsed);
      config_.encoder_max_tokens = parsed;
    } catch (const std::exception& e) {
      log_printf(LogLevel::kWarn,
          "[spam_engine] ignoring invalid SPAM_ENGINE_MAX_TOKENS=%s (%s)", env, e.what());
    }
  }

  // Same knob for the trust-region radius. doc-26's one control run needed a
  // full rebuild because this is a compile-time default, which is why exactly
  // one alternative radius was ever measured. A radius that decides how much a
  // paying user is allowed to teach their own filter deserves a sweep, and a
  // sweep has to be cheaper than five rebuilds. Range-checked here rather than
  // downstream: <= 0 disables the cap entirely, which is a legitimate experiment
  // but never something a stray shell variable should switch on.
  // NOLINTNEXTLINE(concurrency-mt-unsafe) — see the getenv() note above.
  if (const char* env = std::getenv("SPAM_ENGINE_MAX_DRIFT_STEPS")) {
    try {
      const std::string raw(env);
      std::size_t consumed = 0;
      const float parsed = std::stof(raw, &consumed);
      if (consumed != raw.size()) {
        throw std::invalid_argument("max_drift_steps contains trailing characters");
      }
      validate_max_drift_steps(parsed);
      log_printf(LogLevel::kInfo,
          "[spam_engine] SPAM_ENGINE_MAX_DRIFT_STEPS=%s overrides max_drift_steps "
          "%.3f -> %.3f", env, static_cast<double>(config_.max_drift_steps),
          static_cast<double>(parsed));
      config_.max_drift_steps = parsed;
    } catch (const std::exception& e) {
      log_printf(LogLevel::kWarn,
          "[spam_engine] ignoring invalid SPAM_ENGINE_MAX_DRIFT_STEPS=%s (%s)",
          env, e.what());
    }
  }

  // Same knob shape as SPAM_ENGINE_MAX_DRIFT_STEPS above, for the function-
  // space trust region (TASK-193 AC#8/#9, doc-30 Phase B). Both env vars must
  // be set together to take effect; either alone is ignored (see EngineConfig
  // comment) so a stray shell variable can't half-enable the mechanism.
  // NOLINTNEXTLINE(concurrency-mt-unsafe) — see the getenv() note above.
  if (const char* env = std::getenv("SPAM_ENGINE_FUNCTION_SPACE_ANCHOR")) {
    log_printf(LogLevel::kInfo,
        "[spam_engine] SPAM_ENGINE_FUNCTION_SPACE_ANCHOR=%s overrides "
        "function_space_anchor_path", env);
    config_.function_space_anchor_path = env;
  }
  // NOLINTNEXTLINE(concurrency-mt-unsafe) — see the getenv() note above.
  if (const char* env = std::getenv("SPAM_ENGINE_FUNCTION_SPACE_BUDGET")) {
    try {
      const std::string raw(env);
      std::size_t consumed = 0;
      const float parsed = std::stof(raw, &consumed);
      if (consumed != raw.size()) {
        throw std::invalid_argument("function_space_budget contains trailing characters");
      }
      if (!std::isfinite(parsed) || parsed < 0.0F) {
        throw std::invalid_argument("function_space_budget must be finite and >= 0");
      }
      log_printf(LogLevel::kInfo,
          "[spam_engine] SPAM_ENGINE_FUNCTION_SPACE_BUDGET=%s overrides "
          "function_space_budget %.6f -> %.6f", env,
          static_cast<double>(config_.function_space_budget), static_cast<double>(parsed));
      config_.function_space_budget = parsed;
    } catch (const std::exception& e) {
      log_printf(LogLevel::kWarn,
          "[spam_engine] ignoring invalid SPAM_ENGINE_FUNCTION_SPACE_BUDGET=%s (%s)",
          env, e.what());
    }
  }

  impl_->encoder = std::make_unique<GgmlEncoder>();
  impl_->encoder->load(config_.gguf_model_path, config_.encoder_max_tokens);

  impl_->trainable_head = std::make_unique<TrainableClassifierHead>(
      config_.model_path, config_.learning_rate, config_.l2_lambda, config_.max_grad_norm,
      config_.max_drift_steps, config_.function_space_anchor_path,
      config_.function_space_budget);
  input_format_ = impl_->trainable_head->uses_raw_input()
      ? ModelInputFormat::kRaw : ModelInputFormat::kLegacyWrapped;
  structural_markers_ = impl_->trainable_head->uses_structural_markers();
  attachment_context_ = impl_->trainable_head->uses_attachment_context();

  // The neural path indexes the CLS embedding up to the head's input size, so
  // the encoder output dim and the head's hidden size must agree. They come from
  // independent assets (the gguf vs classifier_config.json), so assert equality
  // here: a mismatched model package fails fast at load instead of throwing on
  // every classify_embedding (C4, TASK-251).
  if (impl_->encoder->n_embd() != impl_->trainable_head->input_size()) {
    throw std::runtime_error(
        "model mismatch: encoder n_embd (" +
        std::to_string(impl_->encoder->n_embd()) +
        ") != classifier head input size (" +
        std::to_string(impl_->trainable_head->input_size()) + ")");
  }

  impl_->ftrl = std::make_unique<FTRLClassifier>();
  if (!config_.ftrl_path.empty() && !impl_->ftrl->load(config_.ftrl_path)) {
    // A missing/corrupt baseline must leave a genuinely COLD FTRL (learn-counts
    // zero) so the cold-start guard bypasses it, not a half-loaded one whose
    // bogus counts pass the guard (C3, TASK-251). load() is transactional, but
    // rebuild to guarantee a pristine cold state.
    log_printf(LogLevel::kWarn,
        "[spam_engine] FTRL baseline load failed for %s; starting cold",
        config_.ftrl_path.c_str());
    impl_->ftrl = std::make_unique<FTRLClassifier>();
  }

  // The uuid is read once here, not per model_info() call: the extension
  // asks for model_info on every classify, and a manifest that is present
  // but unreadable would otherwise cost a parse and a WARN line (a row in
  // Plus's logs table) per email. The directory is immutable for the life of
  // a load; a new deploy is a new load.
  impl_->model_uuid = read_manifest_uuid(config_.model_path);

  loaded_ = true;
  // The one line that says which backend this process classifies on, from
  // the engine at the moment it knows, so an appex log answers "did Metal
  // fall back" without any caller re-deriving it. Last, after every throw
  // above: a head that fails to load must not leave a "loaded" line behind.
  const auto& runtime = impl_->encoder->runtime_info();
  log_printf(LogLevel::kInfo,
      "[spam_engine] loaded backend=%s device=\"%s\" max_tokens=%d fallback=%s",
      runtime.backend.c_str(), runtime.device.c_str(), runtime.max_tokens,
      encoder_fallback_name(runtime.fallback));
  if (runtime.fallback == EncoderFallback::kContextInitFailed) {
    std::string detail = runtime.fallback_detail;
    std::replace(detail.begin(), detail.end(), '\n', '|');
    log_printf(LogLevel::kWarn, "[spam_engine] GPU context init failed, on CPU: %s",
        detail.c_str());
  }
}

void SpamEngine::unload() noexcept {
  impl_ = std::make_unique<Impl>();
  loaded_ = false;
  input_format_ = ModelInputFormat::kLegacyWrapped;
  structural_markers_ = false;
  attachment_context_ = false;
}

bool SpamEngine::is_loaded() const noexcept {
  return loaded_;
}

int SpamEngine::n_embd() const noexcept {
  return (loaded_ && impl_->encoder) ? impl_->encoder->n_embd() : 0;
}

EncoderRuntimeInfo SpamEngine::runtime_info() const {
  if (!loaded_ || !impl_->encoder) { return {}; }
  return impl_->encoder->runtime_info();
}

SpamEngine::ModelInfo SpamEngine::model_info() const {
  ModelInfo info;
  if (!loaded_ || !impl_->trainable_head) { return info;
}

  const auto& head = *impl_->trainable_head;
  info.source_model = head.source_model();
  info.hidden_size = head.hidden_size();
  info.num_labels = head.output_size();
  info.raw_input = head.uses_raw_input();
  info.structural_markers = head.uses_structural_markers();
  info.attachment_context = head.uses_attachment_context();
  info.spam_side_calibration_knot = head.spam_side_calibration_knot();
  info.uuid = impl_->model_uuid;  // read once at load, see read_manifest_uuid
  return info;
}

CalibratedInputText SpamEngine::calibrate_input(
    const std::string& text,
    const SenderInfo& sender) const {
  ensure_loaded();
  return build_input_text(text, sender, input_format_);
}

CalibratedInputText SpamEngine::calibrate_preprocessed_input(
    const std::string& normalized_text,
    const std::string& marker_prefix,
    const std::string& attachment_context,
    const SenderInfo& sender) const {
  ensure_loaded();
  std::string model_text = normalized_text;
  if (structural_markers_ && !marker_prefix.empty() && !model_text.empty()) {
    model_text = marker_prefix + "\n" + model_text;
  }
  if (attachment_context_ && !attachment_context.empty()) {
    constexpr const char* kEmailMarker = "[Email]\n";
    const std::size_t marker = attachment_context.find(kEmailMarker);
    if (marker == std::string::npos) {
      model_text = attachment_context + model_text;
    } else {
      const std::size_t after_marker = marker + std::strlen(kEmailMarker);
      const std::string details = attachment_context.substr(after_marker);
      model_text = attachment_context.substr(0, after_marker) + model_text;
      if (!details.empty()) {
        model_text += "\n" + details;
        while (!model_text.empty() && model_text.back() == '\n') {
          model_text.pop_back();
}
      }
    }
  }
  return build_input_text(model_text, sender, input_format_);
}

void SpamEngine::ensure_loaded() const {
  if (!loaded_ || !impl_->encoder || !impl_->trainable_head) {
    throw std::runtime_error("SpamEngine is not loaded. Call load() first.");
  }
}

std::vector<float> SpamEngine::embed(const CalibratedInputText& input) {
  auto batch_result = embed_inputs({input});
  return batch_result.empty() ? std::vector<float>() : std::move(batch_result[0].values);
}

std::vector<std::vector<float>> SpamEngine::embed_batch(
    const std::vector<CalibratedInputText>& inputs) {
  auto embeddings = embed_inputs(inputs);
  std::vector<std::vector<float>> values;
  values.reserve(embeddings.size());
  for (auto& embedding : embeddings) {
    values.push_back(std::move(embedding.values));
  }
  return values;
}

std::vector<EncoderEmbedding> SpamEngine::embed_inputs(
    const std::vector<CalibratedInputText>& inputs) {
  ensure_loaded();
  if (inputs.empty()) { return {};
}

  // The encoder's embed_batch takes raw strings; the type-level guarantee
  // is satisfied at the SpamEngine boundary. Unwrap here.
  std::vector<std::string> raw_texts;
  raw_texts.reserve(inputs.size());
  for (const auto& input : inputs) {
    raw_texts.push_back(input.str());
  }
  return impl_->encoder->embed_batch(raw_texts);
}

ClassScores SpamEngine::classify_embedding(
    const std::vector<float>& embedding,
    bool cache_for_training) {
  ensure_loaded();

  // forward() indexes cls_embedding[j] for j in [0, n_embd) with no internal
  // bounds check, so a short buffer from any FFI/host caller is a silent OOB
  // heap read. Validate the length at this single choke point (train_embedding
  // routes through it too) before touching the head (C4, TASK-251).
  const int expected = impl_->trainable_head->input_size();
  if (embedding.size() != static_cast<size_t>(expected)) {
    throw std::invalid_argument(
        "classify_embedding: embedding size " + std::to_string(embedding.size()) +
        " != model input size " + std::to_string(expected));
  }

  const auto logits = impl_->trainable_head->forward(embedding, cache_for_training);
  const auto probabilities = TrainableClassifierHead::softmax(logits);
  if (probabilities.size() !=
      static_cast<size_t>(impl_->trainable_head->output_size())) {
    throw std::runtime_error("Unexpected classifier output size");
  }

  const auto probability = [&](const std::string& label) {
    const int index = impl_->trainable_head->label_index(label);
    return index < 0 ? 0.0F : probabilities[static_cast<size_t>(index)];
  };

  // A legacy 4-label head (public-v0) also has a gibberish row, which the fold
  // always counted on the spam side (spam + gibberish). Adding it here, at the
  // one place labels are mapped, keeps that spam side exact and leaves the
  // product taxonomy three classes everywhere downstream (TASK-540).
  return ClassScores{
      probability("marketing"),
      probability("regular"),
      probability("spam") + probability("gibberish"),
  };
}

ClassificationResult SpamEngine::decision_from_scores(const ClassScores& scores) {
  // Shared with the fold's input builder so the binary label the fold reads
  // as "what the model said" is identical across the engine, the C ABI, and Swift
  // (TASK-251 C5).
  const decision::NeuralDecision nd = decision::neural_decision(
      {scores.marketing, scores.regular, scores.spam});
  return ClassificationResult{nd.label, static_cast<float>(nd.confidence), scores,
                              "neural", -1.0F};
}

namespace {
// classify mode is a required, validated choice — no silent "auto" (TASK-219).
void validate_mode(const std::string& mode) {
  if (mode != "ensemble" && mode != "neural" && mode != "ftrl") {
    throw std::invalid_argument(
        R"(ClassifyOptions.mode must be "ensemble", "neural", or "ftrl" (got ")" +
        mode + "\")");
  }
}
}  // namespace

ClassificationResult SpamEngine::combine_scores(
    const ClassScores& neural, float ftrl_score, const std::string& mode) const {
  if (mode == "ftrl") {
    // FTRL-only diagnostic path; neural was not run. Cold/absent FTRL
    // (ftrl_score < 0) degrades to a low-confidence "regular".
    if (ftrl_score < 0.0F) {
      return ClassificationResult{"regular", 0.0F, {}, "ftrl", ftrl_score};
    }
    const bool is_spam = ftrl_score >= 0.5F;
    return ClassificationResult{
        is_spam ? "spam" : "regular",
        is_spam ? ftrl_score : 1.0F - ftrl_score,
        {0.0F, 1.0F - ftrl_score, ftrl_score},
        "ftrl", ftrl_score};
  }

  // "neural" and "ensemble" both start from the neural head. ENSEMBLE folds FTRL
  // P(spam) into the spam side ESCALATE-ONLY: the blend is applied only when it
  // RAISES the spam side (ftrl more suspicious than neural). FTRL can add
  // suspicion (catch personalized spam the neural head missed) but never
  // exonerate. Rationale: the FTRL baseline trains on spam-poor data, so a cold
  // ftrl_score ≈ 0 on unseen spam is absence-of-evidence, NOT a ham vote — a
  // symmetric blend reads it as one and drags a confident-neural spam below the
  // 0.90 condemn threshold (blatant spam → inbox; measured 0/5 recall on the
  // blatant slice). max(neural, blend) keeps neural's recall intact by
  // construction. FP-trimming (FTRL's ham-ward pull) is intentionally dropped:
  // it requires a WARM per-user FTRL and belongs in the decision layer, not a
  // cold model's blanket downward vote. See model-lab measure_escalate_only.py.
  ClassScores scores = neural;
  std::string decided_by = "neural";
  if (mode == "ensemble" && ftrl_score >= 0.0F) {
    const float w = config_.ftrl_ensemble_weight;
    const float blend = (w * ftrl_score) + ((1.0F - w) * neural.spam);
    if (blend > neural.spam) {  // FTRL escalated — only direction we trust day 0
      scores.spam = blend;
      decided_by = "ftrl+neural";
    }
  }
  ClassificationResult result = decision_from_scores(scores);
  result.decided_by = decided_by;
  result.ftrl_score = ftrl_score;
  result.neural_spam = neural.spam;  // pre-blend neural P(spam), for stage reporting
  return result;
}

ClassificationResult SpamEngine::classify(
    const std::string& text,
    const std::string& sender_name,
    const std::string& sender_email,
    const ClassifyOptions& options) {
  validate_mode(options.mode);
  const SenderInfo sender{sender_name, sender_email, /*replyto_differs=*/false};
  return classify_inputs(
      calibrate_input(text, sender),
      build_input_text(text, sender, ModelInputFormat::kLegacyWrapped),
      options);
}

ClassificationResult SpamEngine::classify_rfc822(
    const std::string& raw_rfc822,
    const std::string& sender_name,
    const std::string& sender_email,
    const ClassifyOptions& options,
    bool extract_attachment_signals) {
  auto preprocessed = preprocess_rfc822(
      raw_rfc822, attachment_context_ || extract_attachment_signals);

  SenderInfo sender{sender_name, sender_email, /*replyto_differs=*/false};
  apply_preprocessed_to_sender(sender, preprocessed);

  // The decision logic has several early returns; run it through a lambda so we
  // can stamp the structural features (computed during the preprocess parse —
  // TASK-173) onto every result without touching each return site.
  auto result = [&]() -> ClassificationResult {
    validate_mode(options.mode);
    if (!preprocessed.normalized_plain_text.empty() && !preprocessed.normalized_html_text.empty()) {
      // Multipart: wrap each part via the canonical builder so the embeddings
      // we feed classify_embedding() come from the same distribution the head
      // was trained on.
      const auto plain_input = calibrate_preprocessed_input(
          preprocessed.normalized_plain_text,
          preprocessed.structural_marker_prefix,
          preprocessed.attachment_features.context, sender);
      const auto ftrl_input = build_input_text(
          preprocessed.normalized_plain_text, sender,
          ModelInputFormat::kLegacyWrapped);

      // FTRL P(spam) on the plain body (always present in multipart), unless
      // mode=neural. Only contributes once warm. The bypass is gone: the score
      // is BLENDED into the neural verdict by combine_scores, never overrides it.
      float ftrl_score = -1.0F;
      if (options.mode != "neural" && impl_->ftrl &&
          impl_->ftrl->total_learns() >= config_.ftrl_min_learns) {
        ftrl_score = impl_->ftrl->predict_text(ftrl_input.str());
      }
      if (options.mode == "ftrl") {
        // FTRL-only: neural never runs, so the html part is never embedded —
        // don't pay to build/wrap it.
        return combine_scores(/*neural=*/{}, ftrl_score, options.mode);
      }
      const auto html_input = calibrate_preprocessed_input(
          preprocessed.normalized_html_text,
          preprocessed.structural_marker_prefix,
          preprocessed.attachment_features.context, sender);
      const auto embeddings = embed_inputs({plain_input, html_input});
      const auto plain_scores = classify_embedding(embeddings[0].values, false);
      const auto html_scores = classify_embedding(embeddings[1].values, false);
      const auto& best_scores = (html_scores.spam > plain_scores.spam) ? html_scores : plain_scores;
      auto combined = combine_scores(best_scores, ftrl_score, options.mode);
      combined.encoder_truncated_sequences =
          (embeddings[0].truncated ? 1U : 0U) + (embeddings[1].truncated ? 1U : 0U);
      return combined;
    }

    // Single-part: preserve the RFC822 artifact contract as well as the
    // independent legacy FTRL input. Routing through classify(text) here would
    // silently drop structural_marker_prefix because generic text has no
    // parsed RFC822 structure attached to it.
    const std::string& body = !preprocessed.normalized_plain_text.empty()
        ? preprocessed.normalized_plain_text
        : !preprocessed.normalized_html_text.empty()
            ? preprocessed.normalized_html_text
            : preprocessed.normalized_text;
    return classify_inputs(
        calibrate_preprocessed_input(
            body, preprocessed.structural_marker_prefix,
            preprocessed.attachment_features.context, sender),
        build_input_text(body, sender, ModelInputFormat::kLegacyWrapped),
        options);
  }();

  // preprocessed is a local that dies here; move the feature strings out rather
  // than copy them (the lambda above already consumed its normalized text).
  result.thread_features = std::move(preprocessed.thread_features);
  result.auth_features = std::move(preprocessed.auth_features);
  result.url_features = preprocessed.url_features;
  result.body_features = preprocessed.body_features;
  result.attachment_features = std::move(preprocessed.attachment_features);
  return result;
}

ClassificationResult SpamEngine::classify_inputs(
    const CalibratedInputText& neural_input,
    const CalibratedInputText& ftrl_input,
    const ClassifyOptions& options) {
  validate_mode(options.mode);

  // FTRL P(spam), unless mode=neural. Only contributes once warm
  // (total_learns >= ftrl_min_learns); a cold baseline stays at -1 and the
  // ensemble cleanly falls back to pure neural.
  float ftrl_score = -1.0F;
  if (options.mode != "neural" && impl_->ftrl &&
      impl_->ftrl->total_learns() >= config_.ftrl_min_learns) {
    ftrl_score = impl_->ftrl->predict_text(ftrl_input.str());
  }

  // mode=ftrl skips the (expensive) neural forward pass entirely.
  ClassScores neural{};
  bool truncated = false;
  if (options.mode != "ftrl") {
    const auto embeddings = embed_inputs({neural_input});
    neural = classify_embedding(embeddings[0].values, false);
    truncated = embeddings[0].truncated;
  }
  auto result = combine_scores(neural, ftrl_score, options.mode);
  result.encoder_truncated_sequences = truncated ? 1U : 0U;
  return result;
}

float SpamEngine::train_inputs(
    const CalibratedInputText& neural_input,
    const CalibratedInputText& ftrl_input,
    int correct_label) {
  // Embedding is the expensive/fallible half. Finish it before either online
  // learner mutates so an encoder failure cannot leave an unreceipted FTRL
  // update behind.
  return train_prepared_input(embed(neural_input), ftrl_input, correct_label);
}

float SpamEngine::train_prepared_input(
    const std::vector<float>& embedding,
    const CalibratedInputText& ftrl_input,
    int correct_label) {
  if (correct_label < 0 || correct_label > 3) {
    throw std::invalid_argument("correct_label must be in [0, 3]");
  }

  // Feature extraction may allocate and may consult the current FTRL state for
  // cuckoo bucket selection. Do it before the head update; learn() itself is a
  // fixed-size in-place loop. The neural backward pass likewise allocates all
  // scratch buffers before touching gradients (TrainableClassifierHead).
  std::vector<FTRLClassifier::Feature> ftrl_features;
  if (impl_->ftrl) {
    ftrl_features = impl_->ftrl->extract_features(ftrl_input.str());
  }
  const float loss = train_embedding(embedding, correct_label);
  if (impl_->ftrl) {
    const bool is_spam = (correct_label == 0 || correct_label == 3);
    impl_->ftrl->learn(ftrl_features, is_spam);
  }
  return loss;
}

float SpamEngine::train_text(const std::string& text, int correct_label) {
  const SenderInfo sender{};
  return train_inputs(
      calibrate_input(text, sender),
      build_input_text(text, sender, ModelInputFormat::kLegacyWrapped),
      correct_label);
}

std::vector<std::pair<CalibratedInputText, CalibratedInputText>>
SpamEngine::prepare_rfc822_training_inputs(
    const std::string& raw_rfc822,
    const SenderInfo& sender) const {
  // Mirror classify_rfc822 exactly: multipart trains on both plain and
  // html parts wrapped via the canonical builder; single-part trains on
  // whichever body the preprocessor produced. The CalibratedInputText
  // type makes "wrap before embed" structurally enforced — there's no
  // way to skip it.
  const auto preprocessed = preprocess_rfc822(raw_rfc822, attachment_context_);

  SenderInfo s = sender;
  apply_preprocessed_to_sender(s, preprocessed);

  std::vector<std::pair<CalibratedInputText, CalibratedInputText>> inputs;
  const auto add_inputs = [&](const std::string& text) {
    inputs.emplace_back(
        calibrate_preprocessed_input(
            text, preprocessed.structural_marker_prefix,
            preprocessed.attachment_features.context, s),
        build_input_text(text, s, ModelInputFormat::kLegacyWrapped));
  };
  // build_normalized_text() includes the subject even when its body argument is
  // empty. Gate on the actual MIME part as well, otherwise a text/plain-only
  // message trains once on subject+body and a second time on a phantom
  // subject-only "HTML" sample (and vice versa).
  if (!preprocessed.plain_body_text.empty() &&
      !preprocessed.normalized_plain_text.empty()) {
    add_inputs(preprocessed.normalized_plain_text);
  }
  if (!preprocessed.html_body_text.empty() &&
      !preprocessed.normalized_html_text.empty() &&
      preprocessed.normalized_html_text != preprocessed.normalized_plain_text) {
    add_inputs(preprocessed.normalized_html_text);
  }
  if (inputs.empty() && !preprocessed.normalized_text.empty()) {
    add_inputs(preprocessed.normalized_text);
  }
  if (inputs.empty()) {
    throw std::runtime_error("No trainable RFC822 text extracted");
  }
  return inputs;
}

float SpamEngine::train_rfc822(const std::string& raw_rfc822,
                               const SenderInfo& sender,
                               int correct_label) {
  const auto inputs = prepare_rfc822_training_inputs(raw_rfc822, sender);

  // Prepare every fallible input before applying the correction. A bad second
  // part must not leave the first part applied while the caller records the
  // whole RFC822 sample as failed and retryable.
  std::vector<std::vector<float>> embeddings;
  embeddings.reserve(inputs.size());
  for (const auto& input_pair : inputs) {
    embeddings.push_back(embed(input_pair.first));
  }
  const auto ftrl_features = impl_->ftrl
      ? impl_->ftrl->extract_features(inputs.front().second.str())
      : std::vector<FTRLClassifier::Feature>{};

  const std::string semantic_label = label_name(correct_label);
  int model_label = impl_->trainable_head->label_index(semantic_label);
  if (model_label < 0 && correct_label == 0) {
    model_label = impl_->trainable_head->label_index("spam");
  }
  if (model_label < 0) {
    throw std::invalid_argument(
        "correct_label is not represented by this model's label_map");
  }

  // One user correction is one head optimizer step, even when the MIME message
  // has both plain and HTML representations. Accumulate their gradients and
  // average the batch. No weights move until every forward/backward succeeds;
  // zero_grad makes an allocation failure on a later part retry-safe.
  float loss_sum = 0.0F;
  try {
    for (const auto& embedding : embeddings) {
      (void)classify_embedding(embedding, true);
      loss_sum += impl_->trainable_head->backward(model_label);
    }
  } catch (...) {
    impl_->trainable_head->zero_grad();
    throw;
  }
  impl_->trainable_head->step(static_cast<int>(inputs.size()));

  if (impl_->ftrl) {
    const bool is_spam = (correct_label == 0 || correct_label == 3);
    // Classification ensembles FTRL from the plain representation only (or
    // the sole available representation for a single-part message). Mirror
    // that contract and count one FTRL learn per user correction.
    impl_->ftrl->learn(ftrl_features, is_spam);
  }
  return loss_sum / static_cast<float>(inputs.size());
}

void SpamEngine::train_ftrl_rfc822(const std::string& raw_rfc822,
                                   const SenderInfo& sender,
                                   int correct_label) {
  ensure_loaded();
  if (correct_label < 0 || correct_label > 3) {
    throw std::invalid_argument("correct_label must be in [0, 3]");
  }
  if (!impl_->ftrl) {
    throw std::runtime_error("FTRL-only training requires a loaded FTRL model");
  }

  const auto inputs = prepare_rfc822_training_inputs(raw_rfc822, sender);
  // Classification and the joint head+FTRL path both use the first available
  // representation for FTRL (plain preferred, otherwise HTML/combined). Keep
  // that contract here so choosing the learner cannot change its features.
  const auto features = impl_->ftrl->extract_features(inputs.front().second.str());
  const bool is_spam = (correct_label == 0 || correct_label == 3);
  impl_->ftrl->learn(features, is_spam);
}

// The representative body part the contribution hashes (plain preferred, else
// html, else combined) — the same choice classify_rfc822's FTRL pre-filter
// makes. We use ONE part, not a per-part sum: summing log-compressed weights
// (ln(1+a)+ln(1+b) != ln(1+a+b)) is not a value the head ever trains on. The
// text is PII-scrubbed here: GMime already dropped attachments and split real
// headers, so scrub_body_text only needs to redact quoted/forwarded recipient-
// routing headers and strip inline data: URIs from the body itself.
namespace {
// The representative body part (plain preferred, else html, else combined),
// PII-scrubbed. Shared by scrub_contribution and extract_contribution so the
// bag and the audit string come from the identical text.
std::string representative_scrubbed_text(const PreprocessedEmail& p) {
  const std::string& text =
      !p.normalized_plain_text.empty() ? p.normalized_plain_text
      : !p.normalized_html_text.empty() ? p.normalized_html_text
                                        : p.normalized_text;
  return scrub_body_text(text, p.recipient_tokens);
}
}  // namespace

std::string SpamEngine::scrub_contribution(const std::string& raw_rfc822) const {
  ensure_loaded();
  return representative_scrubbed_text(preprocess_rfc822(raw_rfc822));
}

std::map<uint32_t, float> SpamEngine::extract_contribution(
    const std::string& raw_rfc822,
    const std::string& sender_name,
    const std::string& sender_email,
    uint64_t hash_key) const {
  ensure_loaded();

  // One GMime parse; scrub its representative body, fold sender metadata in
  // exactly as train_rfc822 does, then hash. The text is scrubbed BEFORE
  // hashing, so PII cannot enter the bag the flywheel uploads.
  const auto preprocessed = preprocess_rfc822(raw_rfc822);
  const std::string scrubbed = representative_scrubbed_text(preprocessed);
  if (scrubbed.empty()) { return {};
}

  SenderInfo s{sender_name, sender_email, /*replyto_differs=*/false};
  apply_preprocessed_to_sender(s, preprocessed);
  const auto input = build_input_text(scrubbed, s, ModelInputFormat::kLegacyWrapped);

  std::map<uint32_t, float> bag;
  if (impl_->ftrl) {
    bag = impl_->ftrl->extract_contribution(input.str(), /*sender_email=*/"", hash_key);
  }
  return bag;
}

float SpamEngine::train_embedding(const std::vector<float>& embedding, int correct_label) {
  ensure_loaded();
  if (correct_label < 0 || correct_label > 3) {
    throw std::invalid_argument("correct_label must be in [0, 3]");
  }

  (void)classify_embedding(embedding, true);
  const std::string semantic_label = label_name(correct_label);
  int model_label = impl_->trainable_head->label_index(semantic_label);
  // Compact spam heads intentionally omit the legacy gibberish output. A
  // caller that still supplies the old spam-side gibberish semantic trains the
  // spam row rather than indexing a missing output.
  if (model_label < 0 && correct_label == 0) {
    model_label = impl_->trainable_head->label_index("spam");
  }
  if (model_label < 0) {
    throw std::invalid_argument(
        "correct_label is not represented by this model's label_map");
  }
  const float loss = impl_->trainable_head->backward(model_label);
  impl_->trainable_head->step(1);
  return loss;
}

TrainableClassifierHead* SpamEngine::trainable_head() noexcept {
  return impl_ ? impl_->trainable_head.get() : nullptr;
}

float SpamEngine::head_drift_saturation() const {
  if (!impl_ || !impl_->trainable_head) { return 0.0F;
}
  return impl_->trainable_head->drift_saturation();
}

float SpamEngine::head_relative_drift() const {
  if (!impl_ || !impl_->trainable_head) { return 0.0F;
}
  return impl_->trainable_head->relative_drift();
}

int SpamEngine::head_optimizer_steps() const {
  if (!impl_ || !impl_->trainable_head) { return 0;
}
  return impl_->trainable_head->optimizer_steps();
}

void SpamEngine::save(const std::string& model_path) {
  ensure_loaded();
  const std::string target = model_path.empty() ? config_.model_path : model_path;

  // An explicit save target is a deployable model snapshot, not just a bag of
  // mutable weights. Klar Plus gives us an empty ModelStore staging directory;
  // carry the immutable encoder/config/tokenizer assets over before writing the
  // trained files. Hard links keep the large GGUF cheap. Mutable files are
  // excluded because overwriting a hard link would mutate the currently
  // deployed model and destroy rollback/atomic-promotion semantics.
  if (!model_path.empty() &&
      std::filesystem::weakly_canonical(target) !=
          std::filesystem::weakly_canonical(config_.model_path)) {
    namespace fs = std::filesystem;
    fs::create_directories(target);
    std::string ftrl_basename;
    if (!config_.ftrl_path.empty()) {
      ftrl_basename = fs::path(config_.ftrl_path).filename().string();
    }
    const auto is_mutable = [&](const fs::path& path) {
      const std::string name = path.filename().string();
      const bool classifier_digest = name.size() > 4 && name[0] == '.' &&
          name.rfind(".md5") == name.size() - 4 &&
          name.find("classifier_") != std::string::npos;
      const bool ftrl_digest = !ftrl_basename.empty() &&
          name == "." + ftrl_basename + ".md5";
      return name == "MANIFEST.json" || classifier_digest || ftrl_digest ||
             name == "classifier_dense_weight.bin" ||
             name == "classifier_dense_bias.bin" ||
             name == "classifier_out_proj_weight.bin" ||
             name == "classifier_out_proj_bias.bin" ||
             name.rfind("classifier_anchor_", 0) == 0 ||
             (!ftrl_basename.empty() && name == ftrl_basename);
    };
    // The API also accepts an existing target. Remove mutable artifacts first
    // so a pre-existing hard link cannot turn the following writes into an
    // in-place mutation of the active model, and stale release checksums cannot
    // survive from a prior staging attempt.
    for (const auto& entry : fs::directory_iterator(target)) {
      if (is_mutable(entry.path())) { fs::remove(entry.path());
}
    }
    const auto link_tree = [&](const auto& self, const fs::path& source,
                               const fs::path& destination) -> void {
      if (is_mutable(source)) { return;
}
      if (fs::is_directory(source)) {
        fs::create_directories(destination);
        for (const auto& entry : fs::directory_iterator(source)) {
          self(self, entry.path(), destination / entry.path().filename());
        }
        return;
      }
      if (fs::exists(destination)) { return;
}
      std::error_code ec;
      fs::create_hard_link(source, destination, ec);
      if (ec) { fs::copy_file(source, destination);
}
    };
    for (const auto& entry : fs::directory_iterator(config_.model_path)) {
      link_tree(link_tree, entry.path(), fs::path(target) / entry.path().filename());
    }
  }
  impl_->trainable_head->save(target);

  if (impl_->ftrl && !config_.ftrl_path.empty()) {
    // FTRL was loaded from `<modelDir>/<basename>` (e.g. ftrl_baseline.bin).
    // When the caller passes an explicit save target, write the new weights
    // into <target>/<basename> so the promoted model directory carries the
    // trained FTRL forward. When save is called with no target, keep the
    // in-place behavior used by the head above.
    std::string ftrl_target = config_.ftrl_path;
    if (!model_path.empty()) {
      const auto slash = config_.ftrl_path.find_last_of('/');
      const std::string basename = (slash == std::string::npos)
          ? config_.ftrl_path
          : config_.ftrl_path.substr(slash + 1);
      ftrl_target = target + "/" + basename;
    }
    if (!impl_->ftrl->save(ftrl_target)) {
      throw std::runtime_error("SpamEngine::save: failed to write FTRL weights to " + ftrl_target);
    }
  }
}

void SpamEngine::set_learning_rate(float learning_rate) {
  if (impl_->trainable_head) {
    impl_->trainable_head->set_learning_rate(learning_rate);
  }
  config_.learning_rate = learning_rate;
}

float SpamEngine::learning_rate() const {
  if (impl_->trainable_head) {
    return impl_->trainable_head->get_learning_rate();
  }
  return config_.learning_rate;
}

int SpamEngine::label_from_string(const std::string& label) {
  if (label == "gibberish") { return 0;
}
  if (label == "marketing") { return 1;
}
  if (label == "regular") { return 2;
}
  if (label == "spam") { return 3;
}
  return -1;
}

const char* SpamEngine::label_name(int label) {
  switch (label) {
    case 0: return "gibberish";
    case 1: return "marketing";
    case 2: return "regular";
    case 3: return "spam";
    default: return "unknown";
  }
}

std::string SpamEngine::label_to_string(int label) { return label_name(label); }

}  // namespace spam_engine
