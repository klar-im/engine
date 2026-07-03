#include "spam_engine.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <stdexcept>
#include <utility>
#include <vector>

#include "decision_layer.h"
#include "email_preprocessor.h"
#include "ftrl_classifier.h"
#include "pii_scrub.h"
#include "ggml_encoder.h"
#include "trainable_classifier.h"

namespace spam_engine {

// Parse "Foo Bar <foo@bar.com>" or "foo@bar.com" into (name, email).
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
void apply_preprocessed_to_customer(
    CustomerInfo& customer,
    const PreprocessedEmail& preprocessed) {
  customer.replyto_differs = preprocessed.replyto_differs;
  if (customer.name.empty() && customer.email.empty() && !preprocessed.from.empty()) {
    auto parsed = parse_from_header(preprocessed.from);
    customer.name = std::move(parsed.first);
    customer.email = std::move(parsed.second);
  }
}

// === CalibratedInputText constructor =====================================
//
// `build_input_text` is the ONLY way a CalibratedInputText comes into
// existence. Anyone wanting to feed text to the encoder has to go through
// it, which means the head sees one and only one input shape:
//
//   "User (email): <body>\n[Customer Info:\nName: ...\nEmail: ...]
//    [ReplyToDiffers: yes]\n"
//
// (Optional fields appear only when present so old training distributions
// stay valid until the next retrain teaches the new tokens.)

CalibratedInputText build_input_text(
    const std::vector<TranscriptMessage>& transcript,
    const CustomerInfo& customer) {
  std::string input_text;

  for (const auto& exchange : transcript) {
    std::string from_type = exchange.from_type;
    if (!from_type.empty()) {
      from_type[0] = static_cast<char>(std::toupper(from_type[0]));
    }
    input_text += from_type + " (" + exchange.origin + "): " + exchange.text + "\n";
  }

  // Customer info after message (matches pod-spam format).
  // The block is emitted whenever ANY field is present so the head can
  // learn to look for it consistently.
  const bool has_any_customer_signal =
      !customer.name.empty() || !customer.email.empty() || customer.replyto_differs;
  if (has_any_customer_signal) {
    input_text += "Customer Info:\n";
    if (!customer.name.empty()) input_text += "Name: " + customer.name + "\n";
    if (!customer.email.empty()) input_text += "Email: " + customer.email + "\n";
    // ReplyToDiffers is wire-format-additive: emitted only when true so
    // the absence-vs-false distinction doesn't introduce a new token in
    // the common case. The head learns "presence of this line == suspicious".
    if (customer.replyto_differs) input_text += "ReplyToDiffers: yes\n";
  }

  return CalibratedInputText(std::move(input_text));
}

class SpamEngine::Impl {
 public:
  std::unique_ptr<GgmlEncoder> encoder;
  std::unique_ptr<TrainableClassifierHead> trainable_head;
  std::unique_ptr<FTRLClassifier> ftrl;
};

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

  if (config_.gguf_model_path.empty()) {
    config_.gguf_model_path = config_.model_path + "/gguf/encoder-q4_k_m.gguf";
  }

  // Env-var override for the token cap — A/B knob against a single compiled
  // dylib. The value is validated downstream by GgmlEncoder against
  // [kMinMaxTokens, model->n_ctx_train]; here we only parse and log so an
  // accidental shell leak (CI, dev .envrc) doesn't silently retune production.
  if (const char* env = std::getenv("SPAM_ENGINE_MAX_TOKENS")) {
    try {
      const int parsed = std::stoi(env);
      std::fprintf(stderr,
          "[spam_engine] SPAM_ENGINE_MAX_TOKENS=%s overrides encoder_max_tokens %d -> %d\n",
          env, config_.encoder_max_tokens, parsed);
      config_.encoder_max_tokens = parsed;
    } catch (const std::exception& e) {
      std::fprintf(stderr,
          "[spam_engine] ignoring invalid SPAM_ENGINE_MAX_TOKENS=%s (%s)\n", env, e.what());
    }
  }

  impl_->encoder = std::make_unique<GgmlEncoder>();
  impl_->encoder->load(config_.gguf_model_path, config_.encoder_max_tokens);

  impl_->trainable_head = std::make_unique<TrainableClassifierHead>(
      config_.model_path, config_.learning_rate, config_.l2_lambda, config_.max_grad_norm,
      config_.max_drift);

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
    std::fprintf(stderr,
        "[spam_engine] FTRL baseline load failed for %s; starting cold\n",
        config_.ftrl_path.c_str());
    impl_->ftrl = std::make_unique<FTRLClassifier>();
  }

  loaded_ = true;
}

void SpamEngine::unload() noexcept {
  impl_ = std::make_unique<Impl>();
  loaded_ = false;
}

bool SpamEngine::is_loaded() const noexcept {
  return loaded_;
}

int SpamEngine::n_embd() const noexcept {
  return (loaded_ && impl_->encoder) ? impl_->encoder->n_embd() : 0;
}

void SpamEngine::ensure_loaded() const {
  if (!loaded_ || !impl_->encoder || !impl_->trainable_head) {
    throw std::runtime_error("SpamEngine is not loaded. Call load() first.");
  }
}

std::vector<float> SpamEngine::embed(const CalibratedInputText& input) {
  auto batch_result = embed_batch({input});
  return batch_result.empty() ? std::vector<float>() : std::move(batch_result[0]);
}

std::vector<std::vector<float>> SpamEngine::embed_batch(
    const std::vector<CalibratedInputText>& inputs) {
  ensure_loaded();
  if (inputs.empty()) return {};

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
  const auto probabilities = impl_->trainable_head->softmax(logits);
  if (probabilities.size() != 4) {
    throw std::runtime_error("Unexpected classifier output size");
  }

  return ClassScores{
      probabilities[0],  // gibberish
      probabilities[1],  // marketing
      probabilities[2],  // regular
      probabilities[3],  // spam
  };
}

ClassificationResult SpamEngine::decision_from_scores(const ClassScores& scores) const {
  // Shared with the C-ABI decide-input builder so the binary label the fold reads
  // as "what the model said" is identical across the engine, the C ABI, and Swift
  // (TASK-251 C5).
  const decision::NeuralDecision nd = decision::neural_decision(
      {scores.gibberish, scores.marketing, scores.regular, scores.spam});
  return ClassificationResult{nd.label, static_cast<float>(nd.confidence), scores,
                              "neural", -1.0f};
}

namespace {
// classify mode is a required, validated choice — no silent "auto" (TASK-219).
void validate_mode(const std::string& mode) {
  if (mode != "ensemble" && mode != "neural" && mode != "ftrl") {
    throw std::invalid_argument(
        "ClassifyOptions.mode must be \"ensemble\", \"neural\", or \"ftrl\" (got \"" +
        mode + "\")");
  }
}
}  // namespace

ClassificationResult SpamEngine::combine_scores(
    const ClassScores& neural, float ftrl_score, const std::string& mode) const {
  if (mode == "ftrl") {
    // FTRL-only diagnostic path; neural was not run. Cold/absent FTRL
    // (ftrl_score < 0) degrades to a low-confidence "regular".
    if (ftrl_score < 0.0f) {
      return ClassificationResult{"regular", 0.0f, {}, "ftrl", ftrl_score};
    }
    const bool is_spam = ftrl_score >= 0.5f;
    return ClassificationResult{
        is_spam ? "spam" : "regular",
        is_spam ? ftrl_score : 1.0f - ftrl_score,
        {0.0f, 0.0f, 1.0f - ftrl_score, ftrl_score},
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
  // cold model's blanket downward vote. See pythonDiscovery measure_escalate_only.py.
  ClassScores scores = neural;
  std::string decided_by = "neural";
  if (mode == "ensemble" && ftrl_score >= 0.0f) {
    const float w = config_.ftrl_ensemble_weight;
    const float blend = w * ftrl_score + (1.0f - w) * neural.spam;
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
  return classify_transcript(
      {{"user", text, "email"}},
      CustomerInfo{sender_name, sender_email, /*replyto_differs=*/false},
      options);
}

ClassificationResult SpamEngine::classify_rfc822(
    const std::string& raw_rfc822,
    const std::string& sender_name,
    const std::string& sender_email,
    const ClassifyOptions& options) {
  auto preprocessed = preprocess_rfc822(raw_rfc822);

  CustomerInfo customer{sender_name, sender_email, /*replyto_differs=*/false};
  apply_preprocessed_to_customer(customer, preprocessed);

  // The decision logic has several early returns; run it through a lambda so we
  // can stamp the structural features (computed during the preprocess parse —
  // TASK-173) onto every result without touching each return site.
  auto result = [&]() -> ClassificationResult {
    validate_mode(options.mode);
    if (!preprocessed.normalized_plain_text.empty() && !preprocessed.normalized_html_text.empty()) {
      // Multipart: wrap each part via the canonical builder so the embeddings
      // we feed classify_embedding() come from the same distribution the head
      // was trained on.
      const auto plain_input = build_input_text(
          {{"user", preprocessed.normalized_plain_text, "email"}}, customer);

      // FTRL P(spam) on the plain body (always present in multipart), unless
      // mode=neural. Only contributes once warm. The bypass is gone: the score
      // is BLENDED into the neural verdict by combine_scores, never overrides it.
      float ftrl_score = -1.0f;
      if (options.mode != "neural" && impl_->ftrl &&
          impl_->ftrl->total_learns() >= config_.ftrl_min_learns) {
        ftrl_score = impl_->ftrl->predict_text(plain_input.str());
      }
      if (options.mode == "ftrl") {
        // FTRL-only: neural never runs, so the html part is never embedded —
        // don't pay to build/wrap it.
        return combine_scores(/*neural=*/{}, ftrl_score, options.mode);
      }
      const auto html_input = build_input_text(
          {{"user", preprocessed.normalized_html_text, "email"}}, customer);
      const auto embeddings = embed_batch({plain_input, html_input});
      const auto plain_scores = classify_embedding(embeddings[0], false);
      const auto html_scores = classify_embedding(embeddings[1], false);
      const auto& best_scores = (html_scores.spam > plain_scores.spam) ? html_scores : plain_scores;
      return combine_scores(best_scores, ftrl_score, options.mode);
    }

    // Single-part: pick the most informative body and route through
    // classify_transcript so we still get FTRL ensembling.
    const std::string& body = !preprocessed.normalized_plain_text.empty()
        ? preprocessed.normalized_plain_text
        : !preprocessed.normalized_html_text.empty()
            ? preprocessed.normalized_html_text
            : preprocessed.normalized_text;
    return classify_transcript({{"user", body, "email"}}, customer, options);
  }();

  // preprocessed is a local that dies here; move the feature strings out rather
  // than copy them (the lambda above already consumed its normalized text).
  result.thread_features = std::move(preprocessed.thread_features);
  result.auth_features = std::move(preprocessed.auth_features);
  return result;
}

ClassificationResult SpamEngine::classify_transcript(
    const std::vector<TranscriptMessage>& transcript,
    const CustomerInfo& customer,
    const ClassifyOptions& options) {
  validate_mode(options.mode);
  const auto input_text = build_input_text(transcript, customer);

  // FTRL P(spam), unless mode=neural. Only contributes once warm
  // (total_learns >= ftrl_min_learns); a cold baseline stays at -1 and the
  // ensemble cleanly falls back to pure neural.
  float ftrl_score = -1.0f;
  if (options.mode != "neural" && impl_->ftrl &&
      impl_->ftrl->total_learns() >= config_.ftrl_min_learns) {
    ftrl_score = impl_->ftrl->predict_text(input_text.str());
  }

  // mode=ftrl skips the (expensive) neural forward pass entirely.
  ClassScores neural{};
  if (options.mode != "ftrl") {
    neural = classify_embedding(embed(input_text), false);
  }
  return combine_scores(neural, ftrl_score, options.mode);
}

float SpamEngine::train(const CalibratedInputText& input, int correct_label) {
  // FTRL learns from the same canonical-shape string the neural head
  // sees, so the train/inference token bag stays consistent with
  // classify_transcript's predict_text path.
  if (impl_->ftrl) {
    const bool is_spam = (correct_label == 0 || correct_label == 3);
    impl_->ftrl->learn_text(input.str(), is_spam);
  }
  return train_embedding(embed(input), correct_label);
}

float SpamEngine::train_rfc822(const std::string& raw_rfc822,
                               const CustomerInfo& customer,
                               int correct_label) {
  // Mirror classify_rfc822 exactly: multipart trains on both plain and
  // html parts wrapped via the canonical builder; single-part trains on
  // whichever body the preprocessor produced. The CalibratedInputText
  // type makes "wrap before embed" structurally enforced — there's no
  // way to skip it.
  const auto preprocessed = preprocess_rfc822(raw_rfc822);

  CustomerInfo c = customer;
  apply_preprocessed_to_customer(c, preprocessed);

  std::vector<CalibratedInputText> inputs;
  if (!preprocessed.normalized_plain_text.empty()) {
    inputs.push_back(build_input_text(
        {{"user", preprocessed.normalized_plain_text, "email"}}, c));
  }
  if (!preprocessed.normalized_html_text.empty() &&
      preprocessed.normalized_html_text != preprocessed.normalized_plain_text) {
    inputs.push_back(build_input_text(
        {{"user", preprocessed.normalized_html_text, "email"}}, c));
  }
  if (inputs.empty() && !preprocessed.normalized_text.empty()) {
    inputs.push_back(build_input_text(
        {{"user", preprocessed.normalized_text, "email"}}, c));
  }
  if (inputs.empty()) {
    throw std::runtime_error("No trainable RFC822 text extracted");
  }

  float loss_sum = 0.0f;
  for (const auto& input : inputs) {
    loss_sum += train(input, correct_label);
  }
  return loss_sum / static_cast<float>(inputs.size());
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
  if (scrubbed.empty()) return {};

  CustomerInfo c{sender_name, sender_email, /*replyto_differs=*/false};
  apply_preprocessed_to_customer(c, preprocessed);
  const auto input = build_input_text({{"user", scrubbed, "email"}}, c);

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
  const float loss = impl_->trainable_head->backward(correct_label);
  impl_->trainable_head->step(1);
  return loss;
}

void SpamEngine::save(const std::string& model_path) {
  ensure_loaded();
  const std::string target = model_path.empty() ? config_.model_path : model_path;
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
    impl_->ftrl->save(ftrl_target);
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
  if (label == "gibberish") return 0;
  if (label == "marketing") return 1;
  if (label == "regular") return 2;
  if (label == "spam") return 3;
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
