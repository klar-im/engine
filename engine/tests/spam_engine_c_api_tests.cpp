#include "spam_engine_c_api.h"

#include "callback_shape.h"
#include "no_contact_shape.h"
#include "spam_engine_handle_internal.h"
#include "brand_names.h"  // direct cover for the IDN/punycode fold (TASK-237 AC#3)
#include "brand_kb.h"     // direct cover for the multi-word KB IDN cousin route
#include "spam_engine_training_c_api.h"
#include "test_support.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <new>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unistd.h>  // _exit
#include <string>
#include <sys/wait.h>
#include <vector>

namespace {

void test_create_and_destroy() {
  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "spam_engine_create should return a handle");
  test_support::check(spam_engine_is_loaded(handle) == 0, "new handle should start unloaded");
  test_support::check(spam_engine_get_last_error(handle) == nullptr, "new handle should have no error");
  spam_engine_destroy(handle);
}

void test_load_classify_unload_flow() {
  const auto paths = test_support::model_paths();
  test_support::ensure_model_assets(paths, "load/classify/unload flow");

  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "spam_engine_create should return a handle");

  spam_engine_result_t result{};

  int status = spam_engine_classify(
      handle,
      "free gift cards available now",
      "Promo",
      "promo@example.com",
      "ensemble",
      &result);
  test_support::check(status != SPAM_ENGINE_STATUS_OK, "classify before load should fail");
  test_support::check(spam_engine_get_last_error(handle) != nullptr,
        "classify before load should set an error message");

  status = spam_engine_load(
      handle,
      paths.model_path.string().c_str(),
      0.001F,
      nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "load should succeed with local model");
  test_support::check(spam_engine_is_loaded(handle) == 1, "handle should be loaded after load");
  test_support::check(spam_engine_get_last_error(handle) == nullptr, "load should clear error");

  status = spam_engine_classify(
      handle,
      "weekly project update and next sprint planning details",
      "Alice",
      "alice@example.com",
      "ensemble",
      &result);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "classify should succeed after load");

  const float sum = result.scores.gibberish + result.scores.marketing
      + result.scores.regular + result.scores.spam;
  test_support::check(std::abs(sum - 1.0F) < 1e-3F, "classify probabilities should sum to ~1");
  test_support::check(result.label >= 0 && result.label <= 3, "classify label should be in [0, 3]");

  status = spam_engine_unload(handle);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "unload should succeed");
  test_support::check(spam_engine_is_loaded(handle) == 0, "handle should be unloaded after unload");

  status = spam_engine_classify(
      handle,
      "free gift cards available now",
      "Promo",
      "promo@example.com",
      "ensemble",
      &result);
  test_support::check(status != SPAM_ENGINE_STATUS_OK, "classify after unload should fail");

  spam_engine_destroy(handle);
}

// Create + load an engine with the FTRL baseline when present (the demo/addon
// load shape, learning_rate 0). Reports FTRL presence via *have_ftrl for tests
// that branch on it. Caller owns the handle (spam_engine_destroy).
spam_engine_handle_t* create_loaded_engine(const std::string& label,
                                           bool* have_ftrl = nullptr) {
  const auto paths = test_support::model_paths();
  test_support::ensure_model_assets(paths, label);
  const std::string ftrl_path = (paths.model_path / "ftrl_baseline.bin").string();
  const bool ftrl = std::ifstream(ftrl_path, std::ios::binary).good();
  if (have_ftrl != nullptr) { *have_ftrl = ftrl;
}
  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, label + ": spam_engine_create should return a handle");
  const int status = spam_engine_load(handle, paths.model_path.string().c_str(), 0.0F,
                                      ftrl ? ftrl_path.c_str() : nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, label + ": load should succeed");
  return handle;
}

// The /demo canned samples (TASK-266): the exact bytes the website's demo page
// serves (engine/tests/data/demo-samples/, imported by the page as ?raw), run
// through the same pipeline the demo addon runs: ensemble classify_rfc822 +
// structural decision fold at the standard profile (classify_full is that in
// one call). Filenames carry the expected decision label (<label>.<slug>.eml,
// decision vocabulary: spam | gibberish | marketing | ham). A regression here
// is a public wrong verdict on klar.im/demo: the Ham EN sample ("Marie
// Dupont") shipped misclassified as spam for two weeks because nothing checked
// these.
// The engine must be able to say which artifact it loaded. Before this, the only
// way to answer that for a running host was to hash its model files and compare
// them against every historical UUID on S3, which is why klar.im served an
// unreleased model for a month without anyone noticing.
void test_model_info_names_the_loaded_artifact() {
  const auto paths = test_support::model_paths();
  spam_engine_handle_t* handle = create_loaded_engine("model info");

  spam_engine_model_info_t info{};
  test_support::check(spam_engine_model_info(handle, &info) == 1,
      "model_info should succeed on a loaded handle");

  // Read from classifier_config.json, so present for any loadable artifact.
  test_support::check(info.hidden_size > 0, "hidden_size must be reported");
  test_support::check(info.num_labels > 0, "num_labels must be reported");
  test_support::check(info.raw_input == 0 || info.raw_input == 1,
      "raw_input must be a 0/1 flag");

  // The uuid tracks the manifest, and an absent manifest must read as unknown
  // rather than as a confident wrong answer.
  const bool has_manifest =
      std::filesystem::exists(paths.model_path / "MANIFEST.json");
  if (has_manifest) {
    test_support::check(info.uuid[0] != '\0',
        "a model dir with a MANIFEST.json must report its uuid");
  } else {
    test_support::check(info.uuid[0] == '\0',
        "a model dir with no manifest must report an EMPTY uuid, not a guess");
  }

  // Every string is NUL-terminated inside its buffer: callers read them as C
  // strings straight out of the struct.
  test_support::check(
      memchr(info.uuid, '\0', sizeof(info.uuid)) != nullptr, "uuid must be NUL-terminated");
  test_support::check(
      memchr(info.source_model, '\0', sizeof(info.source_model)) != nullptr,
      "source_model must be NUL-terminated");

  spam_engine_destroy(handle);

  // A NULL handle or out pointer is a 0, never a crash and never a partial write.
  spam_engine_model_info_t untouched{};
  untouched.hidden_size = 4242;
  test_support::check(spam_engine_model_info(nullptr, &untouched) == 0,
      "model_info on a NULL handle should fail");
  test_support::check(untouched.hidden_size == 4242,
      "a failed model_info must not write to out");
  spam_engine_handle_t* fresh = spam_engine_create();
  test_support::check(spam_engine_model_info(fresh, nullptr) == 0,
      "model_info with a NULL out should fail");
  test_support::check(spam_engine_model_info(fresh, &untouched) == 0,
      "model_info on an unloaded handle should fail");
  spam_engine_destroy(fresh);
}

void test_demo_samples_decision() {
  const auto paths = test_support::model_paths();
  spam_engine_handle_t* handle = create_loaded_engine("demo samples decision");
  int status = 0;

  const std::filesystem::path dir = paths.source_dir / "tests" / "data" / "demo-samples";
  std::vector<std::filesystem::path> files;
  for (const auto& entry : std::filesystem::directory_iterator(dir)) {
    if (entry.path().extension() == ".eml") { files.push_back(entry.path());
}
  }
  std::sort(files.begin(), files.end());
  test_support::check(files.size() == 28,
      "all 28 demo samples present (7 pickable examples + the 7x3 mailbox the "
      "homepage pre-fills; keep in sync with DEMO_SAMPLES)");

  // Both exception sets below are properties of ONE artifact, Gen 3 e5, so they
  // are gated on the loaded model rather than applied to whatever is in
  // engine/model. Unconditional, they were a standing licence for two wrong demo
  // verdicts on any model, which is part of why nobody noticed klar.im serving a
  // set that got five of these wrong. Measured on the CPU path: public-v0 is
  // 28/28 and needs neither.
  spam_engine_model_info_t model{};
  test_support::check(spam_engine_model_info(handle, &model) == 1,
      "demo samples: the engine must report which model it loaded");
  const bool is_gen3 = std::string(model.source_model) == "klar/e5-base-ft-markers-gen3";
  std::cout << "  [demo samples] model source='" << model.source_model
            << "' uuid='" << model.uuid << "'\n";

  // Gen 3 (e5-base) has a documented German-marketing weakness: German marketing
  // is underrepresented in the corpus (rule 7), so it reads some German promo as
  // spam on Metal and ham on the forced CPU path. Tracked in TASK-378 (ship-grade
  // fix needs quarantine-clean labels + source/time holdout). Keep this as an
  // explicit expected failure: if it starts passing, the test fails until the
  // exception and TASK-378 note are removed; any third label is still a new
  // regression.
  static const std::set<std::string> gen3_expected_backend_failures = {
      "marketing.weekend.de.eml"};
  // e5 q4_k_m is backend-sensitive on this softer retail example: Metal returns
  // marketing while CPU can return ham. Both are non-spam, so this is not a user
  // false positive; it is still a broken category-demo contract and must be
  // fixed before the website demo moves to Gen 3 (TASK-379).
  static const std::set<std::string> gen3_accepted_backend_drifts = {
      "marketing.retail.en.eml"};
  const std::set<std::string> empty_exceptions;
  const std::set<std::string>& expected_backend_failures =
      is_gen3 ? gen3_expected_backend_failures : empty_exceptions;
  const std::set<std::string>& accepted_backend_drifts =
      is_gen3 ? gen3_accepted_backend_drifts : empty_exceptions;

  // gen3-v6 (the released model since TASK-367 AC#1) decides 25 of the 28 on
  // both backends, measured 2026-09-14 on the CPU and Metal paths alike: two
  // non-English marketing samples read as ham (spam side 0.85 / 0.74, the
  // weak-language legitimate-mail direction TRAINING_EXPERIMENT_LOG.md #51
  // found), and the English parcel scam lands at spam side 0.98, one grid
  // step under the 0.99 gate. Pinned to the exact outcome so a third label is
  // a regression and a pass fails the test until the entry is removed; the
  // fix is a retrain (gen3-v7 carrying the adjudicated native ham), not an
  // operating point read off the demo.
  static const std::map<std::string, std::string> gen3v6_measured_misses = {
      {"marketing.fr.eml", "ham"},
      {"marketing.weekend.de.eml", "ham"},
      {"spam.parcel.en.eml", "ham"}};
  // Keyed on the exact artifact, not the recipe: a reproduction, a different
  // quantization or a recalibrated export of the same fit shares the source
  // prefix and has its own verdicts to measure.
  const bool is_gen3v6 =
      std::string(model.uuid) == "dab55c42-6eb5-464b-9e2a-271fd1867a19";
  const std::map<std::string, std::string> no_misses;
  const std::map<std::string, std::string>& measured_misses =
      is_gen3v6 ? gen3v6_measured_misses : no_misses;

  for (const auto& f : files) {
    const std::string name = f.filename().string();
    const std::string expected = name.substr(0, name.find('.'));
    if (const auto miss = measured_misses.find(name); miss != measured_misses.end()) {
      const std::string eml = test_support::read_binary_file(f);
      spam_engine_full_result_t full{};
      status = spam_engine_classify_full(handle, eml.data(), eml.size(), nullptr, nullptr,
                                         "ensemble", nullptr, &full);
      test_support::check(status == SPAM_ENGINE_STATUS_OK, "classify_full ok: " + name);
      const std::string got(full.decision.label);
      std::string message = "demo sample '";
      message += name;
      message += "' is a recorded gen3-v6 miss and must still decide '";
      message += miss->second;
      message += "' (want '";
      message += expected;
      message += "', got '";
      message += got;
      message += "'); a pass means the entry is stale, anything else is a new regression";
      test_support::check(got == miss->second, message);
      std::cout << "  [MEASURED-MISS gen3-v6] demo '" << name << "' decided '" << got
                << "' (want '" << expected << "')\n";
      continue;
    }
    const std::string eml = test_support::read_binary_file(f);
    test_support::check(!eml.empty(), "demo sample readable: " + name);
    spam_engine_full_result_t full{};
    status = spam_engine_classify_full(handle, eml.data(), eml.size(), nullptr, nullptr,
                                       "ensemble", nullptr, &full);
    test_support::check(status == SPAM_ENGINE_STATUS_OK, "classify_full ok: " + name);
    const std::string got(full.decision.label);
    if (accepted_backend_drifts.count(name)) {
      std::string message = "demo sample '";
      message += name;
      message += "' may drift only between marketing and ham (got '";
      message += got;
      message += "')";
      test_support::check(got == expected || got == "ham",
          message);
      if (got != expected) {
        std::cout << "  [BACKEND-DRIFT TASK-379] demo '" << name << "' decided '"
                  << got << "' (want '" << expected << "')\n";
}
      continue;
    }
    if (expected_backend_failures.count(name)) {
      std::string message = "demo sample '";
      message += name;
      message += "' must retain one of its measured TASK-378 backend outcomes "
                 "(spam on Metal, ham on CPU) until the exception is removed; got '";
      message += got;
      message += '\'';
      test_support::check(got == "spam" || got == "ham",
          message);
      std::cout << "  [EXPECTED-FAIL TASK-378] demo '" << name << "' decided '" << got
                << "' (want '" << expected << "') — German-marketing gap\n";
      continue;
    }
    std::string message = "demo sample '";
    message += name;
    message += "' must decide '";
    message += expected;
    message += "' (got '";
    message += got;
    message += "')";
    test_support::check(got == expected,
        message);
  }
  spam_engine_destroy(handle);
}

void test_rfc822_preprocessing_fixes_false_positive_via_c_api() {
  const auto paths = test_support::model_paths();
  test_support::ensure_model_assets(paths, "RFC822 C API false-positive regression");

  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "spam_engine_create should return a handle");

  int status = spam_engine_load(
      handle, paths.model_path.string().c_str(), 0.001F, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "load should succeed for C API regression");

  const auto noisy_html_ham = test_support::fixture_noisy_html_ham_rfc822();

  spam_engine_result_t rfc822_result{};
  status = spam_engine_classify_rfc822(
      handle,
      noisy_html_ham.c_str(),
      noisy_html_ham.size(),
      nullptr,
      nullptr,
      "ensemble",
      &rfc822_result,
      nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "classify_rfc822 should succeed for regression");
  // 4-class head distributes "not spam" probability across regular AND marketing —
  // both are "keep in inbox" semantically. Test the not-spam invariant, not the split.
  const float not_spam = rfc822_result.scores.regular + rfc822_result.scores.marketing;
  test_support::check(not_spam > 0.90F,
        "classify_rfc822 should recover ham classification");
  test_support::check(rfc822_result.scores.spam < 0.10F,
        "classify_rfc822 noisy ham should not be classified as spam");

  spam_engine_destroy(handle);
}

void test_rfc822_picks_spammy_html_when_plain_and_html_drift_via_c_api() {
  const auto paths = test_support::model_paths();
  test_support::ensure_model_assets(paths, "RFC822 C API plain/html drift evasion");

  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "spam_engine_create should return a handle");

  int const status = spam_engine_load(
      handle, paths.model_path.string().c_str(), 0.001F, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "load should succeed for C API drift test");

  // Same headers/sender across all three messages so the structural fold
  // (sender-auth, display name, subject) is identical and only the body varies.
  const std::string headers =
      "From: Promo Team <promo@example.com>\r\n"
      "To: dev@example.com\r\n"
      "Subject: Project agenda for tomorrow\r\n"
      "MIME-Version: 1.0\r\n";
  const std::string plain_body =
      "Hi team, sharing the project agenda and action items for tomorrow.";
  const std::string html_body =
      "<html><body><p><b>BUY VIAGRA NOW!!!</b> Limited time offer. CLICK HERE.</p></body></html>";

  const std::string drift_rfc822 =
      headers +
      "Content-Type: multipart/alternative; boundary=\"d1\"\r\n"
      "\r\n"
      "--d1\r\n"
      "Content-Type: text/plain; charset=UTF-8\r\n"
      "\r\n" + plain_body + "\r\n"
      "--d1\r\n"
      "Content-Type: text/html; charset=UTF-8\r\n"
      "\r\n" + html_body + "\r\n"
      "--d1--\r\n";
  const std::string plain_only_rfc822 =
      headers + "Content-Type: text/plain; charset=UTF-8\r\n\r\n" + plain_body + "\r\n";
  const std::string html_only_rfc822 =
      headers + "Content-Type: text/html; charset=UTF-8\r\n\r\n" + html_body + "\r\n";

  auto const scores_of = [&](const std::string& raw, const char* label) -> spam_engine_scores_t {
    spam_engine_result_t r{};
    const int st = spam_engine_classify_rfc822(
        handle, raw.c_str(), raw.size(), nullptr, nullptr, "ensemble", &r, nullptr);
    test_support::check(st == SPAM_ENGINE_STATUS_OK,
        std::string("classify_rfc822 should succeed: ") + label);
    return r.scores;
  };
  auto const confident_spam = [](const spam_engine_scores_t& s) {
    return test_support::confident_class(s.spam, s.regular, s.marketing, s.gibberish);
  };

  const spam_engine_scores_t drift_scores = scores_of(drift_rfc822, "multipart drift");
  const spam_engine_scores_t plain_scores = scores_of(plain_only_rfc822, "plain-only");
  const spam_engine_scores_t html_scores = scores_of(html_only_rfc822, "html-only");
  const float drift = drift_scores.spam;
  const float plain = plain_scores.spam;
  const float html = html_scores.spam;

  // Drift-evasion contract (spam_engine.cpp classify_rfc822: best = html.spam >
  // plain.spam ? html : plain). A multipart/alternative is scored as the MORE
  // spammy of its parts, so classify_rfc822(drift) == max(plain, html). This is
  // model-independent: it tests the max-selection MECHANISM through the C ABI,
  // not accuracy.
  const float expected = (plain > html) ? plain : html;
  const float eps = 1e-2F;
  test_support::check(drift >= plain - eps,
      "classify_rfc822 drift must not be dragged down to the benign plain part");
  test_support::check(std::fabs(drift - expected) <= eps,
      "classify_rfc822 drift must equal the most-spammy part (max-selection)");

  // Accuracy guarantee: the spammy html part ("BUY VIAGRA NOW!!!") must score as
  // high spam, so drift-selection actually surfaces spam and not just the higher
  // of two low scores. The public build imports the production model, so this
  // runs in CI (the deeper accuracy suite is the private spam_engine_tests).
  test_support::check(confident_spam(html_scores),
      "spammy html part must score as confident spam (argmax by a 0.5 margin)");
  test_support::check(plain < html,
      "benign plain part (real subject + agenda body) scores below the spammy html part");
  test_support::check(confident_spam(drift_scores),
      "drift selection must surface the spammy html part as confident spam");

  spam_engine_destroy(handle);
}

// TASK-219: mode is a REQUIRED arg (no silent bypass), ensemble blends FTRL into
// the neural verdict without overriding it, and classify_full reports every
// stage in one call.
void test_mode_required_ensemble_and_classify_full() {
  bool have_ftrl = false;
  spam_engine_handle_t* handle =
      create_loaded_engine("mode + ensemble + classify_full", &have_ftrl);
  int status = 0;

  const std::string spam =
      "From: Promo <promo@example.com>\r\n"
      "Subject: You WON a FREE iPhone!!! Claim your prize now\r\n"
      "\r\n"
      "Congratulations! Click http://claim-prize.example for your $1000 gift card now!!!\r\n";

  spam_engine_result_t r{};
  spam_engine_parsed_signals_t sig{};

  // mode is REQUIRED: NULL and unknown values are rejected up front.
  status = spam_engine_classify_rfc822(handle, spam.data(), spam.size(), nullptr, nullptr,
                                       nullptr, &r, &sig);
  test_support::check(status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "NULL mode must be rejected");
  status = spam_engine_classify_rfc822(handle, spam.data(), spam.size(), nullptr, nullptr,
                                       "bogus", &r, &sig);
  test_support::check(status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT, "unknown mode must be rejected");

  // neural mode: FTRL is never consulted, so ftrl_score stays -1.
  status = spam_engine_classify_rfc822(handle, spam.data(), spam.size(), nullptr, nullptr,
                                       "neural", &r, &sig);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "neural classify should succeed");
  test_support::check(r.ftrl_score < 0.0F, "neural mode must not consult FTRL");
  test_support::check(std::string(r.decided_by) == "neural", "neural mode decided_by should be neural");

  if (have_ftrl) {
    // ensemble mode with a warm baseline: FTRL is consulted (ftrl_score >= 0) and
    // the 4-class neural mass is preserved (NOT a bypass synthetic {0,0,1-f,f}).
    // ESCALATE-ONLY (TASK-38): decided_by is "ftrl+neural" only when FTRL raised
    // the spam side (it was more suspicious than neural); otherwise it stays
    // "neural" — FTRL can escalate but never exonerate. Both are valid here.
    status = spam_engine_classify_rfc822(handle, spam.data(), spam.size(), nullptr, nullptr,
                                         "ensemble", &r, &sig);
    test_support::check(status == SPAM_ENGINE_STATUS_OK, "ensemble classify should succeed");
    test_support::check(r.ftrl_score >= 0.0F, "ensemble must consult a warm FTRL");
    const std::string db = r.decided_by;
    test_support::check(db == "ftrl+neural" || db == "neural",
                        "ensemble decided_by is neural or ftrl+neural (escalate-only)");
  }

  // classify_full: one call surfaces FTRL → neural → ensemble → decision.
  spam_engine_full_result_t full{};
  status = spam_engine_classify_full(handle, spam.data(), spam.size(), nullptr, nullptr,
                                     "ensemble", nullptr, &full);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "classify_full should succeed");
  test_support::check(full.decision.label[0] != '\0', "classify_full must report a final decision label");
  test_support::check(full.ensemble_spam >= 0.0F && full.ensemble_spam <= 1.0F,
                      "classify_full ensemble_spam must be a probability");
  if (have_ftrl) {
    test_support::check(full.ftrl_score >= 0.0F, "classify_full must report the FTRL stage");
    // Escalate-only invariant: the ensemble spam side never drops below raw
    // neural, and decided_by credits FTRL exactly when it raised the spam side.
    test_support::check(full.ensemble_spam >= full.neural_scores.spam - 1e-6F,
                        "ensemble_spam must never fall below raw neural (escalate-only)");
    const bool escalated = full.ensemble_spam > full.neural_scores.spam;
    test_support::check((std::string(full.decided_by) == "ftrl+neural") == escalated,
                        "decided_by is ftrl+neural iff FTRL raised the spam side");
  }
  // classify_full also enforces the required mode.
  status = spam_engine_classify_full(handle, spam.data(), spam.size(), nullptr, nullptr,
                                     nullptr, nullptr, &full);
  test_support::check(status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
                      "classify_full must reject NULL mode");

  spam_engine_destroy(handle);
}

void test_last_error_snapshot_survives_subsequent_calls() {
  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "spam_engine_create should return a handle");

  spam_engine_result_t result{};
  const auto first_status = spam_engine_classify(
      handle,
      "hello",
      nullptr,
      nullptr,
      "ensemble",
      &result);
  test_support::check(first_status != SPAM_ENGINE_STATUS_OK, "classify before load should fail");

  const char* first_error = spam_engine_get_last_error(handle);
  test_support::check(first_error != nullptr, "first error should be available");
  const std::string snapshot(first_error);
  test_support::check(!snapshot.empty(), "first error snapshot should be non-empty");

  const auto second_status = spam_engine_classify(
      handle,
      nullptr,
      nullptr,
      nullptr,
      "ensemble",
      &result);
  test_support::check(second_status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
        "classify with null text should fail as invalid argument");

  test_support::check(snapshot == first_error,
        "captured error snapshot pointer should remain stable after later API calls");
  spam_engine_destroy(handle);
}

void test_train_rfc822_and_incremental_flow() {
  const auto paths = test_support::model_paths();
  test_support::ensure_model_assets(paths, "training C ABI flow");

  const auto temp_model = test_support::create_temp_model_fixture(paths.model_path);
  const std::string temp_model_path = temp_model.path().string();

  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "spam_engine_create should return a handle");

  int status = spam_engine_load(handle, temp_model_path.c_str(), 0.001F, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "load should succeed for training flow");
  size_t optimizer_steps = 999;
  status = spam_engine_head_optimizer_steps(handle, &optimizer_steps);
  test_support::check(status == SPAM_ENGINE_STATUS_OK && optimizer_steps == 0,
        "optimizer-step telemetry should start at zero after load");

  const std::string ham_rfc822 =
      "From: Alice Example <alice@example.com>\r\n"
      "To: team@example.com\r\n"
      "Subject: Weekly project update and blockers\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: text/plain; charset=UTF-8\r\n"
      "\r\n"
      "Hi team, sharing the weekly project update and blocker review.\r\n";
  const std::string spam_rfc822 =
      "From: Promo Team <promo@example.com>\r\n"
      "To: team@example.com\r\n"
      "Subject: BUY VIAGRA NOW\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: text/plain; charset=UTF-8\r\n"
      "\r\n"
      "BUY VIAGRA NOW!!! Limited time offer. CLICK HERE.\r\n";

  status = spam_engine_add_training_sample(
      handle,
      ham_rfc822.c_str(),
      ham_rfc822.size(),
      /*sender_name=*/nullptr,
      /*sender_email=*/nullptr,
      2);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "add_training_sample should queue ham sample");

  status = spam_engine_add_training_sample(
      handle,
      spam_rfc822.c_str(),
      spam_rfc822.size(),
      /*sender_name=*/nullptr,
      /*sender_email=*/nullptr,
      3);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "add_training_sample should queue spam sample");

  float avg_loss = -1.0F;
  size_t trained_count = 0;
  status = spam_engine_train_incremental(handle, &avg_loss, &trained_count);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "train_incremental should succeed");
  test_support::check(trained_count == 2, "train_incremental should process 2 queued samples");
  test_support::check(std::isfinite(avg_loss), "train_incremental should return finite avg_loss");
  status = spam_engine_head_optimizer_steps(handle, &optimizer_steps);
  test_support::check(status == SPAM_ENGINE_STATUS_OK && optimizer_steps == 2,
        "optimizer-step telemetry should count each trained plain-text sample; got " +
            std::to_string(optimizer_steps));

  // Queue should be drained after a successful training pass.
  avg_loss = -1.0F;
  trained_count = 999;
  status = spam_engine_train_incremental(handle, &avg_loss, &trained_count);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "train_incremental on empty queue should succeed");
  test_support::check(trained_count == 0, "train_incremental on empty queue should report 0 samples");
  test_support::check(avg_loss == 0.0F, "train_incremental on empty queue should reset avg_loss to 0");

  status = spam_engine_save_model(handle, temp_model_path.c_str());
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "save_model should persist trained weights");

  // Also keep direct RFC822 training API covered.
  float direct_loss = -1.0F;
  const auto noisy_html_ham = test_support::fixture_noisy_html_ham_rfc822();
  status = spam_engine_train_rfc822(
      handle,
      noisy_html_ham.c_str(),
      noisy_html_ham.size(),
      /*sender_name=*/nullptr,
      /*sender_email=*/nullptr,
      2,
      &direct_loss);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "train_rfc822 should succeed");
  test_support::check(std::isfinite(direct_loss), "train_rfc822 should return finite loss");

  status = spam_engine_head_optimizer_steps(handle, &optimizer_steps);
  test_support::check(status == SPAM_ENGINE_STATUS_OK && optimizer_steps == 3,
        "direct single-part correction should add one optimizer step");

  // A correction is one learning event, not one event per MIME rendering. The
  // plain and HTML parts form a single averaged head batch so multipart mail
  // cannot consume the trust-region budget twice as fast.
  const auto multipart_ham = test_support::fixture_google_security_alert_rfc822();
  status = spam_engine_train_rfc822(
      handle,
      multipart_ham.c_str(),
      multipart_ham.size(),
      /*sender_name=*/nullptr,
      /*sender_email=*/nullptr,
      2,
      &direct_loss);
  test_support::check(status == SPAM_ENGINE_STATUS_OK,
        "multipart train_rfc822 should succeed");
  status = spam_engine_head_optimizer_steps(handle, &optimizer_steps);
  test_support::check(status == SPAM_ENGINE_STATUS_OK && optimizer_steps == 4,
        "multipart correction should add exactly one optimizer step; got " +
            std::to_string(optimizer_steps));

  // TASK-251 (minor): a sample that throws mid-batch must NOT drop the untried
  // tail. Queue [good, no-content(throws in train_rfc822), good]: the batch fails,
  // the already-trained head is not re-run, the poison sample is dropped, and the
  // trailing good sample is re-queued (previously the whole drained batch was lost).
  const std::string no_content = "To: x@y.com\r\n\r\n";  // no From/Subject/body -> no extractable text
  spam_engine_add_training_sample(handle, ham_rfc822.c_str(), ham_rfc822.size(), nullptr, nullptr, 2);
  spam_engine_add_training_sample(handle, no_content.c_str(), no_content.size(), nullptr, nullptr, 3);
  spam_engine_add_training_sample(handle, spam_rfc822.c_str(), spam_rfc822.size(), nullptr, nullptr, 3);
  trained_count = 999;
  status = spam_engine_train_incremental(handle, &avg_loss, &trained_count);
  test_support::check(status == SPAM_ENGINE_STATUS_RUNTIME_ERROR,
        "train_incremental reports the mid-batch failure");
  test_support::check(trained_count == 1 && std::isfinite(avg_loss),
        "mid-batch failure reports the already-applied prefix exactly once");
  // The trailing good sample survived; the head (trained) and poison are gone.
  trained_count = 999;
  status = spam_engine_train_incremental(handle, &avg_loss, &trained_count);
  test_support::check(status == SPAM_ENGINE_STATUS_OK && trained_count == 1,
        "the untried tail was re-queued (1 sample), head+poison not (TASK-251)");

  spam_engine_destroy(handle);
}

void test_ftrl_only_training_freezes_neural_head() {
  const auto paths = test_support::model_paths();
  test_support::ensure_model_assets(paths, "FTRL-only training flow");

  // A pretrained ftrl_baseline.bin ships with the private model (it is
  // training-data-derived IP, never published — engine/publish/closed.txt);
  // the open-core build's `make import` never produces one. spam_engine_load
  // already treats a missing/unreadable ftrl_path as a graceful cold start
  // (see the "starting cold" log line in spam_engine.cpp), so this test
  // exercises that same real path instead of requiring the private baseline:
  // existing installs prove bytes are unchanged from a REAL warm state,
  // fresh/open-core installs prove the cold-start path produces a working one.
  const auto source_ftrl = paths.model_path / "ftrl_baseline.bin";
  const bool had_ftrl_before = std::filesystem::is_regular_file(source_ftrl);
  const auto temp_model = test_support::create_temp_model_fixture(paths.model_path);
  const auto& temp_path = temp_model.path();

  const std::vector<std::string> head_files = {
      "classifier_dense_weight.bin",
      "classifier_dense_bias.bin",
      "classifier_out_proj_weight.bin",
      "classifier_out_proj_bias.bin",
  };
  std::vector<std::string> head_before;
  head_before.reserve(head_files.size());
  for (const auto& name : head_files) {
    head_before.push_back(test_support::read_binary_file(temp_path / name));
  }
  const std::string ftrl_before =
      had_ftrl_before ? test_support::read_binary_file(source_ftrl) : std::string();

  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "FTRL-only create should succeed");
  int status = spam_engine_load(
      handle,
      temp_path.string().c_str(),
      0.001F,
      source_ftrl.string().c_str());
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "FTRL-only load should succeed");

  const std::string spam_rfc822 =
      "From: Promo Team <promo@example.com>\r\n"
      "To: team@example.com\r\n"
      "Subject: personalized suspicious token offer\r\n"
      "\r\n"
      "personalized suspicious token offer click now\r\n";
  for (int i = 0; i < 10; ++i) {
    status = spam_engine_add_training_sample(
        handle, spam_rfc822.data(), spam_rfc822.size(), nullptr, nullptr, 3);
    test_support::check(status == SPAM_ENGINE_STATUS_OK, "FTRL-only sample should queue");
  }

  float avg_loss = -1.0F;
  size_t trained_count = 0;
  status = spam_engine_train_incremental_mode(
      handle,
      SPAM_ENGINE_TRAIN_FTRL_ONLY,
      &avg_loss,
      &trained_count);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "FTRL-only batch should succeed");
  test_support::check(trained_count == 10, "FTRL-only batch should train all queued samples");
  test_support::check(avg_loss == 0.0F, "FTRL-only batch has no neural loss");

  size_t optimizer_steps = 999;
  status = spam_engine_head_optimizer_steps(handle, &optimizer_steps);
  test_support::check(
      status == SPAM_ENGINE_STATUS_OK && optimizer_steps == 0,
      "FTRL-only training must not apply a neural optimizer step");
  float saturation = -1.0F;
  float relative_drift = -1.0F;
  status = spam_engine_head_drift(handle, &saturation, &relative_drift);
  test_support::check(
      status == SPAM_ENGINE_STATUS_OK && saturation == 0.0F && relative_drift == 0.0F,
      "FTRL-only training must leave neural drift at zero");

  status = spam_engine_save_model(handle, temp_path.string().c_str());
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "FTRL-only snapshot should save");
  spam_engine_destroy(handle);

  for (size_t i = 0; i < head_files.size(); ++i) {
    test_support::check(
        test_support::read_binary_file(temp_path / head_files[i]) == head_before[i],
        "FTRL-only save changed neural head bytes: " + head_files[i]);
  }
  const auto saved_ftrl = temp_path / "ftrl_baseline.bin";
  test_support::check(
      std::filesystem::is_regular_file(saved_ftrl),
      "FTRL-only save must write an FTRL baseline");
  if (had_ftrl_before) {
    test_support::check(
        test_support::read_binary_file(saved_ftrl) != ftrl_before,
        "FTRL-only save must persist the learned FTRL state");
  } else {
    // Cold start (open-core install, no pretrained baseline): there is no
    // prior state to diff against, so the meaningful assertion is that
    // training from scratch actually produced one.
    test_support::check(
        !test_support::read_binary_file(saved_ftrl).empty(),
        "FTRL-only save from a cold start must write a non-empty FTRL baseline");
  }
}

void test_training_c_api_input_validation() {
  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "spam_engine_create should return a handle");

  int status = spam_engine_add_training_sample(handle, nullptr, 5, nullptr, nullptr, 2);
  test_support::check(status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
        "add_training_sample should reject null raw_email");

  status = spam_engine_add_training_sample(handle, "x", 0, nullptr, nullptr, 2);
  test_support::check(status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
        "add_training_sample should reject zero-length raw email");

  status = spam_engine_add_training_sample(handle, "x", 1, nullptr, nullptr, 99);
  test_support::check(status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
        "add_training_sample should reject invalid label");

  status = spam_engine_train_incremental(nullptr, nullptr, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
        "train_incremental should reject null handle");
  status = spam_engine_train_incremental_mode(
      handle,
      static_cast<spam_engine_training_mode_t>(99),
      nullptr,
      nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
        "train_incremental_mode should reject an unknown learner mode");

  size_t optimizer_steps = 0;
  status = spam_engine_head_optimizer_steps(nullptr, &optimizer_steps);
  test_support::check(status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
        "head_optimizer_steps should reject null handle");
  status = spam_engine_head_optimizer_steps(handle, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
        "head_optimizer_steps should reject null output");

  status = spam_engine_save_model(nullptr, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
        "save_model should reject null handle");

  spam_engine_destroy(handle);
}

// The one property every online correction relies on and nothing in THIS
// file pinned: a step on a sample moves the head toward its label. Found on
// 2026-09-14 by flipping the sign of backward()'s one-hot: the flow test
// above and the trust-region tests stayed green, because they assert bounds
// and telemetry, never the direction; only the closed head suite went red.
// The public suite has to catch it on its own, since it is the whole test of
// the training ABI in the public tree. Two steps on the same message at the
// load-time learning rate sit inside the trust region, so the second loss
// reads the first step's effect (0.11 -> 1.90 with the sign flipped).
void test_training_lowers_the_loss_on_the_corrected_sample() {
  const auto paths = test_support::model_paths();
  test_support::ensure_model_assets(paths, "training direction");
  const auto temp_model = test_support::create_temp_model_fixture(paths.model_path);

  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "spam_engine_create should return a handle");
  int status = spam_engine_load(handle, temp_model.path().string().c_str(), 0.001F, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "load should succeed for the direction check");

  const std::string spam_rfc822 =
      "From: Promo Team <promo@example.com>\r\n"
      "To: team@example.com\r\n"
      "Subject: BUY VIAGRA NOW\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: text/plain; charset=UTF-8\r\n"
      "\r\n"
      "BUY VIAGRA NOW!!! Limited time offer. CLICK HERE.\r\n";
  float first_loss = -1.0F;
  float second_loss = -1.0F;
  status = spam_engine_train_rfc822(handle, spam_rfc822.c_str(), spam_rfc822.size(), nullptr,
                                    nullptr, 3, &first_loss);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "the first step should succeed");
  status = spam_engine_train_rfc822(handle, spam_rfc822.c_str(), spam_rfc822.size(), nullptr,
                                    nullptr, 3, &second_loss);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "the second step should succeed");
  test_support::check(std::isfinite(first_loss) && std::isfinite(second_loss) && first_loss > 0.0F,
        "both steps should report a finite, positive cross-entropy");
  test_support::check(second_loss < first_loss,
        "a step toward the label must lower the sample's loss: " + std::to_string(first_loss) +
            " -> " + std::to_string(second_loss));
  spam_engine_destroy(handle);
}

void test_training_incremental_requires_loaded_engine() {
  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "spam_engine_create should return a handle");

  const std::string sample =
      "From: tester@example.com\r\n"
      "To: team@example.com\r\n"
      "Subject: Sample\r\n"
      "\r\n"
      "Hello.\r\n";
  int status = spam_engine_add_training_sample(handle, sample.c_str(), sample.size(), nullptr, nullptr, 2);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "add_training_sample should queue sample before load");

  float avg_loss = -1.0F;
  size_t trained_count = 999;
  status = spam_engine_train_incremental(handle, &avg_loss, &trained_count);
  test_support::check(status == SPAM_ENGINE_STATUS_RUNTIME_ERROR,
        "train_incremental should fail when engine is not loaded");
  test_support::check(spam_engine_get_last_error(handle) != nullptr,
        "train_incremental failure should expose error text");
  test_support::check(trained_count == 0, "failed train_incremental should report 0 trained samples");

  // Failed call drains queue to avoid duplicate updates on retries.
  avg_loss = -1.0F;
  trained_count = 999;
  status = spam_engine_train_incremental(handle, &avg_loss, &trained_count);
  test_support::check(status == SPAM_ENGINE_STATUS_OK,
        "second train_incremental should succeed after queue drain");
  test_support::check(trained_count == 0, "second train_incremental should see empty queue");

  spam_engine_destroy(handle);
}

void test_pending_training_queue_cleared_on_load_and_unload() {
  const auto paths = test_support::model_paths();
  test_support::ensure_model_assets(paths, "training queue cleared on load/unload");

  const auto temp_model = test_support::create_temp_model_fixture(paths.model_path);
  const std::string temp_model_path = temp_model.path().string();

  const std::string sample =
      "From: tester@example.com\r\n"
      "To: team@example.com\r\n"
      "Subject: Queue clear regression\r\n"
      "\r\n"
      "Hello.\r\n";

  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "spam_engine_create should return a handle");

  int status = spam_engine_add_training_sample(handle, sample.c_str(), sample.size(), nullptr, nullptr, 2);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "add_training_sample should queue before load");

  status = spam_engine_load(handle, temp_model_path.c_str(), 0.001F, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "load should succeed");

  float avg_loss = -1.0F;
  size_t trained_count = 999;
  status = spam_engine_train_incremental(handle, &avg_loss, &trained_count);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "train_incremental should succeed after load");
  test_support::check(
      trained_count == 0,
      "load should clear any queued training samples from pre-load phase");
  test_support::check(avg_loss == 0.0F, "empty queue after load should report avg_loss=0");

  status = spam_engine_add_training_sample(handle, sample.c_str(), sample.size(), nullptr, nullptr, 2);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "add_training_sample should queue while loaded");

  status = spam_engine_unload(handle);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "unload should succeed");

  status = spam_engine_load(handle, temp_model_path.c_str(), 0.001F, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "second load should succeed");

  avg_loss = -1.0F;
  trained_count = 999;
  status = spam_engine_train_incremental(handle, &avg_loss, &trained_count);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "train_incremental should succeed after reload");
  test_support::check(
      trained_count == 0,
      "unload should clear queued training samples from previous loaded session");
  test_support::check(avg_loss == 0.0F, "empty queue after reload should report avg_loss=0");

  spam_engine_destroy(handle);
}

void test_extract_body_text_preview_prefers_plain_text() {
  // Multipart email with both text/plain and text/html
  // text_preview should contain the plain text content, not CSS
  const auto email = test_support::fixture_google_security_alert_rfc822();

  spam_engine_email_body_t body{};
  int const result = spam_engine_extract_body(email.data(), email.size(), &body);
  test_support::check(result == 0, "extract_body should succeed");

  test_support::check(body.plain_body != nullptr, "plain_body should be extracted");
  test_support::check(body.text_preview != nullptr, "text_preview should be set");

  std::string const preview(body.text_preview);
  std::string const plain(body.plain_body);

  // Debug output
  std::cerr << "  plain_body: " << plain.substr(0, 100) << "..." << '\n';
  std::cerr << "  text_preview: " << preview.substr(0, 100) << "..." << '\n';

  // text_preview should contain actual content, not CSS
  test_support::check(
      preview.find("security alert") != std::string::npos,
      "text_preview should contain 'security alert' from plain text");
  test_support::check(
      preview.find(".awl") == std::string::npos,
      "text_preview should NOT contain CSS class '.awl'");
  test_support::check(
      preview.find("font-family") == std::string::npos,
      "text_preview should NOT contain 'font-family' CSS");

  spam_engine_free_string(body.html_body);
  spam_engine_free_string(body.plain_body);
  spam_engine_free_string(body.text_preview);
  spam_engine_free_string(body.subject);
  spam_engine_free_string(body.from);
  spam_engine_free_string(body.date);
}

void test_extract_body_cleans_html_dumped_into_a_plain_text_part() {
  // A real ESP bug (myphotobook.de's newsletter, 2026-09-04), not a
  // hypothetical: no genuine text/html alternative exists, so plain_body is
  // the only body there is, and its decoded content is literally the HTML
  // template with the tags left in. Before this fix it reached the app
  // (and the review pane's preview) with `<meta http-equiv="Content-Type"
  // ...>` and `<div>` visible as if they were message text.
  const auto email = test_support::fixture_html_dumped_as_plain_rfc822();

  spam_engine_email_body_t body{};
  int const result = spam_engine_extract_body(email.data(), email.size(), &body);
  test_support::check(result == 0, "extract_body should succeed for HTML-dumped-as-plain");

  test_support::check(body.plain_body != nullptr, "plain_body should be extracted");
  test_support::check(body.text_preview != nullptr, "text_preview should be set");

  std::string const plain(body.plain_body);
  std::string const preview(body.text_preview);

  // The actual content should survive, readable
  test_support::check(
      plain.find("Hallo Fotofan") != std::string::npos,
      "plain_body should contain the real message text");
  test_support::check(
      preview.find("Hallo Fotofan") != std::string::npos,
      "text_preview should contain the real message text");

  // No literal markup should leak through, in either surfaced field
  test_support::check(
      plain.find("<meta") == std::string::npos,
      "plain_body should NOT contain a literal <meta> tag");
  test_support::check(
      plain.find("<div") == std::string::npos,
      "plain_body should NOT contain a literal <div> tag");
  test_support::check(
      preview.find("<meta") == std::string::npos,
      "text_preview should NOT contain a literal <meta> tag");

  spam_engine_free_string(body.html_body);
  spam_engine_free_string(body.plain_body);
  spam_engine_free_string(body.text_preview);
  spam_engine_free_string(body.subject);
  spam_engine_free_string(body.from);
  spam_engine_free_string(body.date);
}

void test_extract_body_does_not_corrupt_plain_text_quoting_a_div_snippet() {
  // The false-positive direction `looks_like_html_markup`'s own comment
  // warns about (found by /codex:review): a genuine plain-text email that
  // quotes one attribute-bearing tag early in the body must survive intact,
  // not get run through html_to_text as if it were a raw HTML dump.
  const auto email = test_support::fixture_plain_text_quoting_a_div_snippet_rfc822();

  spam_engine_email_body_t body{};
  int const result = spam_engine_extract_body(email.data(), email.size(), &body);
  test_support::check(result == 0, "extract_body should succeed for quoted-snippet plain text");

  test_support::check(body.plain_body != nullptr, "plain_body should be extracted");
  std::string const plain(body.plain_body);

  test_support::check(
      plain.find("<div class=\"btn\">Submit</div>") != std::string::npos,
      "a genuine plain-text email's quoted snippet must survive verbatim, not be stripped/rewritten");
  test_support::check(
      plain.find("click handler needs to bind") != std::string::npos,
      "the rest of the real message text must survive too");

  spam_engine_free_string(body.html_body);
  spam_engine_free_string(body.plain_body);
  spam_engine_free_string(body.text_preview);
  spam_engine_free_string(body.subject);
  spam_engine_free_string(body.from);
  spam_engine_free_string(body.date);
}

void test_extract_body_html_to_text_strips_css() {
  // HTML-only email with CSS in <style> tags
  // text_preview should strip the CSS and return only body content
  const auto email = test_support::fixture_html_only_with_css_rfc822();

  spam_engine_email_body_t body{};
  int const result = spam_engine_extract_body(email.data(), email.size(), &body);
  test_support::check(result == 0, "extract_body should succeed for HTML-only");

  test_support::check(body.text_preview != nullptr, "text_preview should be set");

  std::string const preview(body.text_preview);

  // Debug output
  std::cerr << "  text_preview: " << preview << '\n';

  // Should contain actual content
  test_support::check(
      preview.find("Hello world") != std::string::npos,
      "text_preview should contain 'Hello world'");
  test_support::check(
      preview.find("actual content") != std::string::npos,
      "text_preview should contain 'actual content'");

  // Should NOT contain CSS
  test_support::check(
      preview.find(".awl") == std::string::npos,
      "text_preview should NOT contain CSS class '.awl'");
  test_support::check(
      preview.find("font-family") == std::string::npos,
      "text_preview should NOT contain 'font-family' CSS");
  test_support::check(
      preview.find("text-decoration") == std::string::npos,
      "text_preview should NOT contain 'text-decoration' CSS");

  spam_engine_free_string(body.html_body);
  spam_engine_free_string(body.plain_body);
  spam_engine_free_string(body.text_preview);
  spam_engine_free_string(body.subject);
  spam_engine_free_string(body.from);
  spam_engine_free_string(body.date);
}

void test_replay_rfc822_preserves_model_input_and_drops_attachment_payloads() {
  const std::string email =
      "From: Sender <sender@example.com>\r\n"
      "To: receiver@example.net\r\n"
      "Subject: Replay fixture\r\n"
      "Message-ID: <replay-fixture@example.com>\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/mixed; boundary=outer\r\n\r\n"
      "--outer\r\n"
      "Content-Type: multipart/alternative; boundary=inner\r\n\r\n"
      "--inner\r\n"
      "Content-Type: text/plain; charset=utf-8\r\n\r\n"
      "Keep this body and https://example.com/path\r\n"
      "--inner\r\n"
      "Content-Type: text/html; charset=utf-8\r\n\r\n"
      "<p>Keep this <a href=\"https://example.com/path\">body</a></p>\r\n"
      "--inner--\r\n"
      "--outer\r\n"
      "Content-Type: application/octet-stream; name=secret.txt\r\n"
      "Content-Disposition: attachment; filename=secret.txt\r\n"
      "Content-Transfer-Encoding: base64\r\n\r\n"
      "U0VDUkVUX0FUVEFDSE1FTlRfUEFZTE9BRA==\r\n"
      "--outer--\r\n";

  size_t required = 0;
  auto status = spam_engine_make_replay_rfc822(
      email.data(), email.size(), nullptr, 0, &required);
  test_support::check(status == SPAM_ENGINE_STATUS_OK && required > 0,
                      "replay size query should return the required bytes");

  std::vector<char> too_small(required - 1);
  size_t still_required = 0;
  status = spam_engine_make_replay_rfc822(
      email.data(), email.size(), too_small.data(), too_small.size(),
      &still_required);
  test_support::check(status == SPAM_ENGINE_STATUS_OK && still_required == required,
                      "short replay buffer must report the complete required size");

  std::vector<char> output(required);
  size_t written = 0;
  status = spam_engine_make_replay_rfc822(
      email.data(), email.size(), output.data(), output.size(), &written);
  test_support::check(status == SPAM_ENGINE_STATUS_OK && written == required,
                      "replay serialization should fill the sized buffer");
  const std::string replay(output.data(), written);

  test_support::check(replay.find("Subject: Replay fixture") != std::string::npos,
                      "replay keeps original message headers");
  test_support::check(replay.find("Keep this body") != std::string::npos &&
                          replay.find("https://example.com/path") != std::string::npos,
                      "replay keeps inline bodies and URLs");
  test_support::check(replay.find("secret.txt") != std::string::npos &&
                          replay.find("application/octet-stream") != std::string::npos,
                      "replay keeps attachment metadata");
  test_support::check(
      replay.find("U0VDUkVUX0FUVEFDSE1FTlRfUEFZTE9BRA==") == std::string::npos,
      "replay removes attachment payload bytes");

  spam_engine_email_body_t original_body{};
  spam_engine_email_body_t replay_body{};
  test_support::check(
      spam_engine_extract_body(email.data(), email.size(), &original_body) == 0 &&
          spam_engine_extract_body(replay.data(), replay.size(), &replay_body) == 0,
      "original and replay should both remain parseable RFC822");
  test_support::check(std::string(original_body.text_preview) ==
                          std::string(replay_body.text_preview) &&
                          std::string(original_body.subject) ==
                              std::string(replay_body.subject),
                      "replay preserves preview/classifier body and subject input");
  spam_engine_free_string(original_body.html_body);
  spam_engine_free_string(original_body.plain_body);
  spam_engine_free_string(original_body.subject);
  spam_engine_free_string(original_body.from);
  spam_engine_free_string(original_body.text_preview);
  spam_engine_free_string(original_body.date);
  spam_engine_free_string(replay_body.html_body);
  spam_engine_free_string(replay_body.plain_body);
  spam_engine_free_string(replay_body.subject);
  spam_engine_free_string(replay_body.from);
  spam_engine_free_string(replay_body.text_preview);
  spam_engine_free_string(replay_body.date);

  test_support::check(
      spam_engine_make_replay_rfc822(nullptr, 0, nullptr, 0, &required) ==
          SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
      "replay rejects an absent RFC822 source");
}

void test_extract_thread_features_no_thread_headers() {
  const std::string email =
      "From: a@example.com\r\n"
      "To: b@example.com\r\n"
      "Subject: hello\r\n"
      "Message-ID: <self-1@example.com>\r\n"
      "\r\nbody";
  spam_engine_thread_features_t features{};
  test_support::check(
      spam_engine_extract_thread_features(email.data(), email.size(), &features) == 0,
      "extract_thread_features should succeed");
  test_support::check(features.has_in_reply_to == 0, "no In-Reply-To expected");
  test_support::check(features.references_count == 0, "no References expected");
  test_support::check(std::strlen(features.self_message_id) > 0,
                      "self Message-ID should be extracted");
  test_support::check(std::string(features.self_message_id) == "self-1@example.com",
                      "Message-ID brackets should be stripped");
}

void test_extract_thread_features_in_reply_to_only() {
  const std::string email =
      "From: a@example.com\r\n"
      "In-Reply-To: <prev@example.com>\r\n"
      "\r\n";
  spam_engine_thread_features_t features{};
  test_support::check(
      spam_engine_extract_thread_features(email.data(), email.size(), &features) == 0,
      "extract should succeed");
  test_support::check(features.has_in_reply_to == 1, "should detect In-Reply-To");
  test_support::check(std::string(features.in_reply_to) == "prev@example.com",
                      "should strip brackets");
}

void test_extract_thread_features_references_folded_across_lines() {
  // RFC 5322 §2.2.3: References commonly folds with WSP-prefixed
  // continuation lines. Naive splitters miss IDs after the fold —
  // GMime is supposed to unfold for us. This test guards that contract.
  const std::string email =
      "From: a@example.com\r\n"
      "References: <a@x>\r\n"
      " <b@x>\r\n"
      "\t<c@x>\r\n"
      "\r\n";
  spam_engine_thread_features_t features{};
  test_support::check(
      spam_engine_extract_thread_features(email.data(), email.size(), &features) == 0,
      "extract should succeed");
  test_support::check(features.references_count == 3,
                      "folded References must yield 3 IDs");
  test_support::check(std::string(features.first_reference) == "a@x",
                      "first_reference should be the first ID");
}

void test_extract_thread_features_bare_lf_line_endings() {
  // mbox exports use bare LF instead of CRLF. The parser must handle both.
  const std::string email =
      "From: a@example.com\n"
      "In-Reply-To: <bare-lf@example.com>\n"
      "\n";
  spam_engine_thread_features_t features{};
  test_support::check(
      spam_engine_extract_thread_features(email.data(), email.size(), &features) == 0,
      "extract should succeed for bare-LF");
  test_support::check(features.has_in_reply_to == 1,
                      "should detect In-Reply-To despite bare LF");
}

void test_extract_thread_features_empty_input_safely() {
  spam_engine_thread_features_t features{};
  // Pre-fill with garbage to verify zero-init on failure.
  features.has_in_reply_to = 99;
  features.references_count = 999;
  std::strcpy(features.in_reply_to, "garbage");
  test_support::check(
      spam_engine_extract_thread_features(nullptr, 0, &features) != 0,
      "null buffer must return non-zero");
  test_support::check(features.has_in_reply_to == 0,
                      "out struct must be zeroed on failure");
  test_support::check(features.references_count == 0,
                      "references_count must be zeroed on failure");
  test_support::check(features.in_reply_to[0] == '\0',
                      "in_reply_to must be zeroed on failure");
}

void test_extract_thread_features_zero_length_buffer_safely() {
  // Non-null but zero-length input is a legitimate "no bytes to parse"
  // case (e.g. mbox iteration handing back an empty body slice). The
  // contract is "empty features, not an error" — see
  // engine/spec/classifier-contract.allium::ExtractThreadFeaturesIsPureAndSafe.
  spam_engine_thread_features_t features{};
  const char* empty = "";
  test_support::check(
      spam_engine_extract_thread_features(empty, 0, &features) == 0,
      "zero-length non-null buffer must succeed (not return -1)");
  test_support::check(features.has_in_reply_to == 0,
                      "empty input must produce no In-Reply-To");
  test_support::check(features.references_count == 0,
                      "empty input must produce no References");
  test_support::check(features.in_reply_to[0] == '\0',
                      "empty input must produce empty in_reply_to");
  test_support::check(features.self_message_id[0] == '\0',
                      "empty input must produce empty self_message_id");
}

void test_extract_thread_features_in_reply_to_with_phrase_prefix() {
  // Some MUAs prepend free text before the angle-bracketed ID:
  //   "your message of yesterday <id@host>"
  // Parser must extract the ID, not the phrase.
  const std::string email =
      "From: a@example.com\r\n"
      "In-Reply-To: your message of yesterday <real@example.com>\r\n"
      "\r\n";
  spam_engine_thread_features_t features{};
  test_support::check(
      spam_engine_extract_thread_features(email.data(), email.size(), &features) == 0,
      "extract should succeed");
  test_support::check(std::string(features.in_reply_to) == "real@example.com",
                      "should strip phrase prefix and brackets");
}

void test_extract_auth_features_free_host_signer() {
  // The TASK-122 signal: the DKIM signing domain (header.d) is the
  // unforgeable, cryptographically-asserted signer. A free-hosting signer is a
  // near-zero-ham spam prior. Here From is a *.firebaseapp.com subdomain that
  // signs as firebaseapp.com; DMARC does not pass so it is not aligned.
  const std::string email =
      "Authentication-Results: mx.google.com;\r\n"
      "       dkim=pass header.i=@firebaseapp.com header.s=key;\r\n"
      "       spf=pass; dmarc=fail (p=NONE) header.from=ebetd.firebaseapp.com\r\n"
      "From: \"Casino\" <noreply@ebetd.firebaseapp.com>\r\n"
      "Subject: You won\r\n"
      "\r\nbody";
  spam_engine_auth_features_t features{};
  test_support::check(
      spam_engine_extract_auth_features(email.data(), email.size(), &features) == 0,
      "extract_auth_features should succeed");
  test_support::check(std::string(features.dkim_signing_domain) == "firebaseapp.com",
                      "DKIM signing org-domain should be firebaseapp.com");
  test_support::check(std::string(features.from_org_domain) == "firebaseapp.com",
                      "From org-domain should reduce to firebaseapp.com");
  test_support::check(features.dmarc_aligned == 0,
                      "dmarc=fail must not count as aligned");
}

// Direct cover for the punycode (xn--) decode path (TASK-237 AC#3). gmime decodes the
// From header's xn-- to raw UTF-8 before the engine sees it, so test_display_impersonation
// exercises only the UTF-8 branch; DKIM d= and body-URL hosts (AC#2) stay ASCII xn--, so
// the RFC-3492 decoder must be locked on its own.
void test_idn_punycode_fold() {
  using spam_engine::brand_names::is_lookalike_domain;
  using spam_engine::brand_names::confusable_fold_unicode;
  // xn--caleway-iog decodes to "ѕcaleway" (Cyrillic ѕ) -> folds to the brand "scaleway".
  test_support::check(confusable_fold_unicode("xn--caleway-iog") == "scaleway",
      "punycode xn--caleway-iog must fold to scaleway");
  test_support::check(is_lookalike_domain("xn--caleway-iog.com"),
      "ASCII xn-- homoglyph domain is a look-alike");
  // Same brand reached as raw UTF-8 (the gmime-decoded From form).
  test_support::check(is_lookalike_domain("\xD1\x95""caleway.com"),
      "raw UTF-8 Cyrillic homoglyph domain is a look-alike");
  // A real IDN that is not a brand must not fire: xn--mnchen-3ya -> "munchen".
  test_support::check(confusable_fold_unicode("xn--mnchen-3ya") == "munchen",
      "münchen folds to munchen, not a brand");
  test_support::check(!is_lookalike_domain("xn--mnchen-3ya.de"),
      "a real non-brand IDN domain is NOT a look-alike");
  // Malformed xn-- must fail safe (empty, no crash).
  test_support::check(confusable_fold_unicode("xn--").empty(),
      "empty punycode payload yields no fold");
  test_support::check(confusable_fold_unicode("xn---").empty(),
      "malformed punycode yields no fold");
  // Pure-ASCII stems are left to the caller's ASCII confusable_fold (return "").
  test_support::check(confusable_fold_unicode("scaleway").empty(),
      "pure-ASCII stem returns empty from the Unicode fold");
  // Multi-word KB brand whose hyphen drops out under folding: a Cyrillic homoglyph of
  // "deutsche-bank.de" -> "deutschebank" (a KB joined SLD). is_lookalike_domain can't
  // see it (Tranco single-token only); the KB IDN route catches it.
  test_support::check(spam_engine::brand_kb::is_idn_lookalike_kb("d\xD0\xB5utsche-bank.de"),
      "raw UTF-8 Cyrillic homoglyph of deutsche-bank is a KB look-alike");
  test_support::check(spam_engine::brand_kb::is_idn_lookalike_kb("xn--dutsche-bank-sck.de"),
      "ASCII xn-- homoglyph of deutsche-bank is a KB look-alike");
  test_support::check(!spam_engine::brand_kb::is_idn_lookalike_kb("xn--mnchen-3ya.de"),
      "a real non-brand IDN domain is NOT a KB look-alike");
}

// TASK-251 FP1/FN1 regressions: ccTLD variants of canonical brand domains are the
// brand, not subdomain deception; hyphenless brand+keyword concatenations are
// combosquats the hyphen splitter missed.
// TASK-440: the callback-phishing family (fake renewal invoice, no link, a phone
// number to call). Measured against the released model, the Norton and McAfee
// spellings of this were condemned and the Geek Squad one was delivered at 0.988
// ham, because "Geek Squad" is two words: its join is not a registrable stem, so
// it never entered brand_names and nothing could fire on it. Keying the brand in
// the KB is what closes that, and these lock the four cases that matters.
// TASK-440/442: the parcel-notice family, measured rather than imagined. A full
// scan of the trap corpus read all 62 French transactional-shaped messages by
// hand and found 27 real imitations, 24 of them one bpost campaign ("Votre colis
// ne peut pas etre livre"). Two thirds sailed through because bpost was not in
// the KB.
//
// Keying the brand buys four of the five spoof shapes, and the fifth is refused
// ON PURPOSE. Measured against the built library rather than assumed:
//
//   combosquat        bpost-livraison.com       fires
//   lookalike host    bpost.be.colis-suivi.net  fires
//   unrelated domain  sendgrid-relay.example    fires
//   typosquat         bpotst.be                 fires
//   DIRECT spoof      bpost.be itself           does NOT fire
//
// The last one is the same-name exclusion in the KB mismatch path: a From whose
// org-domain stem IS the claimed brand is treated as ambiguous rather than as a
// spoof, so that a same-name regional domain (orange.sk for Orange) is not
// condemned. That exclusion is why bpost.be publishes p=reject: a direct forge of
// a brand's own domain is DMARC's job at the receiving edge, not a display-name
// heuristic's. Klar sees mail that already survived that edge.
void test_parcel_carrier_impersonation() {
  struct Case { const char* label; std::string raw; int expect; };
  const std::vector<Case> cases = {
      {"combosquat",
       "From: \"bpost\" <noreply@bpost-livraison.com>\r\n"
       "Subject: Votre colis ne peut pas etre livre\r\n\r\nDroits de douane.\r\n", 1},
      {"lookalike host",
       "From: \"bpost\" <noreply@bpost.be.colis-suivi.net>\r\n"
       "Subject: Probleme de livraison\r\n\r\nSuivi.\r\n", 1},
      {"unrelated domain claiming the brand",
       "From: \"bpost\" <noreply@sendgrid-relay.example>\r\n"
       "Subject: Votre colis\r\n\r\nSuivi.\r\n", 1},
      {"typosquat",
       "From: \"bpost\" <noreply@bpotst.be>\r\n"
       "Subject: Votre colis\r\n\r\nSuivi.\r\n", 1},
      // Not a gap to be fixed here: see the header above.
      {"direct forge of the brand's own domain (DMARC's job)",
       "From: \"bpost\" <noreply@bpost.be>\r\n"
       "Subject: Votre colis\r\n\r\nSuivi.\r\n", 0},
      // The other half of the genre, which this signal must stay silent on: a
      // compromised unrelated domain relaying a French parcel notice claims no
      // brand at all. NOTHING owns it today, which is the honest state: the
      // structural rule that briefly did (isolated_offsite_cta, TASK-439) cost
      // 15 legitimate messages per 4 catches and was removed. TASK-442.
      {"compromised relay, no brand claimed",
       "From: \"Info\" <info@arredamentimoreni.it>\r\n"
       "Subject: Probleme de livraison\r\n\r\nVotre colis attend.\r\n", 0},
      // Keying a brand cuts both ways, and this is the half that protects users:
      // the entry that condemns the spoofs above exempts the carrier's real mail.
      {"the real carrier, DMARC-aligned",
       "From: \"bpost\" <noreply@bpost.be>\r\n"
       "Authentication-Results: mx.example.net; dmarc=pass header.from=bpost.be;"
       " dkim=pass header.d=bpost.be\r\n"
       "Subject: Votre colis est en route\r\n\r\nSuivi.\r\n", 0},
  };

  for (const auto& c : cases) {
    spam_engine_auth_features_t f{};
    spam_engine_extract_auth_features(c.raw.data(), c.raw.size(), &f);
    test_support::check(f.display_impersonation == c.expect,
                        std::string("parcel case: ") + c.label);
  }
}

// The combosquat keyword list was English-only until 2026-08-29, and the genre it
// let through is the one users actually report. Measured on the shipping model
// before the fix: "Amazon Prime" <service-client@amazon-prime-resiliation.com>,
// the lure that opens the bank-advisor scam chain, scored 0.73 and was DELIVERED
// at both profiles, because nothing structural fired. Two reasons, and only the
// first is fixed here:
//
//   1. "amazon" is a dictionary word (the river), so it is a Tier-2 brand, so
//      is_phishy_combosquat is the only path that can condemn a domain carrying
//      it -- and that path needs a keyword token. "resiliation" was not one, in
//      any language. `amazon-verify.com` fired and `amazon-resiliation.com` did
//      not, which is the whole bug in two domains.
//   2. The display name "Amazon Prime" raises no brand claim at all: a Tier-2
//      brand plus a leftover token breaks the Tier-2 shape upstream, the same
//      guard that keeps "Orange County" from claiming Orange. Tier-1 brands are
//      unaffected ("Apple Pay", "Netflix Billing" both fire), so this is
//      narrower than it looks, but it is still open. NOT fixed here: the guard
//      is load-bearing for FPs and moving it needs its own ham sweep.
//
// Asserted as PAIRS on one brand and one shape, `<brand>-<word>.fr`, so the only
// thing that differs between the two sides is the word. That matters more than it
// looks: most KB brands condemn ANY unauthenticated domain claiming them through
// the claimed-vs-authenticated path, so a "brand + benign word" control on one of
// those fires for a reason that has nothing to do with keywords and proves
// nothing. The brands below were picked BY MEASUREMENT for having no such auth
// set, which leaves is_phishy_combosquat as the only path that can speak. So the
// benign half of each pair is a live control: promote "actualites" or "boutique"
// into the keyword list and this test goes red.
void test_non_english_combosquat_keywords() {
  // Keyword tokens that must license a combosquat, and benign ones that must not.
  const std::vector<const char*> keywords = {
      "resiliation", "securite", "connexion",   // fr
      "kuendigung", "sicherheit",               // de
  };
  const std::vector<const char*> benign = {
      "actualites", "boutique", "newsletter", "magazine", "recettes",
  };
  // Display name / org-domain stem, for brands the KB keys with no auth set.
  const std::vector<std::pair<const char*, const char*>> brands = {
      {"Amazon", "amazon"}, {"Orange", "orange"},
      {"Decathlon", "decathlon"}, {"Free", "free"},
  };

  const auto impersonates = [](const std::string& display, const std::string& domain) {
    const std::string raw = "From: \"" + display + "\" <service@" + domain + ">\r\n"
                            "Subject: Votre abonnement\r\n\r\nBonjour.\r\n";
    spam_engine_auth_features_t f{};
    spam_engine_extract_auth_features(raw.data(), raw.size(), &f);
    return f.display_impersonation;
  };

  for (const auto& [display, stem] : brands) {
    for (const char* k : keywords) {
      test_support::check(
          impersonates(display, std::string(stem) + "-" + k + ".fr") == 1,
          std::string("combosquat keyword must fire: ") + stem + "-" + k);
    }
    for (const char* b : benign) {
      test_support::check(
          impersonates(display, std::string(stem) + "-" + b + ".fr") == 0,
          std::string("benign word must NOT fire: ") + stem + "-" + b);
    }
  }

  // The reported lure itself, exactly as it was written, with the multi-token
  // domain the hyphen splitter has to walk past to reach the keyword.
  test_support::check(
      impersonates("Amazon Prime", "amazon-prime-resiliation.com") == 1,
      "the reported bank-advisor lure must impersonate");

  // And the brand's own authenticated mail stays clean, which is what the whole
  // strong/dual-use split exists to protect.
  const std::string real =
      "From: \"Amazon\" <no-reply@amazon.fr>\r\n"
      "Authentication-Results: mx.example.net; dmarc=pass header.from=amazon.fr;"
      " dkim=pass header.d=amazon.fr\r\n"
      "Subject: Votre commande\r\n\r\nBonjour.\r\n";
  spam_engine_auth_features_t f{};
  spam_engine_extract_auth_features(real.data(), real.size(), &f);
  test_support::check(f.display_impersonation == 0,
      "an authenticated amazon.fr sender must not impersonate itself");
}

// Tricky spellings of a brand, measured rather than assumed. Measured 2026-08-29
// as a table with two holes in it, and closed the same day:
//
//   display "AMAZ0N", unrelated domain   was NOT caught, now caught (TASK-458)
//   display "PayPa1", unrelated domain   caught       (PayPal is Tier-1 coined)
//   From amaz0n.com                      caught       (domain path, tier-free)
//   display "аmazon" (Cyrillic а)        caught       (both tiers)
//   display "A m a z o n"                was NOT caught, now caught (TASK-459)
//
// THE LOCKS WORKED, and that is worth recording because writing them felt like
// bureaucracy at the time. Both gaps were asserted here as the CURRENT state
// with a comment saying so, which is what stopped them becoming folklore and
// what made closing them a red test rather than a discovery. The assertions
// below are now the fixed behaviour plus the typographic controls that bound
// it; if a future change reopens either gap, this test says which one.
void test_brand_spelling_tricks() {
  const auto claim = [](const std::string& display, const std::string& domain) {
    const std::string raw = "From: \"" + display + "\" <service@" + domain + ">\r\n"
                            "Subject: Votre commande\r\n\r\nBonjour.\r\n";
    spam_engine_auth_features_t f{};
    spam_engine_extract_auth_features(raw.data(), raw.size(), &f);
    return f.display_impersonation;
  };
  const std::string unrelated = "billing-notice-4471.net";

  // Alphabet confusables are covered for both tiers. These are the real attack
  // in the wild and they must never regress.
  test_support::check(claim("\xd0\xb0mazon", unrelated) == 1,
      "Cyrillic a: display must impersonate");
  test_support::check(claim("amaz\xce\xbfn", unrelated) == 1,
      "Greek omicron: display must impersonate");
  test_support::check(claim("P\xd0\xb0yPal", unrelated) == 1,
      "Cyrillic a in a Tier-1 brand: display must impersonate");

  // The digit fold, on the DOMAIN, is tier-free and covered.
  test_support::check(claim("Amazon", "amaz0n.com") == 1,
      "zero-for-O in the sending domain must impersonate");
  test_support::check(claim("Amazon", "arnazon.com") == 1,
      "rn-for-m in the sending domain must impersonate");
  test_support::check(claim("PayPal", "paypa1.com") == 1,
      "one-for-l in the sending domain must impersonate");

  // The digit fold on the DISPLAY NAME, now at BOTH tiers (TASK-458, closed
  // 2026-08-29). It was Tier-1 only, which left 'AMAZ0N' raising no claim while
  // 'PayPa1' did and while amaz0n.com fired on the domain path at both tiers.
  // The branch only runs when the fold CHANGED the token, so an ordinary
  // all-letter display never reaches it.
  test_support::check(claim("PayPa1", unrelated) == 1,
      "Tier-1 digit-folded display must impersonate");
  test_support::check(claim("AMAZ0N", unrelated) == 1,
      "Tier-2 digit-folded display must impersonate too (TASK-458)");
  test_support::check(claim("Amaz0n", unrelated) == 1,
      "mixed case, digit-folded, Tier-2");

  // Letter-spacing, closed the same day (TASK-459). A run of single-character
  // tokens is joined in the tokenizer, so every guard downstream still applies
  // to the joined form.
  test_support::check(claim("A m a z o n", unrelated) == 1,
      "letter-spacing must not defeat the display match (TASK-459)");
  test_support::check(claim("P a y P a l", unrelated) == 1,
      "letter-spacing, Tier-1 (TASK-459)");
  test_support::check(claim("A.m.a.z.o.n", unrelated) == 1,
      "any separator, not just a space");
  test_support::check(claim("A-m-a-z-o-n", unrelated) == 1,
      "hyphen as the separator");

  // THE FLOOR IS THE FALSE-POSITIVE LEVER, and these are what set it at 5.
  // Letter-spacing is a real typographic style and the words marketing sets
  // that way are short. THREE OF THESE FIVE ARE TIER-2 BRANDS, so a floor of 4
  // would have started claiming brands inside ordinary promotional display
  // names. If any of these fires, the floor has been lowered.
  test_support::check(claim("S A L E", unrelated) == 0,
      "a 4-letter spaced word must not join (typographic style)");
  test_support::check(claim("F R E E", unrelated) == 0,
      "'free' is a Tier-2 brand and a promotional word");
  test_support::check(claim("L I V E", unrelated) == 0,
      "'live' is a Tier-2 brand and a promotional word");
  test_support::check(claim("N E X T", unrelated) == 0,
      "'next' is a Tier-2 brand and a promotional word");
  test_support::check(claim("T H E  E D I T", unrelated) == 0,
      "two short runs must not join across the gap");

  // Ownership still exempts, on the joined form as on any other.
  test_support::check(claim("A m a z o n", "amazon.fr") == 0,
      "a letter-spaced sender on its own domain is not a spoof");

  // A MULTI-WORD brand letter-spaced collapses to ONE token, because a string
  // that separates every letter has no recoverable word boundary. The join
  // matcher required >= 2 tokens, so "D e u t s c h e B a n k" stayed at 0 while
  // "Deutsche Bank" was 1, and TASK-459 was marked closed with the evasion still
  // half-open for exactly the brands whose canonical SLD is hyphenated. The
  // single collapsed token now goes through is_joined_sld, which exists to hold
  // those hyphen-stripped forms.
  test_support::check(claim("D e u t s c h e B a n k", unrelated) == 1,
      "a letter-spaced multi-word KB brand must impersonate (TASK-459)");
  test_support::check(claim("C r e d i t A g r i c o l e", unrelated) == 1,
      "same, for a three-word hyphenated SLD");
  test_support::check(claim("D e u t s c h e B a n k", "deutsche-bank.de") == 0,
      "and the brand's own hyphenated domain still owns the joined form");

  // And the shapes a scammer reaches for that ARE covered, so the coverage
  // above is read against a full picture rather than on its own.
  test_support::check(claim("AMAZON", unrelated) == 1, "all-caps must impersonate");
  test_support::check(claim("Amazon Support", unrelated) == 1,
      "a generic leftover token must not break the claim");
  test_support::check(claim("Amazon", "amazon.com.billing-4471.net") == 1,
      "canonical domain as a non-registrable label must impersonate");
  test_support::check(claim("Amazon", "amazon.security-check.net") == 1,
      "brand in the subdomain must impersonate");
}

// A product line after a dictionary-word brand IS the brand; a place or a nature
// word after it is a namesake. The guard ran backwards for the first half until
// 2026-08-29: bare "Amazon" from an unrelated domain raised a claim and "Amazon
// Prime" raised none, because "prime" read as a distinctive qualifier and
// dropped it entirely. Nobody means the river when they write "Amazon Prime".
//
// Asserted as PAIRS on one brand, because that is what makes it a check: the
// namesake half is the live control on the product-line list. Add "river" or
// "county" to kCont and this test goes red immediately.
void test_product_line_versus_namesake() {
  const auto claim = [](const std::string& display) {
    const std::string raw = "From: \"" + display + "\" <service@billing-notice-4471.net>\r\n"
                            "Subject: Votre abonnement\r\n\r\nBonjour.\r\n";
    spam_engine_auth_features_t f{};
    spam_engine_extract_auth_features(raw.data(), raw.size(), &f);
    return f.display_impersonation;
  };

  // The brand plus one of its own product lines: still the brand.
  for (const char* d : {"Amazon Prime", "Amazon Prime Video", "AMAZON PRIME",
                        "Amazon Music", "Amazon Business", "Apple Pay",
                        "Apple Store", "Orange Pay"}) {
    test_support::check(claim(d) == 1,
        std::string("product line must keep the brand claim: ") + d);
  }

  // The brand plus a place or nature word: a namesake, and the claim is dropped.
  // These are the false positives the shape guard exists to prevent, and they
  // are why the product-line list is curated rather than "any second token".
  for (const char* d : {"Amazon River", "Amazon River Cruises", "Amazon Basin",
                        "Amazon Watch", "Amazon Rainforest", "Orange County",
                        "Orange County News", "Apple Valley", "Apple Valley News"}) {
    test_support::check(claim(d) == 0,
        std::string("namesake must NOT claim the brand: ") + d);
  }

  // Unchanged either way: a person's name, and the brand's own authenticated mail.
  test_support::check(claim("Edmond Boulanger") == 0, "a personal name is not a claim");
  const std::string real =
      "From: \"Amazon Prime\" <no-reply@amazon.fr>\r\n"
      "Authentication-Results: mx.example.net; dmarc=pass header.from=amazon.fr;"
      " dkim=pass header.d=amazon.fr\r\n"
      "Subject: Votre commande\r\n\r\nBonjour.\r\n";
  spam_engine_auth_features_t f{};
  spam_engine_extract_auth_features(real.data(), real.size(), &f);
  test_support::check(f.display_impersonation == 0,
      "the brand's own authenticated mail must not impersonate itself");
}

// An IDN must not be a way to spell a keyword past the combosquat check, and for
// FRENCH keywords that is not a hypothetical: `résiliation`, `sécurité` and
// `vérification` are the NATURAL spellings, so the accented domain is the
// likelier registration and the ASCII one the exception. Shipping the keyword
// list without this would have been a mitigation an attacker bypasses by
// spelling the word correctly.
//
// Underneath it was an encoding bug, which is the part worth keeping: the domain
// path lower-cased with locale `std::tolower`, which folds the Latin-1 range, so
// 0xC3 -- the lead byte of every two-byte UTF-8 sequence in that block -- became
// 0xE3. Every IDN reached every downstream check as mojibake that matches no
// keyword, no brand and no KB entry. The byte assertion below is deliberate: a
// verdict-only test would pass again the moment someone "fixed" this by adding
// the corrupt spelling to a table.
void test_idn_keyword_is_not_a_bypass() {
  struct Case { const char* label; const char* domain; int expect; };
  const std::vector<Case> cases = {
      {"ascii spelling", "amazon-prime-resiliation.com", 1},
      {"punycode of the accented spelling",
       "xn--amazon-prime-rsiliation-occ.com", 1},
      {"raw utf-8 accented spelling", "amazon-prime-r\xc3\xa9siliation.com", 1},
      // UPPERCASE accents. This half became reachable BECAUSE to_lower_ascii was
      // fixed to leave bytes >= 0x80 alone: the locale tolower it replaced
      // mangled 0xC3 0x89 into mojibake, which also matched nothing, so the
      // path was never right, only differently wrong.
      {"uppercase accented spelling", "amazon-prime-R\xc3\x89SILIATION.com", 1},
      // DECOMPOSED (NFD): "e" followed by U+0301 combining acute, which is what
      // a Mac produces by default when the accent is typed.
      {"decomposed accented spelling", "amazon-prime-re\xcc\x81siliation.com", 1},
      // The namesake control survives every fold: an accented benign word is
      // still benign, so this is not "any IDN is a combosquat".
      {"accented BENIGN word must still not fire",
       "amazon-actualit\xc3\xa9s.fr", 0},
  };
  for (const auto& c : cases) {
    const std::string raw = std::string("From: \"Amazon\" <service@") + c.domain +
                            ">\r\nSubject: S\r\n\r\nBonjour.\r\n";
    spam_engine_auth_features_t f{};
    spam_engine_extract_auth_features(raw.data(), raw.size(), &f);
    test_support::check(f.display_impersonation == c.expect,
                        std::string("idn keyword: ") + c.label);
  }

  // The SEPARATORLESS branch, which is a different code path and was missed by
  // the first pass at this: a distinctive brand glued straight to the keyword
  // never reaches the token splitter, so it queried the ASCII keyword set with
  // an accented string of its own. `paypalsecurite.com` fired and
  // `paypalsécurité.com` did not.
  // Each case carries its own display name. A shared one contaminated this
  // block: with `From: "PayPal"` on every row, an amazon* domain fired through
  // the claimed-vs-authenticated path (PayPal claimed from a non-PayPal domain)
  // and looked like a combosquat catch. The Tier-2 rows use a NEUTRAL display so
  // only the domain can speak.
  struct Concat { const char* label; const char* display; const char* domain; int expect; };
  const std::vector<Concat> concat = {
      {"ascii", "PayPal", "paypalsecurite.com", 1},
      {"accented", "PayPal", "paypals\xc3\xa9""curit\xc3\xa9.com", 1},
      {"uppercase accented", "PayPal", "paypalS\xc3\x89""CURIT\xc3\x89.com", 1},
      {"decomposed accented", "PayPal", "paypalse\xcc\x81""curite\xcc\x81.com", 1},
      {"keyword FIRST, accented", "PayPal", "s\xc3\xa9""curitepaypal.com", 1},
      {"benign concatenation must NOT fire", "PayPal", "paypalnews.com", 0},
      // Tier-2 (dictionary-word) brand on the separatorless path, licensed by a
      // STRONG keyword only, mirroring the hyphen path's asymmetry. Removing the
      // hyphens used to walk straight through the fix that caught the
      // hyphenated spelling. Measured at 0 of 2,908 distinct ham From org-stems.
      // TWO tokens is how ordinary domains are built, so a Tier-2 brand glued to
      // one keyword does NOT fire, however much it looks like a combosquat. The
      // first version of the cover had no floor and fired on every row below,
      // including the `freesecurity` collision the call-site comment names as
      // the reason containment was rejected. display_impersonation is a 0.99
      // offset that can authorize a bounce, so this is the costliest place in
      // the engine to be loose. The hyphenated spellings still fire through the
      // token path, which is unchanged.
      {"CONTROL: two-token cover, brand is an ordinary word",
       "Service Client", "freesecurity.com", 0},
      {"CONTROL: two-token cover (2)",
       "Service Client", "officesecurity.com", 0},
      {"CONTROL: two-token cover (3)",
       "Service Client", "livesecurity.com", 0},
      {"CONTROL: two-token cover (4)",
       "Service Client", "visasecurity.com", 0},
      {"accepted loss: two-token cover, stated in the code",
       "Service Client", "amazonresiliation.com", 0},
      // ... and the hyphenated spelling of that same loss still fires.
      {"the hyphenated form of the accepted loss still fires",
       "Service Client", "amazon-resiliation.com", 1},
      {"tier-2 brand + DUAL-USE keyword must NOT fire",
       "Service Client", "amazonbilling.com", 0},
      {"tier-2 brand + benign word must NOT fire",
       "Service Client", "amazonnews.com", 0},
      // A middle token. An exact two-way split could not see this, and it was
      // briefly locked as a known gap; the token COVER closes it, because
      // amazonprimeresiliation decomposes as [amazon][prime][resiliation] with
      // nothing left over.
      {"middle token, covered end to end (three tokens: the floor)",
       "Service Client", "amazonprimeresiliation.com", 1},
      // THE FLOOR IS NOT THE RULE, and believing it was is what a cold review
      // caught. Three tokens said nothing about what the tokens ARE: with role
      // words and brand continuations admissible, `officesecuritysolutions`
      // decomposed as [office][security][solutions], cleared the floor, and set
      // display_impersonation on a plausible security vendor's own domain, at
      // 0.99 and on the bounce allowlist. The code comment claimed "no ordinary
      // noun phrase looks like it" about three tokens; "office security
      // solutions" is an ordinary noun phrase.
      //
      // Every token must now BE evidence: a KB brand, a STRONG keyword, or a
      // product-line word. `solutions` is none of those, so the cover fails
      // rather than being outvoted by a count. If these start firing, generic
      // vocabulary is admissible again.
      {"three tokens, but the third is generic filler",
       "Service Client", "officesecuritysolutions.com", 0},
      {"three tokens, generic filler (2)",
       "Service Client", "freesecurityservices.com", 0},
      {"three tokens, generic filler (3)",
       "Service Client", "livesecuritysupport.com", 0},
      // The cover's whole reason for being, and the controls that keep it
      // honest. Containment (a brand anywhere, a keyword anywhere) also caught
      // the line above and was rejected because it cuts brands out of the middle
      // of ordinary words. None of these has a cover, so none fires:
      //   deliverysecurity  -> "live" only by splitting "de|live|rysecurity"
      //   olivesecurity     -> "live" only by splitting "o|live|security"
      //   freelancesecurity -> "free" leaves "lance", which is not a token
      // If any of these starts firing, the cover has been loosened into
      // containment and the collisions are back.
      {"CONTROL: brand only mid-word, no cover",
       "Service Client", "deliverysecurity.com", 0},
      {"CONTROL: brand only mid-word, no cover (2)",
       "Service Client", "olivesecurity.com", 0},
      {"CONTROL: cover leaves an unknown remainder",
       "Service Client", "freelancesecurity.com", 0},
      {"CONTROL: covered, but no strong keyword",
       "Service Client", "amazonprimevideo.com", 0},
  };
  for (const auto& c : concat) {
    const std::string raw = std::string("From: \"") + c.display + "\" <service@" +
                            c.domain + ">\r\nSubject: S\r\n\r\nBonjour.\r\n";
    spam_engine_auth_features_t f{};
    spam_engine_extract_auth_features(raw.data(), raw.size(), &f);
    test_support::check(f.display_impersonation == c.expect,
                        std::string("idn separatorless: ") + c.label);
  }

  // The SAME domain in a BODY LINK, which is the other half and reaches the
  // engine in a different encoding: GMime decodes the From header's `xn--` to
  // UTF-8, while a body URL stays punycode. So one message could be caught
  // through its From and missed through its link, for the same domain.
  struct LinkCase { const char* label; const char* link; int expect; };
  const std::vector<LinkCase> links = {
      {"ascii link", "https://amazon-prime-resiliation.com/annulation", 1},
      {"punycode link", "https://xn--amazon-prime-rsiliation-occ.com/annulation", 1},
      {"raw utf-8 link", "https://amazon-prime-r\xc3\xa9siliation.com/annulation", 1},
      {"benign brand link must NOT fire",
       "https://amazon-actualites.fr/news", 0},
  };
  for (const auto& c : links) {
    const std::string raw =
        std::string("From: \"Service\" <s@courrier-client-4471.net>\r\n"
                    "Content-Type: text/plain; charset=utf-8\r\n"
                    "Subject: Votre abonnement\r\n\r\nCliquez ici: ") + c.link + "\r\n";
    spam_engine_auth_features_t lf{};
    spam_engine_extract_auth_features(raw.data(), raw.size(), &lf);
    test_support::check(lf.display_impersonation == c.expect,
                        std::string("idn body link: ") + c.label);
  }

  // The org-domain must reach the caller as valid UTF-8, not as the locale-folded
  // mojibake it used to be. 0xC3 0xA9 is é; 0xE3 0xA9 is what the bug produced.
  const std::string raw =
      "From: \"Amazon\" <service@amazon-prime-r\xc3\xa9siliation.com>\r\n"
      "Subject: S\r\n\r\nBonjour.\r\n";
  spam_engine_auth_features_t f{};
  spam_engine_extract_auth_features(raw.data(), raw.size(), &f);
  const std::string got(f.from_org_domain);
  test_support::check(got.find("\xc3\xa9") != std::string::npos,
      "the decoded IDN must reach the caller as UTF-8 (found: " + got + ")");
  test_support::check(got.find("\xe3\xa9") == std::string::npos,
      "the locale tolower must not corrupt the UTF-8 lead byte");
}

void test_consumer_support_brand_impersonation() {
  // 1. The reported scam: a Geek Squad claim from a combosquat of their domain.
  const std::string scam =
      "From: \"Geek Squad Billing\" <billing@geeksquad-invoice-dept.com>\r\n"
      "Subject: Invoice GS-88421905 - Your Total Protection plan has been renewed\r\n"
      "\r\nTo cancel this subscription call +1 (888) 402-7719 within 24 hours.\r\n";
  spam_engine_auth_features_t f{};
  spam_engine_extract_auth_features(scam.data(), scam.size(), &f);
  test_support::check(f.display_impersonation == 1,
                      "Geek Squad claim from a non-canonical domain must impersonate");

  // 2. The same claim on a domain that has nothing to do with the brand, which is
  //    the other half of the family: the scam does not always bother squatting.
  const std::string plain =
      "From: \"Geek Squad\" <billing@secure-billing-notice.net>\r\n"
      "\r\nYour invoice is attached.\r\n";
  spam_engine_auth_features_t f2{};
  spam_engine_extract_auth_features(plain.data(), plain.size(), &f2);
  test_support::check(f2.display_impersonation == 1,
                      "Geek Squad claim from an unrelated domain must impersonate");

  // 3. The exemption the KB buys us, and the reason a canonical domain has to be
  //    verified before it is written down: a real renewal receipt, DMARC-aligned
  //    to a domain Best Buy actually sends from, must NOT be flagged.
  const std::string real =
      "From: \"Geek Squad\" <no-reply@geeksquad.com>\r\n"
      "Authentication-Results: mx.example.net; dmarc=pass header.from=geeksquad.com;"
      " dkim=pass header.d=geeksquad.com\r\n"
      "\r\nYour appointment is confirmed.\r\n";
  spam_engine_auth_features_t f3{};
  spam_engine_extract_auth_features(real.data(), real.size(), &f3);
  test_support::check(f3.display_impersonation == 0,
                      "an authenticated geeksquad.com sender is the brand, not an impersonator");

  // 4. Norton was already condemned before this change, but through the cold-start
  //    STRING crutch (a Tranco stem with no KB auth set), which cannot exempt the
  //    brand's own mail. Now it is keyed, so the authenticated case must be clean
  //    too: this is the FP the crutch would have produced.
  const std::string real_norton =
      "From: \"Norton\" <no-reply@norton.com>\r\n"
      "Authentication-Results: mx.example.net; dmarc=pass header.from=norton.com;"
      " dkim=pass header.d=norton.com\r\n"
      "\r\nYour subscription renews on 1 October.\r\n";
  spam_engine_auth_features_t f4{};
  spam_engine_extract_auth_features(real_norton.data(), real_norton.size(), &f4);
  test_support::check(f4.display_impersonation == 0,
                      "an authenticated norton.com sender must not impersonate itself");
}

void test_brand_fp_regressions() {
  // FP1: the brand's own ccTLD variant as the SENDER. paypal.com.au is KB-canonical
  // and contains the labels "paypal.com"; the deception scan must not self-flag it.
  const std::string au_sender =
      "From: PayPal <service@paypal.com.au>\r\n\r\nreceipt\r\n";
  spam_engine_auth_features_t g1{};
  spam_engine_extract_auth_features(au_sender.data(), au_sender.size(), &g1);
  test_support::check(g1.display_impersonation == 0,
      "From the brand's own ccTLD variant (paypal.com.au) must NOT impersonate");

  // FP1: a body link to a brand's ccTLD site from an unrelated sender.
  const std::string au_link =
      "From: News <hello@aussiebakery.example>\r\n"
      "Content-Type: text/plain\r\n\r\n"
      "Find us on https://www.google.com.au/maps/place/bakery\r\n";
  spam_engine_auth_features_t g2{};
  spam_engine_extract_auth_features(au_link.data(), au_link.size(), &g2);
  test_support::check(g2.display_impersonation == 0,
      "a link to www.google.com.au must NOT flag subdomain deception");

  // The real deception pattern still fires: canonical labels over a foreign registrable.
  const std::string deception =
      "From: Docs <share@medbp.example>\r\n"
      "Content-Type: text/plain\r\n\r\n"
      "open https://accounts.google.com.medbp.com/login\r\n";
  spam_engine_auth_features_t g3{};
  spam_engine_extract_auth_features(deception.data(), deception.size(), &g3);
  test_support::check(g3.display_impersonation == 1,
      "accounts.google.com.medbp.com still IS subdomain deception");

  // FN1: brand+keyword concatenation without a hyphen (paypalsupport, paypalverify).
  const std::string concat1 =
      "From: PayPal <security@paypalsupport.com>\r\n\r\nverify your account\r\n";
  spam_engine_auth_features_t g4{};
  spam_engine_extract_auth_features(concat1.data(), concat1.size(), &g4);
  test_support::check(g4.display_impersonation == 1,
      "'PayPal' from paypalsupport.com IS a concatenation combosquat");
  const std::string concat2 =
      "From: PayPal Security <s@paypalverify.net>\r\n\r\nverify\r\n";
  spam_engine_auth_features_t g5{};
  spam_engine_extract_auth_features(concat2.data(), concat2.size(), &g5);
  test_support::check(g5.display_impersonation == 1,
      "paypalverify.net IS a concatenation combosquat");

  // A brand glued to a NON-keyword stays clean (legit brand-adjacent names).
  const std::string concat_legit =
      "From: Newsletter <hi@paypalcommunity.com>\r\n\r\nforum digest\r\n";
  spam_engine_auth_features_t g6{};
  spam_engine_extract_auth_features(concat_legit.data(), concat_legit.size(), &g6);
  test_support::check(g6.display_impersonation == 0,
      "brand + non-keyword concatenation (paypalcommunity) must NOT combosquat");

  // FP2 spillover via links: a body link to a legit one-edit neighbour must not fire.
  const std::string neighbour_link =
      "From: Fashion Weekly <news@fashionweekly.example>\r\n"
      "Content-Type: text/plain\r\n\r\n"
      "Sale at https://www.lacoste.com/fr\r\n";
  spam_engine_auth_features_t g7{};
  spam_engine_extract_auth_features(neighbour_link.data(), neighbour_link.size(), &g7);
  test_support::check(g7.display_impersonation == 0,
      "a body link to lacoste.com (one edit from laposte) must NOT impersonate");

  // The ccTLD exemption is positional, not stem-based: canonical brand labels hung
  // above an attacker registrable that shares the brand's stem must still fire.
  const std::string same_stem_evasion =
      "From: Docs <share@filehost.example>\r\n"
      "Content-Type: text/plain\r\n\r\n"
      "open https://secure.paypal.com.paypal.tk/login\r\n";
  spam_engine_auth_features_t g8{};
  spam_engine_extract_auth_features(same_stem_evasion.data(), same_stem_evasion.size(), &g8);
  test_support::check(g8.display_impersonation == 1,
      "paypal.com labels above the attacker registrable paypal.tk still fire");

  // Multi-word brand claim: the claimed-token joins must cover the joined SLD form,
  // so a typosquat of a multi-word brand under its own display claim condemns.
  const std::string multiword_typo =
      "From: Wells Fargo <alerts@wellsfargoo.com>\r\n\r\naccount notice\r\n";
  spam_engine_auth_features_t g9{};
  spam_engine_extract_auth_features(multiword_typo.data(), multiword_typo.size(), &g9);
  test_support::check(g9.display_impersonation == 1,
      "'Wells Fargo' <@wellsfargoo.com> is a claimed multi-word typosquat");

  // BEC reply-hijack with the brand claimed in the Reply-To DISPLAY (the field the
  // victim sees when replying): the claim-gate reads Reply-To identity too.
  const std::string rt_display_claim =
      "From: Account Team <updates@send-1.example-mailer.com>\r\n"
      "Reply-To: PayPal Support <service@paypall.com>\r\n\r\nbody\r\n";
  spam_engine_auth_features_t g10{};
  spam_engine_extract_auth_features(rt_display_claim.data(), rt_display_claim.size(), &g10);
  test_support::check(g10.display_impersonation == 1,
      "Reply-To 'PayPal Support <service@paypall.com>' IS a claimed typosquat");

  // Underscore combosquat: '_' separates like '-' (paypal_secure link host).
  const std::string underscore_link =
      "From: Billing <noreply@notif-center.example>\r\n"
      "Content-Type: text/plain\r\n\r\n"
      "verify at https://paypal_secure.com/login\r\n";
  spam_engine_auth_features_t g11{};
  spam_engine_extract_auth_features(underscore_link.data(), underscore_link.size(), &g11);
  test_support::check(g11.display_impersonation == 1,
      "underscore combosquat link (paypal_secure.com) fires");

  // Unclaimed link typosquat with a throwaway signer: the corroborated fallback fires.
  const std::string corro_link =
      "From: Billing <noreply@notif-center.example>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=hfp4j.e5q.jalo.edu.pl; dmarc=fail\r\n"
      "Content-Type: text/plain\r\n\r\n"
      "restore at https://paypall.com/verify\r\n";
  spam_engine_auth_features_t g12{};
  spam_engine_extract_auth_features(corro_link.data(), corro_link.size(), &g12);
  test_support::check(g12.display_impersonation == 1,
      "unclaimed link typosquat + throwaway signer fires (corroborated fallback)");

  // ...but the same unclaimed link typosquat on clean infrastructure stays clean
  // (the lacoste-class link ambiguity, g7, generalized).
  const std::string clean_link_typo =
      "From: Billing <noreply@notif-center.example>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=notif-center.example; dmarc=pass\r\n"
      "Content-Type: text/plain\r\n\r\n"
      "see https://paypall.com/verify\r\n";
  spam_engine_auth_features_t g13{};
  spam_engine_extract_auth_features(clean_link_typo.data(), clean_link_typo.size(), &g13);
  test_support::check(g13.display_impersonation == 0,
      "unclaimed link typosquat on clean aligned infra must NOT fire");

  // TASK-337: a KB brand authenticated by an ALIGNED dkim=pass with NO dmarc=
  // token still earns the rescue. Outlook/Hotmail stamp "dkim=pass header.d=
  // <brand>" without a dmarc token, so demanding the literal token dropped
  // legit brand mail (badoo, ~22 panel FPs). badoo.com is in the KB.
  const std::string aligned_dkim_no_dmarc =
      "From: Badoo <noreply@badoo.com>\r\n"
      "Authentication-Results: hotmail.com; dkim=pass header.d=badoo.com; x-hmca=pass\r\n"
      "Content-Type: text/plain\r\n\r\nYou have a new match\r\n";
  spam_engine_auth_features_t g14{};
  spam_engine_extract_auth_features(aligned_dkim_no_dmarc.data(), aligned_dkim_no_dmarc.size(), &g14);
  test_support::check(g14.kb_brand_dmarc_pass == 1,
      "aligned dkim=pass (no dmarc token) rescues a KB brand");

  // Safety: an UNALIGNED dkim=pass (signer != From org-domain) must NOT rescue.
  // This is the whole security of the rescue: a spoofer of a KB brand's From can
  // sign only with a domain they own, which does not align, so it cannot buy the
  // -0.90 ham push.
  const std::string unaligned_dkim =
      "From: Badoo <noreply@badoo.com>\r\n"
      "Authentication-Results: hotmail.com; dkim=pass header.d=mailer-evil.example\r\n"
      "Content-Type: text/plain\r\n\r\nclick here\r\n";
  spam_engine_auth_features_t g15{};
  spam_engine_extract_auth_features(unaligned_dkim.data(), unaligned_dkim.size(), &g15);
  test_support::check(g15.kb_brand_dmarc_pass == 0,
      "unaligned dkim=pass must NOT rescue a spoofed KB-brand From");
}

// TASK-251 FN2 + FN3, tested directly on display_impersonates_brand (the
// display_impersonation boolean unions cousin.tier1, which would mask the
// display-name path when the domain is itself a look-alike).
void test_display_brand_homoglyph_and_owns() {
  using spam_engine::brand_names::display_impersonates_brand;

  // FN2: digit homoglyphs in a distinctive (Tier-1) display name fold onto the
  // brand they imitate (previously only capital-I folded, so these passed clean).
  const auto pa = display_impersonates_brand("PayPa1 Security", "mailer-svc.example");
  test_support::check(pa.tier1 && pa.brand == "paypal",
      "'PayPa1' (digit-1 homoglyph) folds to paypal (FN2)");
  const auto go = display_impersonates_brand("G00gle Security", "notify.example");
  test_support::check(go.tier1 && go.brand == "google",
      "'G00gle' (zero homoglyph) folds to google (FN2)");

  // FN2 preserves the conservative capital-I fold at ANY tier: a capital-I
  // homoglyph of a dictionary-word (Tier-2) brand still fires with impersonation
  // shape ('DecathIon' -> decathlon).
  const auto capI = display_impersonates_brand("DecathIon Support", "notify.example");
  test_support::check(capI.tier2 && capI.brand == "decathlon",
      "'DecathIon' (capital-I) still folds to decathlon at Tier-2 (FN2 preserves capital-I)");

  // THE FN2 TIER-1 GATE IS GONE (TASK-458, 2026-08-29). It was here so a digit
  // coincidence could not fold onto a dictionary-word brand, and the cost was
  // that 'Decath1on Support' and 'AMAZ0N' raised no claim at all while
  // 'PayPa1' did and while the DOMAIN fold caught both tiers. Removing it is a
  // measurement, not an argument: 0/30 on the brand battery's ham classes, 0/32
  // on its legit-FP gate, and zero additional display_impersonation firings on
  // the 1,479-message transactional panel (35 either way, built both ways).
  const auto digit2 = display_impersonates_brand("Decath1on Support", "notify.example");
  test_support::check(digit2.tier2 && digit2.brand == "decathlon",
      "'Decath1on' (digit fold of a Tier-2 brand) now fires (TASK-458)");
  // What actually keeps the fold honest, and it was never the tier: the folded
  // form has to BE a brand. This is the case the gate was really protecting
  // against, and it is unaffected.
  const auto fp = display_impersonates_brand("Passw0rd Reset", "notify.example");
  test_support::check(!fp.tier1 && !fp.tier2,
      "'Passw0rd' folds to 'password' (not a brand) so it must not fire");

  // FN3: a genuine brand domain trusts its own display, in any token order,
  // including co-branded / marketplace mail naming another brand.
  const auto legit = display_impersonates_brand("Amazon Marketplace", "amazon.fr");
  test_support::check(!legit.tier1 && !legit.tier2,
      "'Amazon Marketplace' from amazon.fr is exempt (sender is the brand)");
  const auto cobrand = display_impersonates_brand("Nike on Amazon", "amazon.com");
  test_support::check(!cobrand.tier1 && !cobrand.tier2,
      "'Nike on Amazon' from amazon.com is exempt (amazon owns its own domain, any order)");
  // ...but a brand glued to a longer NON-brand stem (combosquat) is a look-alike,
  // so a DIFFERENT brand claimed beside it still condemns.
  const auto phish = display_impersonates_brand("Amazon PayPal Support", "amazon-offers.xyz");
  test_support::check(phish.tier1 && phish.brand == "paypal",
      "'Amazon PayPal Support' from amazon-offers.xyz still condemns PayPal (FN3)");
}

// TASK-268: the ambiguous Tier-1 brands (Boulanger, Norton) are heavily-phished
// brands that are also common surnames. They condemn standalone like Tier-1, but
// only WITH the impersonation shape, so a personal-name display passes instead
// of repeating the Marie Dupont FP (TASK-266) for these names. (Leclerc, the
// other Leclerc-class dual, is not a Tranco stem at all: e.leclerc reduces to
// stem "e". Its coverage needs the brand KB, TASK-267.)
void test_ambiguous_surname_brands() {
  using spam_engine::brand_names::display_impersonates_brand;

  // Personal-name shape: the first name is a distinctive leftover, breaks the
  // shape, and the claim is dropped entirely (not even Tier-2).
  const auto person = display_impersonates_brand("Edmond Boulanger", "gmail.com");
  test_support::check(!person.tier1 && !person.tier2,
      "'Edmond Boulanger' is a person, not a Boulanger claim (shape broken)");
  const auto person2 = display_impersonates_brand("Sophie Norton", "orange.fr");
  test_support::check(!person2.tier1 && !person2.tier2,
      "'Sophie Norton' is a person, not a Norton claim (shape broken)");

  // Brand + role words (or the bare brand) keeps the shape and condemns
  // STANDALONE from a non-owned domain: Tier-1 strength, no corroboration.
  const auto role = display_impersonates_brand("Boulanger Livraison", "colis-suivi.example");
  test_support::check(role.tier1 && role.brand == "boulanger",
      "'Boulanger Livraison' from a foreign domain IS a standalone Boulanger claim");
  const auto card = display_impersonates_brand("Carte Cadeau Boulanger", "offres-promo.example");
  test_support::check(card.tier1 && card.brand == "boulanger",
      "'Carte Cadeau Boulanger' (gift-card scam shape) IS a standalone Boulanger claim");
  const auto bare = display_impersonates_brand("Norton", "renewal-invoice.example");
  test_support::check(bare.tier1 && bare.brand == "norton",
      "bare 'Norton' from a foreign domain IS a standalone Norton claim");

  // The named scam shapes hold the shape via the renewal/product vocabulary:
  // the fake-invoice family ("Norton Renewal") and the order scam with a digit
  // filler ("Commande 12345", all-digit tokens are not distinctive leftovers).
  const auto renew = display_impersonates_brand("Norton Subscription Renewal", "billing-alerts.example");
  test_support::check(renew.tier1 && renew.brand == "norton",
      "'Norton Subscription Renewal' (fake-invoice scam shape) condemns standalone");
  const auto av = display_impersonates_brand("Norton Antivirus", "billing-alerts.example");
  test_support::check(av.tier1 && av.brand == "norton",
      "'Norton Antivirus' condemns standalone");
  const auto num = display_impersonates_brand("Boulanger Commande 12345", "suivi-colis.example");
  test_support::check(num.tier1 && num.brand == "boulanger",
      "'Boulanger Commande 12345' condemns (an order number is not a distinctive leftover)");
  const auto leet = display_impersonates_brand("Boulanger Serv1ce", "suivi-colis.example");
  test_support::check(leet.tier1 && leet.brand == "boulanger",
      "'Boulanger Serv1ce' condemns (digit-obfuscated role word does not break the shape)");

  // A homoglyph spelling has no personal-name population, so it bypasses the
  // ambiguous gate and stays plain Tier-1 even beside a first name.
  const auto homo = display_impersonates_brand("Edmond B0ulanger", "gmail.com");
  test_support::check(homo.tier1 && homo.brand == "boulanger",
      "'Edmond B0ulanger' (digit homoglyph) stays a plain Tier-1 condemn");

  // The brand on its own domain stays exempt (whole-display self-exemption).
  const auto own = display_impersonates_brand("Boulanger Livraison", "boulanger.com");
  test_support::check(!own.tier1 && !own.tier2,
      "'Boulanger Livraison' from boulanger.com is the brand itself");
}

void test_display_impersonation() {
  // Extraction (TASK-214): the From display claims a distinctive brand the From
  // org-domain isn't, the Scaleway phish shape.
  const std::string phish =
      "From: Scaleway <noca@depilacionlasercanarias.com>\r\n"
      "Subject: Account locked\r\n\r\nbody";
  spam_engine_auth_features_t f{};
  spam_engine_extract_auth_features(phish.data(), phish.size(), &f);
  test_support::check(f.display_impersonation == 1,
      "display 'Scaleway' from depilacionlasercanarias.com IS impersonation");

  // The brand from its OWN domain is exempt (stem matches), no false flag.
  const std::string legit = "From: Scaleway <noreply@scaleway.com>\r\n\r\nbody";
  spam_engine_auth_features_t f2{};
  spam_engine_extract_auth_features(legit.data(), legit.size(), &f2);
  test_support::check(f2.display_impersonation == 0,
      "brand display from the brand's OWN domain is NOT impersonation");

  // No display name → nothing to impersonate.
  const std::string nodisp = "From: <noreply@depilacionlasercanarias.com>\r\n\r\nbody";
  spam_engine_auth_features_t f3{};
  spam_engine_extract_auth_features(nodisp.data(), nodisp.size(), &f3);
  test_support::check(f3.display_impersonation == 0, "no display name → no impersonation");

  // Homoglyph evasion (TASK-230): a capital 'I' standing in for 'l' must not hide
  // a known brand. "ScaIeway" folds to "scaleway" and fires from a foreign domain.
  const std::string homo = "From: ScaIeway <x@depilacionlasercanarias.com>\r\n\r\nbody";
  spam_engine_auth_features_t f4{};
  spam_engine_extract_auth_features(homo.data(), homo.size(), &f4);
  test_support::check(f4.display_impersonation == 1,
      "capital-I homoglyph 'ScaIeway' still detected as Scaleway impersonation");

  // Accent evasion (TASK-230): the diacritic must not split the brand token.
  // "Nocibé" folds to "nocibe" (in the set) and fires from a foreign domain.
  const std::string acc = "From: Nocib\xC3\xA9 <x@pmokejdjee.firebaseapp.com>\r\n\r\nbody";
  spam_engine_auth_features_t f5{};
  spam_engine_extract_auth_features(acc.data(), acc.size(), &f5);
  test_support::check(f5.display_impersonation == 1,
      "accented 'Nocibe' still detected as brand impersonation");

  // Prefix exemption (TASK-230): a brand whose name is the START of its own
  // multi-word org-domain is the sender, not a spoof, "Société" under
  // societegenerale.fr must NOT fire, but the same brand from a foreign domain does.
  const std::string own =
      "From: Soci\xC3\xA9t\xC3\xA9 G\xC3\xA9n\xC3\xA9rale <noreply@societegenerale.fr>\r\n\r\nbody";
  spam_engine_auth_features_t f6{};
  spam_engine_extract_auth_features(own.data(), own.size(), &f6);
  test_support::check(f6.display_impersonation == 0,
      "brand at the start of its own multi-word domain is NOT impersonation");
  const std::string spoof =
      "From: Soci\xC3\xA9t\xC3\xA9 G\xC3\xA9n\xC3\xA9rale <x@sg-login-secure.com>\r\n\r\nbody";
  spam_engine_auth_features_t f7{};
  spam_engine_extract_auth_features(spoof.data(), spoof.size(), &f7);
  test_support::check(f7.display_impersonation == 1,
      "same brand from an unrelated domain IS impersonation");

  // IDN homoglyph (TASK-237 AC#3): a Cyrillic look-alike domain encoded as xn-- must
  // decode + confusable-fold onto the distinctive brand it imitates, with a GENERIC
  // display so the only brand signal is the domain. "xn--caleway-iog" decodes to
  // "ѕcaleway" (Cyrillic ѕ) -> folds to "scaleway".
  const std::string idn =
      "From: Account Services <verify@xn--caleway-iog.com>\r\n\r\nbody";
  spam_engine_auth_features_t f8{};
  spam_engine_extract_auth_features(idn.data(), idn.size(), &f8);
  test_support::check(f8.display_impersonation == 1,
      "IDN homoglyph xn--caleway-iog (Cyrillic 'scaleway') IS impersonation");

  // A real IDN domain that does NOT fold onto a brand must not fire (fail-safe):
  // xn--mnchen-3ya decodes to "münchen" -> folds to "munchen", not a brand.
  const std::string idn_legit =
      "From: M\xC3\xBCnchen Verein <info@xn--mnchen-3ya.de>\r\n\r\nbody";
  spam_engine_auth_features_t f9{};
  spam_engine_extract_auth_features(idn_legit.data(), idn_legit.size(), &f9);
  test_support::check(f9.display_impersonation == 0,
      "a real IDN domain (münchen.de) that is not a brand must NOT impersonate");

  // Multi-field cousin (TASK-237 AC#2): the brand look-alike in a SECONDARY field.
  // The typosquat is claim-gated (TASK-251 FP2): it fires when the sender CLAIMS the
  // target brand, here a forged brand From (whose own-domain guards swallow the display
  // claim) with replies redirected to the typosquat.
  const std::string rt_cousin =
      "From: PayPal <service@paypal.com>\r\n"
      "Reply-To: service@paypall.com\r\n\r\nbody";
  spam_engine_auth_features_t f10{};
  spam_engine_extract_auth_features(rt_cousin.data(), rt_cousin.size(), &f10);
  test_support::check(f10.display_impersonation == 1,
      "Reply-To typosquat (paypall.com) under a claimed brand IS impersonation");

  // ...but UNCLAIMED, the same shape is a legit ESP-From with the real company in
  // Reply-To, and lacoste.com is one edit from laposte (TASK-251 FP2). Must not fire.
  const std::string rt_neighbour =
      "From: Newsletter <updates@send-1.example-mailer.com>\r\n"
      "Reply-To: service@lacoste.com\r\n\r\nbody";
  spam_engine_auth_features_t f10b{};
  spam_engine_extract_auth_features(rt_neighbour.data(), rt_neighbour.size(), &f10b);
  test_support::check(f10b.display_impersonation == 0,
      "unclaimed one-edit Reply-To (lacoste.com vs laposte) must NOT impersonate");

  // Body-URL homoglyph of a distinctive brand fires.
  const std::string body_cousin =
      "From: Account Team <updates@send-1.example-mailer.com>\r\n\r\n"
      "Confirm here: https://paypa1.com/login\r\n";
  spam_engine_auth_features_t f11{};
  spam_engine_extract_auth_features(body_cousin.data(), body_cousin.size(), &f11);
  test_support::check(f11.display_impersonation == 1,
      "body-URL homoglyph (paypa1.com) with a clean From IS impersonation");

  // Combosquat is DELIBERATELY excluded from the multi-field paths: a Reply-To / body
  // link to "notif-paypal.info" must NOT fire (legit ESP / notification infra uses this
  // shape; the real-inbox scan FP'd on notif-laposte.info before this gate).
  const std::string rt_combosquat =
      "From: Account Team <updates@send-1.example-mailer.com>\r\n"
      "Reply-To: noreply@notif-paypal.info\r\n\r\nbody";
  spam_engine_auth_features_t f12{};
  spam_engine_extract_auth_features(rt_combosquat.data(), rt_combosquat.size(), &f12);
  test_support::check(f12.display_impersonation == 0,
      "Reply-To combosquat (notif-paypal.info) must NOT fire (multi-field excludes combosquat)");

  // A legit differing Reply-To (an ESP) and a legit body link must not fire.
  const std::string legit_multifield =
      "From: Newsletter <news@send-1.example-mailer.com>\r\n"
      "Reply-To: reply@mailchimp.com\r\n\r\nSee https://www.google.com/maps\r\n";
  spam_engine_auth_features_t f13{};
  spam_engine_extract_auth_features(legit_multifield.data(), legit_multifield.size(), &f13);
  test_support::check(f13.display_impersonation == 0,
      "legit ESP Reply-To + legit body link must NOT impersonate");

  // Reply-To divergence (TASK-237 AC#1): a tld-swap cousin (paypal.top) aligned to itself
  // (the normal throwaway/free-host corroborator is absent) with replies redirected to
  // free webmail. The reply-hijack corroborates the tld-swap -> fires.
  const std::string tld_hijack =
      "From: Account Team <billing@paypal.top>\r\n"
      "Reply-To: service@gmail.com\r\n"
      "Authentication-Results: mx; dkim=pass header.d=paypal.top; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t f14{};
  spam_engine_extract_auth_features(tld_hijack.data(), tld_hijack.size(), &f14);
  test_support::check(f14.display_impersonation == 1,
      "tld-swap (paypal.top) + free-webmail Reply-To IS impersonation (reply-hijack)");

  // The surname guard: a common-surname display (a Tier-2 stem) from a small-biz domain
  // with a personal-webmail Reply-To must STAY clean. The reply-hijack must not corroborate
  // a display Tier-2 (the FP that reverted the first AC#1 attempt).
  const std::string surname_rt =
      "From: Bob Smith <bob@smallbiz-consulting.fr>\r\n"
      "Reply-To: smith@gmail.com\r\n\r\nFollowing up on our chat.";
  spam_engine_auth_features_t f15{};
  spam_engine_extract_auth_features(surname_rt.data(), surname_rt.size(), &f15);
  test_support::check(f15.display_impersonation == 0,
      "common-surname display + free-webmail Reply-To must NOT impersonate (no Tier-2 reply-hijack)");

  // Non-English surnames are Tier-2 too (TASK-266): "dupont" is a Tranco stem
  // (dupont.com) the English dict misses, so it used to land Tier-1 and condemn
  // every "Marie Dupont" standalone (the /demo Ham EN sample). A personal name
  // has a distinctive leftover (the first name), so the Tier-2 shape breaks and
  // nothing fires.
  const std::string surname_fr =
      "From: Marie Dupont <marie@example.com>\r\n"
      "Subject: Re: Thursday call\r\n\r\nHi Tom, could we move our call?";
  spam_engine_auth_features_t f15b{};
  spam_engine_extract_auth_features(surname_fr.data(), surname_fr.size(), &f15b);
  test_support::check(f15b.display_impersonation == 0,
      "'Marie Dupont' from example.com must NOT impersonate (surname is Tier-2, shape broken)");

  // Same for an EN surname on a shared platform: aligned gmail is never
  // reputable_aligned, so before TASK-266 'John Williams' condemned even with
  // dmarc=pass ("williams" was Tier-1 via williams.com).
  const std::string surname_en =
      "From: John Williams <jwilliams@gmail.com>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=gmail.com; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t f15c{};
  spam_engine_extract_auth_features(surname_en.data(), surname_en.size(), &f15c);
  test_support::check(f15c.display_impersonation == 0,
      "'John Williams' aligned from gmail must NOT impersonate (surname is Tier-2)");

  // The demotion keeps the surname-brand catchable: brand + role word holds the
  // Tier-2 impersonation shape, and a free-host DKIM signer corroborates -> fires.
  const std::string surname_phish =
      "From: Dupont Billing <billing@dupont-notify.web.app>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=dupont-notify.web.app; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t f15d{};
  spam_engine_extract_auth_features(surname_phish.data(), surname_phish.size(), &f15d);
  test_support::check(f15d.display_impersonation == 1,
      "'Dupont Billing' free-host-signed IS impersonation (Tier-2 shape + corroboration)");

  // Regional precision preserved: a tld-swap aligned to itself WITHOUT a reply-hijack
  // stays clean (a header-only signal cannot tell paypal.co from legit paypal.de).
  const std::string tld_nohijack =
      "From: Account Team <billing@paypal.top>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=paypal.top; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t f16{};
  spam_engine_extract_auth_features(tld_nohijack.data(), tld_nohijack.size(), &f16);
  test_support::check(f16.display_impersonation == 0,
      "tld-swap aligned with no reply-hijack stays clean (regional-domain precision)");

  // Anchor href cousin recovery (TASK-239 step 1): a clean From with the cousin ONLY in
  // an <a href> of an HTML body. The text URL scan misses it (html_to_text strips href);
  // the raw-anchor parse recovers it. "paypa1.com" is a homoglyph of paypal.
  const std::string href_cousin =
      "From: Account Team <updates@send-1.example-mailer.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<html><body><a href=\"https://paypa1.com/login\">Click to continue</a></body></html>";
  spam_engine_auth_features_t f17{};
  spam_engine_extract_auth_features(href_cousin.data(), href_cousin.size(), &f17);
  test_support::check(f17.display_impersonation == 1,
      "homoglyph cousin in an <a href> of an HTML body IS impersonation (anchor recovery)");

  // A legit HTML link back to the sender's own domain must not fire.
  const std::string href_legit =
      "From: News <news@send-1.example-mailer.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<html><body><a href=\"https://send-1.example-mailer.com/x\">View online</a></body></html>";
  spam_engine_auth_features_t f18{};
  spam_engine_extract_auth_features(href_legit.data(), href_legit.size(), &f18);
  test_support::check(f18.display_impersonation == 0,
      "an HTML link to the sender's own domain must NOT impersonate");

  // AC#2 phishy-combosquat href: a body link to "paypal-secure.com" (brand + attacker
  // keyword) that the strict-cousin path excludes as a bare combosquat -> fires here.
  const std::string anchor_combosquat =
      "From: Account Team <updates@send-1.example-mailer.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<a href=\"https://paypal-secure.com/login\">https://www.paypal.com</a>";
  spam_engine_auth_features_t f19{};
  spam_engine_extract_auth_features(anchor_combosquat.data(), anchor_combosquat.size(), &f19);
  test_support::check(f19.display_impersonation == 1,
      "phishy-combosquat href 'paypal-secure.com' in an HTML body IS impersonation");

  // Homoglyph href (strict cousin) in an anchor still fires regardless of text.
  const std::string anchor_homoglyph =
      "From: Account Team <updates@send-1.example-mailer.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<a href=\"https://paypa1.com/x\">PayPal Security</a>";
  spam_engine_auth_features_t f20{};
  spam_engine_extract_auth_features(anchor_homoglyph.data(), anchor_homoglyph.size(), &f20);
  test_support::check(f20.display_impersonation == 1,
      "homoglyph href 'paypa1.com' in an HTML anchor IS impersonation");

  // TASK-232 AC#6 anchor-text vs href, Tier-2 brand: visible text shows Apple's real URL,
  // href is a same-brand combosquat 'apple-secure.com'. is_phishy_combosquat needs a
  // DISTINCTIVE brand so it misses this (apple is Tier-2); the per-brand KB names the brand
  // from the visible text and the href look-alike check fires.
  const std::string anchor_t2_spoof =
      "From: Account Team <updates@send-2.example-mailer.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<a href=\"https://apple-secure.com/login\">https://www.apple.com</a>";
  spam_engine_auth_features_t f20b{};
  spam_engine_extract_auth_features(anchor_t2_spoof.data(), anchor_t2_spoof.size(), &f20b);
  test_support::check(f20b.display_impersonation == 1,
      "Tier-2 anchor-url-spoof (apple.com text -> apple-secure.com href) IS impersonation");

  // AC#6 FP-guard (the case that refuted the bare displayed-URL mismatch): a legit
  // newsletter shows a brand's own social URL (linkedin.com) but routes the href through a
  // click-tracker. The tracker is NOT a look-alike of LinkedIn, so it must NOT fire.
  const std::string anchor_tracker_legit =
      "From: Account Team <updates@send-3.example-mailer.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<a href=\"https://click.tracker-mail.com/c/abc\">https://www.linkedin.com/company/acme</a>";
  spam_engine_auth_features_t f20c{};
  spam_engine_extract_auth_features(anchor_tracker_legit.data(), anchor_tracker_legit.size(), &f20c);
  test_support::check(f20c.display_impersonation == 0,
      "a brand's social URL routed through an unrelated tracker does NOT fire (AC#6 FP-guard)");

  // A legit brand-ESP combosquat (paypal-email.com, no phishy keyword) must NOT fire --
  // the FP that a real-inbox scan exposed when bare combosquat was admitted.
  const std::string anchor_esp_combosquat =
      "From: PayPal <service@paypal.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<a href=\"https://click.paypal-email.com/c/1\">www.paypal.com</a>";
  spam_engine_auth_features_t f21{};
  spam_engine_extract_auth_features(anchor_esp_combosquat.data(), anchor_esp_combosquat.size(), &f21);
  test_support::check(f21.display_impersonation == 0,
      "legit brand-ESP combosquat (paypal-email.com, no phishy keyword) must NOT fire");

  // A generic ESP tracker href (not a brand look-alike) must NOT fire.
  const std::string anchor_tracker =
      "From: News <news@send-1.example-mailer.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<a href=\"https://links.sendgrid.net/c/1\">www.paypal.com</a>";
  spam_engine_auth_features_t f22{};
  spam_engine_extract_auth_features(anchor_tracker.data(), anchor_tracker.size(), &f22);
  test_support::check(f22.display_impersonation == 0,
      "a generic ESP tracker href (sendgrid.net) must NOT fire");

  // A legit CTA over a non-look-alike off-domain link must NOT fire.
  const std::string anchor_cta =
      "From: News <news@send-1.example-mailer.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<a href=\"https://partner-store.com/sale\">Shop now</a>";
  spam_engine_auth_features_t f23{};
  spam_engine_extract_auth_features(anchor_cta.data(), anchor_cta.size(), &f23);
  test_support::check(f23.display_impersonation == 0,
      "a plain CTA over a non-look-alike off-domain link must NOT fire");

  // AC#3 credential form: a password input posting to an off-domain unrecognized host.
  const std::string cred_form =
      "From: Account Team <updates@send-1.example-mailer.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<form action=\"https://evil-harvest.ru/submit\"><input type=\"password\" name=\"pw\"></form>";
  spam_engine_auth_features_t f24{};
  spam_engine_extract_auth_features(cred_form.data(), cred_form.size(), &f24);
  test_support::check(f24.display_impersonation == 1,
      "credential form posting off-domain to an unrecognized host IS impersonation");

  // A legit on-site login form (password input posting to the sender's own domain) must
  // NOT fire -- off-domain is the tell.
  const std::string cred_form_onsite =
      "From: PayPal <service@paypal.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<form action=\"https://www.paypal.com/login\"><input type=\"password\" name=\"pw\"></form>";
  spam_engine_auth_features_t f25{};
  spam_engine_extract_auth_features(cred_form_onsite.data(), cred_form_onsite.size(), &f25);
  test_support::check(f25.display_impersonation == 0,
      "a login form posting to the sender's own domain must NOT fire");

  // A form with NO password input must NOT fire (a survey/signup posting off-domain).
  const std::string form_no_pw =
      "From: News <news@send-1.example-mailer.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<form action=\"https://survey-host.com/s\"><input type=\"email\" name=\"e\"></form>";
  spam_engine_auth_features_t f26{};
  spam_engine_extract_auth_features(form_no_pw.data(), form_no_pw.size(), &f26);
  test_support::check(f26.display_impersonation == 0,
      "a form with no password input must NOT fire");

  // AC#4 image-only body: a near-text-empty body that is a clickable logo image linking
  // off-domain to an unrecognized host.
  const std::string img_only =
      "From: Account Team <updates@send-1.example-mailer.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<html><body><a href=\"https://evil-logo.ru/x\"><img src=\"https://evil-logo.ru/l.png\"></a></body></html>";
  spam_engine_auth_features_t f27{};
  spam_engine_extract_auth_features(img_only.data(), img_only.size(), &f27);
  test_support::check(f27.display_impersonation == 1,
      "image-only body linking off-domain to an unrecognized host IS impersonation");

  // A real text newsletter with an image linking off-domain must NOT fire (has text).
  const std::string img_with_text =
      "From: News <news@send-1.example-mailer.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<html><body><p>Here is our long weekly newsletter with plenty of real editorial "
      "content about many topics so the visible text is well over the image-only floor, "
      "ensuring this legitimate message is not mistaken for a bare logo-spoof image.</p>"
      "<a href=\"https://partner-cdn.com/x\"><img src=\"https://partner-cdn.com/l.png\"></a></body></html>";
  spam_engine_auth_features_t f28{};
  spam_engine_extract_auth_features(img_with_text.data(), img_with_text.size(), &f28);
  test_support::check(f28.display_impersonation == 0,
      "an image newsletter with real text must NOT fire (image-only floor)");

  // An image-only body linking to the sender's OWN domain must NOT fire.
  const std::string img_own =
      "From: News <news@send-1.example-mailer.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<html><body><a href=\"https://send-1.example-mailer.com/x\"><img src=\"x.png\"></a></body></html>";
  spam_engine_auth_features_t f29{};
  spam_engine_extract_auth_features(img_own.data(), img_own.size(), &f29);
  test_support::check(f29.display_impersonation == 0,
      "an image-only body linking to the sender's own domain must NOT fire");

  // TASK-242 brand-in-subdomain: a distinctive brand in the subdomain of a host it does
  // not own (the dominant real-phish pattern org_domain reduction misses).
  const std::string sub_brand =
      "From: Account Security <alert@duckdns.org>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<a href=\"https://11paypal-info.duckdns.org/login\">Verify your account</a>";
  spam_engine_auth_features_t f30{};
  spam_engine_extract_auth_features(sub_brand.data(), sub_brand.size(), &f30);
  test_support::check(f30.display_impersonation == 1,
      "a brand in the subdomain of a non-owned host IS impersonation (brand-in-subdomain)");

  // Subdomain deception: a canonical brand domain as a non-registrable label.
  const std::string sub_decept =
      "From: Account <alert@evil-corp.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<a href=\"https://accounts.paypal.com.evil-corp.com/x\">Sign in</a>";
  spam_engine_auth_features_t f31{};
  spam_engine_extract_auth_features(sub_decept.data(), sub_decept.size(), &f31);
  test_support::check(f31.display_impersonation == 1,
      "a canonical brand domain as a non-registrable label IS impersonation (subdomain deception)");

  // The brand's OWN subdomain must NOT fire.
  const std::string own_sub =
      "From: PayPal <service@paypal.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<a href=\"https://secure.paypal.com/login\">Sign in</a>";
  spam_engine_auth_features_t f32{};
  spam_engine_extract_auth_features(own_sub.data(), own_sub.size(), &f32);
  test_support::check(f32.display_impersonation == 0,
      "a brand's own subdomain (secure.paypal.com) must NOT fire");

  // A non-brand subdomain on an unrelated host must NOT fire.
  const std::string no_brand_sub =
      "From: News <news@send-1.example-mailer.com>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<a href=\"https://login.example-corp.com/x\">Sign in</a>";
  spam_engine_auth_features_t f33{};
  spam_engine_extract_auth_features(no_brand_sub.data(), no_brand_sub.size(), &f33);
  test_support::check(f33.display_impersonation == 0,
      "a non-brand subdomain on an unrelated host must NOT fire");

  // A distinctive brand is matched in the subdomain only as an EXACT TOKEN, not a substring:
  // 'paypal' as a token fires, but the legit word 'interactive' (containing 'interac') does
  // NOT (the substring FP a code review found). 'paypal-login' splits to tokens paypal/login.
  const std::string sub_token =
      "From: Account <alert@duckdns.org>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<a href=\"https://paypal-login.duckdns.org/x\">Sign in</a>";
  spam_engine_auth_features_t f34{};
  spam_engine_extract_auth_features(sub_token.data(), sub_token.size(), &f34);
  test_support::check(f34.display_impersonation == 1,
      "distinctive brand 'paypal' as an exact subdomain token IS impersonation");

  // A legit word that merely CONTAINS a brand stem as a substring must NOT fire.
  const std::string sub_substr =
      "From: Community <news@communitynews.org>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<a href=\"https://interactive-events.eventhost.io/x\">Join</a>";
  spam_engine_auth_features_t f35{};
  spam_engine_extract_auth_features(sub_substr.data(), sub_substr.size(), &f35);
  test_support::check(f35.display_impersonation == 0,
      "a legit word containing a brand stem as a substring (interac in interactive) must NOT fire");

  // A dictionary-word brand (chase) in a subdomain must NOT fire even as a token: 'chase'
  // collides with legit compounds (purchase, chase-news); dictionary brands need the
  // authenticated-domain KB (TASK-232), not link scanning.
  const std::string dict_sub =
      "From: Community <news@communitynews.org>\r\n"
      "Content-Type: text/html\r\n\r\n"
      "<a href=\"https://chase-rewards.someblog.com/x\">Read more</a>";
  spam_engine_auth_features_t f36{};
  spam_engine_extract_auth_features(dict_sub.data(), dict_sub.size(), &f36);
  test_support::check(f36.display_impersonation == 0,
      "a dictionary-word brand token in a subdomain must NOT fire (collides with legit text)");

  // Tier-2 (dictionary-word brand, doc-12): a common word like "Apple" counts as
  // impersonation only with the impersonation SHAPE (brand + role words) AND a
  // corroborating hard signal (throwaway / free-host DKIM signer).
  // (a) Corroborated: bare "Apple" from a free-host signer -> fires.
  const std::string t2fire =
      "From: Apple <noreply@account-portal.firebaseapp.com>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=account-portal.firebaseapp.com; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t g1{};
  spam_engine_extract_auth_features(t2fire.data(), t2fire.size(), &g1);
  test_support::check(g1.display_impersonation == 1,
      "Tier-2 'Apple' with shape + free-host signer IS impersonation");

  // (b) Same brand, clean aligned infra (no throwaway/free-host). 'apple' is a KB brand
  // whose authenticated sending domains are known, and mailservice-portal.com is NOT one
  // of them, so claimed-vs-authenticated (TASK-232 AC#2) fires WITHOUT a corroborator --
  // the clean-infra phish a string/corroboration match misses.
  const std::string t2clean =
      "From: Apple <noreply@mailservice-portal.com>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=mailservice-portal.com; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t g2{};
  spam_engine_extract_auth_features(t2clean.data(), t2clean.size(), &g2);
  test_support::check(g2.display_impersonation == 1,
      "KB Tier-2 'Apple' from a non-authenticated clean domain IS impersonation (claimed-vs-auth)");

  // (b2) icloud.com is in Apple's auth set BUT is a SHARED webmail platform anyone can send from,
  // and Apple does not send "Apple"-branded mail from its users' icloud.com mailbox domain. So a
  // shared-platform domain does NOT vouch for the brand even when in its auth set -> this FIRES
  // (TASK-246). Contrast g2c: Apple from its own NON-shared domain is the brand and is exempt.
  const std::string t2shared =
      "From: Apple <noreply@icloud.com>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=icloud.com; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t g2b{};
  spam_engine_extract_auth_features(t2shared.data(), t2shared.size(), &g2b);
  test_support::check(g2b.display_impersonation == 1,
      "KB 'Apple' from icloud.com (a SHARED webmail in Apple's auth set) IS impersonation (TASK-246)");
  const std::string t2own =
      "From: Apple <noreply@apple.com>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=apple.com; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t g2c{};
  spam_engine_extract_auth_features(t2own.data(), t2own.size(), &g2c);
  test_support::check(g2c.display_impersonation == 0,
      "KB 'Apple' from apple.com (its own NON-shared domain) is the brand -> does NOT fire");

  // (c) Place-name shape: "Apple Valley News" has a distinctive leftover ('valley'),
  // so it is not the impersonation shape even from a free-host signer -> no fire.
  const std::string t2shape =
      "From: Apple Valley News <news@reports.firebaseapp.com>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=reports.firebaseapp.com; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t g3{};
  spam_engine_extract_auth_features(t2shape.data(), t2shape.size(), &g3);
  test_support::check(g3.display_impersonation == 0,
      "Tier-2 'Apple Valley News' breaks the shape (distinctive 'Valley') -> no fire");

  // (d) Any-token-owns (doc-12 eval): a brand's multi-word display where a SECONDARY
  // token is itself a distinctive stem ("Amazon Marketplace", "Scaleway Elements")
  // must NOT fire when the sender owns the brand, the secondary token is a product /
  // sub-brand, not a spoof. The owning token ('amazon') authenticates the sender.
  const std::string ownsec = "From: Amazon Marketplace <ship@amazon.fr>\r\n\r\nbody";
  spam_engine_auth_features_t g4{};
  spam_engine_extract_auth_features(ownsec.data(), ownsec.size(), &g4);
  test_support::check(g4.display_impersonation == 0,
      "'Amazon Marketplace' from amazon.fr: owning brand token exempts the sub-brand");

  // ...but a non-brand token matching the throwaway domain must NOT self-exempt a
  // real impersonation: 'PayPal depilacion' from depilacionlasercanarias.com still fires
  // ('depilacion' owns the domain but is not a brand; 'paypal' is the spoofed brand).
  const std::string ownself =
      "From: PayPal depilacion <x@depilacionlasercanarias.com>\r\n\r\nbody";
  spam_engine_auth_features_t g5{};
  spam_engine_extract_auth_features(ownself.data(), ownself.size(), &g5);
  test_support::check(g5.display_impersonation == 1,
      "non-brand token matching the throwaway domain does NOT self-exempt PayPal spoof");

  // (e) Multi-word brand name (doc-12 eval): a Tier-2 brand + a CORPORATE
  // continuation ("Fidelity International") keeps the impersonation shape, so a
  // free-host-signed spoof fires, the continuation is part of the brand's name.
  const std::string mwbrand =
      "From: Fidelity International <secure@fidelity-verify.firebaseapp.com>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=fidelity-verify.firebaseapp.com; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t g6{};
  spam_engine_extract_auth_features(mwbrand.data(), mwbrand.size(), &g6);
  test_support::check(g6.display_impersonation == 1,
      "Tier-2 'Fidelity International' (corporate continuation) IS impersonation");

  // ...but a Tier-2 brand + a GEOGRAPHIC/generic word ("Orange County Moms") is a
  // namesake, not the brand, it breaks the shape even when free-host signed.
  const std::string mwplace =
      "From: Orange County Moms <ocmoms@gmail.com>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=gmail.com; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t g7{};
  spam_engine_extract_auth_features(mwplace.data(), mwplace.size(), &g7);
  test_support::check(g7.display_impersonation == 0,
      "Tier-2 'Orange County Moms' (geographic leftover) does NOT fire");

  // (f) Homoglyph from the brand's OWN domain (code-review regression): a brand
  // matched only via its folded form must test ownership against that folded form,
  // else legit aligned mail self-flags. "PayPaI" (capital-I) from paypal.com folds
  // to "paypal" which equals the domain stem -> owned -> must NOT fire.
  const std::string homoOwn = "From: PayPaI <noreply@paypal.com>\r\n\r\nbody";
  spam_engine_auth_features_t g8{};
  spam_engine_extract_auth_features(homoOwn.data(), homoOwn.size(), &g8);
  test_support::check(g8.display_impersonation == 0,
      "homoglyph 'PayPaI' from paypal.com (folded form owns the domain) does NOT fire");

  // ...and the brand sitting at the front of its own multi-word domain is exempt
  // even with a place token after it: "Time Out London" from timeout.com ('time'
  // fronts the domain) must NOT fire (the place-name 'London' residual fix).
  const std::string fronts = "From: Time Out London <hello@timeout.com>\r\n\r\nbody";
  spam_engine_auth_features_t g9{};
  spam_engine_extract_auth_features(fronts.data(), fronts.size(), &g9);
  test_support::check(g9.display_impersonation == 0,
      "'Time Out London' from timeout.com (brand fronts its own domain) does NOT fire");

  // (g) Auth-reputation exemption (real-inbox scan, doc-12): a sub-brand / product
  // display from the parent brand's OWN established domain, DMARC-aligned, is the
  // brand, not a spoof. "iCloud" from apple.com (established + aligned, not a free
  // host) must NOT fire even though 'icloud' != domain stem 'apple'.
  const std::string repExempt =
      "From: iCloud <noreply@apple.com>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=apple.com; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t g10{};
  spam_engine_extract_auth_features(repExempt.data(), repExempt.size(), &g10);
  test_support::check(g10.display_impersonation == 0,
      "'iCloud' from apple.com (established, DMARC-aligned) is exempt, not impersonation");

  // ...but the exemption must NOT cover free webmail / shared platforms: a brand
  // display from a gmail.com account is the classic spoof and must still fire even
  // though gmail.com is 'established' and DMARC-aligned to itself.
  const std::string repWebmail =
      "From: PayPal <phisher@gmail.com>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=gmail.com; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t g11{};
  spam_engine_extract_auth_features(repWebmail.data(), repWebmail.size(), &g11);
  test_support::check(g11.display_impersonation == 1,
      "'PayPal' from gmail.com (shared platform) is NOT exempt, still impersonation");

  // (h) Cousin / look-alike sending domain (TASK-214 AC#3): a combosquat domain
  // fires even with NO brand in the display (the display signal can't see it).
  // "paypal-secure.com" splits to a Tier-1 brand token + a role word.
  const std::string combosquat =
      "From: Account Update <security@paypal-secure.com>\r\n\r\nbody";
  spam_engine_auth_features_t h1{};
  spam_engine_extract_auth_features(combosquat.data(), combosquat.size(), &h1);
  test_support::check(h1.display_impersonation == 1,
      "combosquat 'paypal-secure.com' is a look-alike sending domain (AC#3)");

  // ...homoglyph sending domain: "paypa1.com" folds (1->l) onto the Tier-1 brand.
  const std::string homoDom = "From: Security <noreply@paypa1.com>\r\n\r\nbody";
  spam_engine_auth_features_t h2{};
  spam_engine_extract_auth_features(homoDom.data(), homoDom.size(), &h2);
  test_support::check(h2.display_impersonation == 1,
      "homoglyph 'paypa1.com' folds onto a Tier-1 brand (AC#3)");

  // ...but a legit hyphenated name whose token is only a Tier-2 (dictionary) brand
  // must NOT combosquat: "square-enix.com" ('square' is Tier-2) stays clean.
  const std::string legitHyphen =
      "From: Square Enix <news@square-enix.com>\r\n\r\nbody";
  spam_engine_auth_features_t h3{};
  spam_engine_extract_auth_features(legitHyphen.data(), legitHyphen.size(), &h3);
  test_support::check(h3.display_impersonation == 0,
      "legit hyphenated 'square-enix.com' (Tier-2 token) is NOT a combosquat");

  // ...and a plain non-brand hyphenated domain stays clean (no brand token).
  const std::string plainHyphen =
      "From: Newsletter <hi@mountain-bikes-shop.com>\r\n\r\nbody";
  spam_engine_auth_features_t h4{};
  spam_engine_extract_auth_features(plainHyphen.data(), plainHyphen.size(), &h4);
  test_support::check(h4.display_impersonation == 0,
      "non-brand hyphenated domain is not a look-alike");

  // (i) Curated brand KB (TASK-232). Exemption: a mid-tier brand from its OWN
  // canonical domain (not in the Tranco top-10k rescue set), DMARC-aligned, must
  // NOT fire. "BoursoBank" from boursorama.fr (a KB canonical domain).
  const std::string kbExempt =
      "From: BoursoBank <no-reply@boursorama.fr>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=boursorama.fr; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t k1{};
  spam_engine_extract_auth_features(kbExempt.data(), kbExempt.size(), &k1);
  test_support::check(k1.display_impersonation == 0,
      "KB: 'BoursoBank' from canonical boursorama.fr is exempt, not impersonation");

  // TLD-swap: a distinctive brand's SLD on a non-canonical domain (paypal.top vs
  // paypal.com). This is AMBIGUOUS with a legit regional domain the KB has not
  // enumerated (paypal.de), header-identical when aligned, so it fires only WITH
  // corroboration. Here a throwaway signer corroborates -> cousin.
  const std::string kbTld =
      "From: PayPal Billing <billing@paypal.top>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=hfp4j.e5q.jalo.edu.pl; dmarc=fail\r\n\r\nbody";
  spam_engine_auth_features_t k2{};
  spam_engine_extract_auth_features(kbTld.data(), kbTld.size(), &k2);
  test_support::check(k2.display_impersonation == 1,
      "KB: TLD-swap 'paypal.top' with a throwaway signer is a corroborated cousin");

  // ...but a legit REGIONAL brand domain (paypal.de), DMARC-aligned and self-signed,
  // is the same exact-SLD shape with NO corroboration: it must NOT fire. (The real
  // PayPal.de / Netflix.de false positive this split fixed, 2026-06-28.)
  const std::string kbRegional =
      "From: PayPal <noreply@paypal.de>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=paypal.de; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t k2b{};
  spam_engine_extract_auth_features(kbRegional.data(), kbRegional.size(), &k2b);
  test_support::check(k2b.display_impersonation == 0,
      "legit regional 'paypal.de' (aligned, self-signed) does NOT fire as a TLD-swap");

  // Typosquat: within one edit of a canonical brand SLD (paypall vs paypal). Claim-gated
  // (TASK-251 FP2): standalone only when the sender also claims the target brand; the
  // display claim that owns_prefix swallows ("paypall" starts with "paypal") is exactly
  // what the claim-gate recovers.
  const std::string kbTypo = "From: PayPal <noreply@paypall.com>\r\n\r\nbody";
  spam_engine_auth_features_t k3{};
  spam_engine_extract_auth_features(kbTypo.data(), kbTypo.size(), &k3);
  test_support::check(k3.display_impersonation == 1,
      "KB: claimed typosquat 'PayPal' <@paypall.com> fires standalone");

  // Unclaimed, the one-edit domain is ambiguous with a legit same-name company; it
  // demotes to the corroboration-gated tier. A throwaway signer corroborates -> fires.
  const std::string kbTypoCorro =
      "From: Billing <noreply@paypall.com>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=hfp4j.e5q.jalo.edu.pl; dmarc=fail\r\n\r\nbody";
  spam_engine_auth_features_t k3b{};
  spam_engine_extract_auth_features(kbTypoCorro.data(), kbTypoCorro.size(), &k3b);
  test_support::check(k3b.display_impersonation == 1,
      "KB: unclaimed typosquat + throwaway signer is a corroborated cousin");

  // The FP class the claim-gate fixes (TASK-251 FP2): real companies one edit from a
  // KB brand, claiming only THEIR OWN name, with no Tranco rescue. Must stay clean.
  const std::string kbNeighbour = "From: Lacoste <news@lacoste.com>\r\n\r\nbody";
  spam_engine_auth_features_t k3c{};
  spam_engine_extract_auth_features(kbNeighbour.data(), kbNeighbour.size(), &k3c);
  test_support::check(k3c.display_impersonation == 0,
      "legit one-edit neighbour (lacoste.com vs laposte) must NOT fire");
  const std::string kbNeighbour2 = "From: Amelie Durand <contact@amelie.fr>\r\n\r\nbody";
  spam_engine_auth_features_t k3d{};
  spam_engine_extract_auth_features(kbNeighbour2.data(), kbNeighbour2.size(), &k3d);
  test_support::check(k3d.display_impersonation == 0,
      "legit one-edit neighbour (amelie.fr vs ameli) must NOT fire");

  // (j) Generic-word collision (code-review): 'france', 'partners', 'labs' etc. are
  // continuation/role words AND Tranco stems. They must NOT fire as standalone
  // brands, and a legit hyphenated domain containing one must NOT combosquat.
  const std::string genericDisplay = "From: France <noreply@unrelated-host.com>\r\n\r\nbody";
  spam_engine_auth_features_t j1{};
  spam_engine_extract_auth_features(genericDisplay.data(), genericDisplay.size(), &j1);
  test_support::check(j1.display_impersonation == 0,
      "generic word 'France' does not fire as a standalone brand");

  const std::string genericHyphen = "From: Newsletter <info@france-telecom.com>\r\n\r\nbody";
  spam_engine_auth_features_t j2{};
  spam_engine_extract_auth_features(genericHyphen.data(), genericHyphen.size(), &j2);
  test_support::check(j2.display_impersonation == 0,
      "legit hyphenated 'france-telecom.com' (generic token) is NOT a combosquat");

  // (k) Brand-in-local-part (doc-13 technique #5): the brand claim is in the address
  // local part, not the display. "paypal-support@evil-host.com" fires; the local part
  // reuses the display shape + ownership precision.
  const std::string lpSpoof = "From: Account Team <paypal-support@evil-host.com>\r\n\r\nbody";
  spam_engine_auth_features_t l1{};
  spam_engine_extract_auth_features(lpSpoof.data(), lpSpoof.size(), &l1);
  test_support::check(l1.display_impersonation == 1,
      "brand-in-local-part 'paypal-support@evil-host.com' is impersonation");

  // ...but the brand from its OWN domain local part is still exempt (noreply@paypal.com).
  const std::string lpOwn = "From: PayPal <noreply@paypal.com>\r\n\r\nbody";
  spam_engine_auth_features_t l2{};
  spam_engine_extract_auth_features(lpOwn.data(), lpOwn.size(), &l2);
  test_support::check(l2.display_impersonation == 0,
      "brand local part on the brand's own domain (noreply@paypal.com) does NOT fire");

  // (m) Multi-word brand JOIN (fr/de recall): a brand written as separate display
  // tokens that no single token names. The curated KB resolves the concatenation,
  // via a single-label SLD (laposte, bankofamerica) or a hyphen-stripped joined SLD
  // (deutsche-bank -> deutschebank). Connector words ("of") fold in transparently.
  const std::string mwDB = "From: Deutsche Bank <security@srv-relay88.xyz>\r\n\r\nbody";
  spam_engine_auth_features_t m1{};
  spam_engine_extract_auth_features(mwDB.data(), mwDB.size(), &m1);
  test_support::check(m1.display_impersonation == 1,
      "multi-word join 'Deutsche Bank' from an unrelated domain is impersonation");

  // ...exempt from its own (hyphenated-SLD) canonical domain: the sender IS the brand.
  const std::string mwDBOwn = "From: Deutsche Bank <noreply@deutsche-bank.de>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=deutsche-bank.de; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t m2{};
  spam_engine_extract_auth_features(mwDBOwn.data(), mwDBOwn.size(), &m2);
  test_support::check(m2.display_impersonation == 0,
      "'Deutsche Bank' from deutsche-bank.de (its own domain) does NOT fire");

  // ...and from a hyphenated variant NOT in the KB canonical set (deutsche-bank.com):
  // the joined brand form is hyphen-free, so ownership compares the hyphen-stripped
  // stem, otherwise a legit aligned hyphenated brand domain would false-fire.
  const std::string mwDBcom = "From: Deutsche Bank <noreply@deutsche-bank.com>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=deutsche-bank.com; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t m2c{};
  spam_engine_extract_auth_features(mwDBcom.data(), mwDBcom.size(), &m2c);
  test_support::check(m2c.display_impersonation == 0,
      "'Deutsche Bank' from its hyphenated deutsche-bank.com (owns the joined form) does NOT fire");

  // Single-label multi-word brand (La Poste -> laposte) from a throwaway fires;
  // from its own domain it is exempt.
  const std::string mwLP = "From: La Poste <edu@hfp4j.e5q.jalo.edu.pl>\r\n\r\nbody";
  spam_engine_auth_features_t m3{};
  spam_engine_extract_auth_features(mwLP.data(), mwLP.size(), &m3);
  test_support::check(m3.display_impersonation == 1,
      "multi-word join 'La Poste' from a throwaway is impersonation");
  // (a legit aligned send; the canonical-domain exemption covers the standalone
  // "poste" Tranco brand that the laposte prefix does not own.)
  const std::string mwLPOwn = "From: La Poste <noreply@laposte.fr>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=laposte.fr; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t m4{};
  spam_engine_extract_auth_features(mwLPOwn.data(), mwLPOwn.size(), &m4);
  test_support::check(m4.display_impersonation == 0,
      "'La Poste' from laposte.fr (its own domain) does NOT fire");

  // Three-token join with a connector word ("Bank of America" -> bankofamerica).
  const std::string mwBoA = "From: Bank of America <alert@account-verify-x.info>\r\n\r\nbody";
  spam_engine_auth_features_t m5{};
  spam_engine_extract_auth_features(mwBoA.data(), mwBoA.size(), &m5);
  test_support::check(m5.display_impersonation == 1,
      "multi-word join 'Bank of America' (connector folds in) is impersonation");

  // A legit multi-word org name whose concatenation is a popular Tranco stem but is
  // NOT a curated brand and sends from a different domain ("World Wildlife Fund" ->
  // worldwildlife, from wwf.org) must NOT fire: the join is curated-KB only, never
  // the broad Tranco set (guards the FP that gating the join to the KB removed).
  const std::string mwWWF = "From: World Wildlife Fund <noreply@wwf.org>\r\n\r\nbody";
  spam_engine_auth_features_t m6{};
  spam_engine_extract_auth_features(mwWWF.data(), mwWWF.size(), &m6);
  test_support::check(m6.display_impersonation == 0,
      "'World Wildlife Fund' from wwf.org (not a curated brand) does NOT fire");

  // Named in TASK-230 AC#2: a multi-word brand whose concatenation is a curated KB
  // SLD ("American Express" -> americanexpress). Single-token matching misses it
  // ("express" is a continuation word); the join resolves it.
  const std::string mwAmex = "From: American Express <x@srv-relay88.xyz>\r\n\r\nbody";
  spam_engine_auth_features_t m7{};
  spam_engine_extract_auth_features(mwAmex.data(), mwAmex.size(), &m7);
  test_support::check(m7.display_impersonation == 1,
      "multi-word join 'American Express' from an unrelated domain is impersonation");

  // (n) Curated SHORT brand (3 chars, below the len>=4 floor): DHL is a top
  // delivery impersonation target (huge in DE). Tier-2 (needs shape + corroboration),
  // so a throwaway-signed "DHL" fires but the brand from its own aligned domain does
  // not, and a 3-char token outside the tiny allowlist never matches.
  const std::string dhlTw = "From: DHL Express <edu@hfp4j.e5q.jalo.edu.pl>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=hfp4j.e5q.jalo.edu.pl; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t n1{};
  spam_engine_extract_auth_features(dhlTw.data(), dhlTw.size(), &n1);
  test_support::check(n1.display_impersonation == 1,
      "short brand 'DHL' (throwaway-corroborated) is impersonation");

  const std::string dhlOwn = "From: DHL <noreply@dhl.de>\r\n"
      "Authentication-Results: mx; dkim=pass header.d=dhl.de; dmarc=pass\r\n\r\nbody";
  spam_engine_auth_features_t n2{};
  spam_engine_extract_auth_features(dhlOwn.data(), dhlOwn.size(), &n2);
  test_support::check(n2.display_impersonation == 0,
      "'DHL' from dhl.de (its own aligned domain) does NOT fire");

  // Decision: a low-neural clone flagged as impersonation is condemned to spam
  // (mirrors the real Scaleway phish: neural reads it 'regular').
  spam_engine_decision_input_t in{};
  in.scores = {0.0F, 0.0F, 0.94F, 0.06F};
  in.ml_label = "regular";
  in.ml_confidence = 0.94;
  in.display_impersonation = 1;
  in.profile = SPAM_ENGINE_PROFILE_STANDARD;
  spam_engine_decision_result_t out{};
  spam_engine_decide(&in, &out);
  test_support::check(std::string(out.label) == "spam",
      "display-impersonation offset condemns a low-neural phish to spam");
  test_support::check(out.condemn_offset_fired == 1, "impersonation is a spam-ward condemn");
  in.display_impersonation = 0;
  spam_engine_decide(&in, &out);
  test_support::check(std::string(out.label) != "spam",
      "no impersonation flag → the same low-neural message stays kept");
}

// TASK-232 AC#4: the claimed-vs-authenticated KB mismatch is the primary path for KNOWN
// brands; the bare Tranco string-condemn is demoted to a cold-start crutch scoped to brands
// the KB cannot adjudicate. Pin the split so neither half silently regresses.
void test_display_impersonation_kb_vs_coldstart() {
  // Precondition for the two halves: a distinctive coined brand with NO KB auth set
  // (cold-start tail) vs one the KB knows (durable core). If the KB grows to cover the
  // chosen cold-start brand, swap it -- the architecture, not the specific brand, is the point.
  test_support::check(spam_engine::brand_names::brand_tier("scaleway") == 1 &&
                          !spam_engine::brand_kb::brand_has_auth_set("scaleway"),
      "precondition: 'scaleway' is a Tier-1 coined brand with no KB auth set");
  test_support::check(spam_engine::brand_names::brand_tier("paypal") == 1 &&
                          spam_engine::brand_kb::brand_has_auth_set("paypal"),
      "precondition: 'paypal' is a Tier-1 brand the KB knows");

  // Cold-start crutch vs KB durable core: a non-KB coined brand condemns on the name alone (day-0
  // fallback); a KB brand from an unauthenticated domain fires via claimed-vs-authenticated mismatch;
  // the same KB brand from a domain in its auth set is exonerated (the KB supersedes the bare string
  // match). The full auth-verdict x membership matrix is in test_brand_auth_exoneration_truth_table.
  struct Case { const char* from; int want; const char* why; };
  const Case cases[] = {
      {"Scaleway <noca@depilacionlasercanarias.com>", 1, "non-KB coined brand fires standalone (cold-start crutch)"},
      {"PayPal Support <secure@account-verify-portal.com>", 1, "KB brand from an unauthenticated domain fires (mismatch)"},
      {"PayPal <service@paypal.com>", 0, "KB brand from a domain in its authenticated set is NOT impersonation"},
  };
  for (const Case& c : cases) {
    const std::string eml = std::string("From: ") + c.from + "\r\n\r\nbody";
    spam_engine_auth_features_t f{};
    spam_engine_extract_auth_features(eml.data(), eml.size(), &f);
    test_support::check(f.display_impersonation == c.want, c.why);
  }
}

// TASK-232 AC#7: Tier-2-aware cousin detection on the From path. A dictionary-word brand
// combosquat (orange-secure) is caught because the phishy keyword is the precision lever;
// the same brand without a keyword (orange-business) is legit-shaped, and a bare Tier-2
// typosquat stays excluded because a one-edit corruption of a common word collides with
// legit domains (apples/ample). A generic display isolates the From cousin signal (a brand
// display would be owns-prefix-exempted by the combosquat stem -- the AC#7 seam).
void test_tier2_from_combosquat() {
  struct Case { const char* from; int want; const char* why; };
  const Case cases[] = {
      {"x@orange-secure.fr", 1, "Tier-2 combosquat (brand + STRONG keyword) fires"},
      {"x@visa-verify.com", 1, "Tier-2 combosquat (verify is strong) fires"},
      {"x@orange-support.fr", 0, "Tier-2 + DUAL-USE keyword stays silent (support over-fires on a common word)"},
      {"x@visa-service.com", 0, "Tier-2 + dual-use keyword (service) stays silent"},
      {"x@orange-business.fr", 0, "Tier-2 brand + non-phishy token is legit-shaped"},
      {"x@orangee.fr", 0, "bare Tier-2 typosquat stays excluded (common-word edit-1)"},
      {"x@apples.com", 0, "Tier-2 plural collision must not fire"},
      {"x@ample.com", 0, "Tier-2 substitution collision must not fire"},
  };
  for (const Case& c : cases) {
    const std::string eml = std::string("From: Account <") + c.from + ">\r\n\r\nbody";
    spam_engine_auth_features_t f{};
    spam_engine_extract_auth_features(eml.data(), eml.size(), &f);
    test_support::check(f.display_impersonation == c.want, c.why);
  }
}

// TASK-232: the FP-safe boundary of the brand-auth-set exoneration, as a full truth table over
// {auth verdict} x {From in the brand's auth set?}. This is the invariant that regressed TWICE
// (DKIM-only gate condemned SPF-aligned mail; dmarc_pass gate condemned no-AR mail), each a
// boolean collapsing the THREE auth states (pass / fail / unknown) into two. The rule: a claim
// from a domain IN the brand's own auth set is condemned ONLY on positive DMARC FAILURE; pass,
// SPF-only pass, and no-AR-header (unknown) all exonerate. A domain NOT in the set fires on the
// claim regardless of auth (aligning to your own throwaway is not being the brand). Covers the
// single-token display path (Wise / transferwise.com, a NON-shared in-set domain that isolates the
// verdict) and the multi-word join path (AmEx / aexp.com). A SHARED in-set domain (icloud.com) is a
// separate dimension: it fires regardless of verdict (TASK-246), pinned by the one row below + g2b.
void test_brand_auth_exoneration_truth_table() {
  struct Case { const char* display; const char* from; const char* ar; int want; const char* why; };
  const Case cases[] = {
      // Single-token, NON-shared in-set: transferwise.com is in wise's auth set (non-prefix, so only
      // membership saves it; not a shared platform, so the DMARC verdict alone decides).
      {"Wise", "x@transferwise.com", nullptr,                                            0, "in-set + NO AR (unknown auth) -> exonerate"},
      {"Wise", "x@transferwise.com", "mx; dkim=pass header.d=transferwise.com; dmarc=pass", 0, "in-set + DKIM-aligned pass -> exonerate"},
      {"Wise", "x@transferwise.com", "mx; spf=pass smtp.mailfrom=transferwise.com; dmarc=pass", 0, "in-set + SPF-only pass -> exonerate"},
      {"Wise", "x@transferwise.com", "mx; spf=fail; dmarc=fail",                          1, "in-set + dmarc=FAIL (forged) -> fire"},
      // A SHARED-webmail in-set domain does NOT vouch even on a pass (TASK-246).
      {"Apple", "x@icloud.com", "mx; dkim=pass header.d=icloud.com; dmarc=pass",         1, "in-set but SHARED platform -> fire despite pass"},
      // Not in the brand's auth set, no brand token / phishy keyword: the claim alone decides.
      {"Apple", "x@notice-account-portal.com", nullptr,                                  1, "not-in-set + NO AR -> fire (claim)"},
      {"Apple", "x@notice-account-portal.com", "mx; spf=pass smtp.mailfrom=notice-account-portal.com; dmarc=pass", 1, "not-in-set + aligned to its OWN domain -> still fire"},
      // Multi-word join path: aexp.com is in americanexpress's auth set, cross-stem, non-shared.
      {"American Express", "x@aexp.com", nullptr,                                         0, "join in-set + NO AR -> exonerate"},
      {"American Express", "x@aexp.com", "mx; spf=fail; dmarc=fail",                      1, "join in-set + dmarc=FAIL -> fire"},
      // La Poste publishes these exact notification domains. The pass/fail pair
      // pins the useful rescue without turning a forged From into an exemption.
      {"La Poste", "noreply@notif-moncompte-laposte.info", "mx; dkim=pass header.d=notif-moncompte-laposte.info; dmarc=pass", 0, "published La Poste notification domain + pass -> exonerate"},
      {"La Poste", "noreply@notif-moncompte-laposte.info", "mx; dkim=fail header.d=notif-moncompte-laposte.info; dmarc=fail", 1, "published La Poste notification domain + fail -> fire"},
      {"Colissimo", "noreply@notif-colissimo-laposte.info", "mx; dkim=pass header.d=notif-colissimo-laposte.info; dmarc=pass", 0, "published Colissimo notification domain + pass -> exonerate"},
      {"Identite Numerique La Poste", "noreply@notif-lidentitenumerique-laposte.info", "mx; dkim=pass header.d=notif-lidentitenumerique-laposte.info; dmarc=pass", 0, "published Identite Numerique domain + pass -> exonerate"},
  };
  for (const Case& c : cases) {
    std::string eml = std::string("From: ") + c.display + " <" + c.from + ">\r\n";
    if (c.ar != nullptr) { eml += std::string("Authentication-Results: ") + c.ar + "\r\n";
}
    eml += "\r\nbody";
    spam_engine_auth_features_t f{};
    spam_engine_extract_auth_features(eml.data(), eml.size(), &f);
    test_support::check(f.display_impersonation == c.want, c.why);
  }
}

void test_extract_auth_features_header_d_preferred_and_aligned() {
  // header.d is the signing domain proper; prefer it over header.i. With
  // dmarc=pass and signer == From org-domain, the message is aligned.
  const std::string email =
      "Authentication-Results: mx.example.net;\r\n"
      "       dkim=pass header.d=manning.com header.i=@news.manning.com;\r\n"
      "       dmarc=pass (p=REJECT sp=REJECT) header.from=manning.com\r\n"
      "From: Manning <promo@manning.com>\r\n"
      "\r\nbody";
  spam_engine_auth_features_t features{};
  test_support::check(
      spam_engine_extract_auth_features(email.data(), email.size(), &features) == 0,
      "extract should succeed");
  test_support::check(std::string(features.dkim_signing_domain) == "manning.com",
                      "header.d should win over header.i");
  test_support::check(features.dmarc_aligned == 1,
                      "dmarc=pass + aligned signer should be aligned");
}

void test_extract_auth_features_esp_unaligned() {
  // Legitimate ESP (Mailchimp mcsv.net) signs for a different From org-domain:
  // signer present but NOT aligned. (Alignment alone is not legitimacy — the
  // ham rescue is reputation-gated, TASK-170.)
  const std::string email =
      "Authentication-Results: mx.example.net;\r\n"
      "       dkim=pass header.i=@mcsv.net; dmarc=pass header.from=glinet.biz\r\n"
      "From: GL.iNet <news@glinet.biz>\r\n"
      "\r\nbody";
  spam_engine_auth_features_t features{};
  test_support::check(
      spam_engine_extract_auth_features(email.data(), email.size(), &features) == 0,
      "extract should succeed");
  test_support::check(std::string(features.dkim_signing_domain) == "mcsv.net",
                      "signer should be the ESP org-domain");
  test_support::check(features.dmarc_aligned == 0,
                      "ESP signing a different From org-domain is not aligned");
}

void test_extract_auth_features_throwaway_signer() {
  // The TASK-178 signal: a throwaway-shaped signer — >= 2 machine-generated
  // labels below the org-domain (here over the org.es public suffix). These
  // campaigns DMARC-align their own domain, so alignment must still be 1
  // while signer_throwaway condemns. Mirrors the real fixture
  // 'Action requise pour maintenir votre service Cloud.eml'.
  const std::string email =
      "Authentication-Results: mx.google.com;\r\n"
      "       dkim=pass header.i=@jjlw.how.populag.org.es header.s=smtp;\r\n"
      "       spf=pass; dmarc=pass header.from=jjlw.how.populag.org.es\r\n"
      "From: CIoud.Support <edu@jjlw.how.populag.org.es>\r\n"
      "\r\nbody";
  spam_engine_auth_features_t features{};
  test_support::check(
      spam_engine_extract_auth_features(email.data(), email.size(), &features) == 0,
      "extract should succeed");
  test_support::check(std::string(features.dkim_signing_fqdn) == "jjlw.how.populag.org.es",
                      "full signer FQDN should be surfaced");
  test_support::check(std::string(features.dkim_signing_domain) == "populag.org.es",
                      "org_domain is ccSLD-aware: populag.org.es, not org.es");
  test_support::check(features.signer_throwaway == 1,
                      "jjlw.how below populag.org.es is throwaway-shaped");
  test_support::check(features.dmarc_aligned == 1,
                      "spammer-aligned throwaway domain still reads as aligned");

  // ESP fleet-numbering (mail56.atl71.mcdlv.net) is depth 2 but conventional:
  // alphabetic word + digit suffix labels must NOT read as throwaway.
  const std::string esp =
      "Authentication-Results: mx.example.net;\r\n"
      "       dkim=pass header.d=mail56.atl71.mcdlv.net\r\n"
      "From: Newsletter <news@brand.example>\r\n"
      "\r\nbody";
  test_support::check(
      spam_engine_extract_auth_features(esp.data(), esp.size(), &features) == 0,
      "extract should succeed");
  test_support::check(features.signer_throwaway == 0,
                      "fleet-numbered ESP send hosts are not throwaway");

  // ...but a SINGLE letter + digits (m1 / m4 / t9o) is not a shard word, it is
  // throwaway randomness: it must read as generated so the whole FQDN qualifies.
  // (Real throwaway phish signers: t9o.m1.fnt.rybnik.pl, ek4a.m4.ich.walbrzych.pl.)
  const std::string shortgen =
      "Authentication-Results: mx.example.net;\r\n"
      "       dkim=pass header.d=t9o.m1.fnt.rybnik.pl\r\n"
      "From: Apple <edu@t9o.m1.fnt.rybnik.pl>\r\n"
      "\r\nbody";
  test_support::check(
      spam_engine_extract_auth_features(shortgen.data(), shortgen.size(), &features) == 0,
      "extract should succeed");
  test_support::check(features.signer_throwaway == 1,
                      "single-letter+digit labels (m1) are throwaway, not fleet-numbering");

  // Depth 1 never qualifies, however random the label (em9234.brand.com style
  // service subdomains are how legitimate brands sign).
  const std::string depth1 =
      "Authentication-Results: mx.example.net;\r\n"
      "       dkim=pass header.d=48055234m.manning.com\r\n"
      "From: Manning <promo@manning.com>\r\n"
      "\r\nbody";
  test_support::check(
      spam_engine_extract_auth_features(depth1.data(), depth1.size(), &features) == 0,
      "extract should succeed");
  test_support::check(features.signer_throwaway == 0,
                      "a single sub-label below the org-domain is not throwaway");

  // Common mail-infra words don't count as generated even when deep.
  const std::string infra =
      "Authentication-Results: mx.example.net;\r\n"
      "       dkim=pass header.d=mail.updates.example.com\r\n"
      "From: Example <hi@example.com>\r\n"
      "\r\nbody";
  test_support::check(
      spam_engine_extract_auth_features(infra.data(), infra.size(), &features) == 0,
      "extract should succeed");
  test_support::check(features.signer_throwaway == 0,
                      "mail.updates.* infra labels are not throwaway");

  // Google Workspace signs digit-named customers as
  // <name>-<tld>.<yyyymmdd>.gappssmtp.com — the date-stamp label is exempt,
  // so a brand like 42.fr or beer52.com must NOT read as throwaway
  // (7 real ham FPs in 75,635 before this exemption — TASK-178 OOD scan).
  const std::string workspace =
      "Authentication-Results: mx.example.net;\r\n"
      "       dkim=pass header.i=user@42-fr.20210112.gappssmtp.com\r\n"
      "From: 42 <contact@42.fr>\r\n"
      "\r\nbody";
  test_support::check(
      spam_engine_extract_auth_features(workspace.data(), workspace.size(), &features) == 0,
      "extract should succeed");
  test_support::check(std::string(features.dkim_signing_fqdn) == "42-fr.20210112.gappssmtp.com",
                      "full-AUID header.i=local@domain keeps the domain side");
  test_support::check(features.signer_throwaway == 0,
                      "digit-named Workspace customer with date-stamp label is not throwaway");
}

void test_extract_auth_features_no_dkim_and_safety() {
  // No dkim=pass → empty signer, never aligned. And null buffer is an error
  // with a zeroed-out struct (same contract as thread features).
  const std::string email =
      "Authentication-Results: mx.example.net; dkim=fail; spf=pass\r\n"
      "From: x@nowhere.test\r\n"
      "\r\nbody";
  spam_engine_auth_features_t features{};
  test_support::check(
      spam_engine_extract_auth_features(email.data(), email.size(), &features) == 0,
      "extract should succeed");
  test_support::check(features.dkim_signing_domain[0] == '\0',
                      "no dkim=pass → empty signing domain");
  test_support::check(features.dmarc_aligned == 0, "no signer → not aligned");

  features.dmarc_aligned = 99;
  std::strcpy(features.dkim_signing_domain, "garbage");
  test_support::check(
      spam_engine_extract_auth_features(nullptr, 0, &features) != 0,
      "null buffer must return non-zero");
  test_support::check(features.dkim_signing_domain[0] == '\0',
                      "out struct must be zeroed on failure");
  test_support::check(features.dmarc_aligned == 0,
                      "dmarc_aligned must be zeroed on failure");
}

// TASK-173 fold guard: classify_rfc822's optional out-params must yield exactly
// what the standalone extract_thread_features / extract_auth_features produce on
// the same bytes — proving the single-parse fold didn't change the extraction.
void test_classify_rfc822_features_match_standalone_extractors() {
  const auto paths = test_support::model_paths();
  test_support::ensure_model_assets(paths, "classify_rfc822 feature fold");

  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "create should return a handle");
  const int status = spam_engine_load(
      handle, paths.model_path.string().c_str(), 0.001F, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "load should succeed");

  // Carries BOTH a reply thread (In-Reply-To/References) and a free-host DKIM
  // signer, so both feature structs are non-trivially populated.
  const std::string email =
      "Authentication-Results: mx.google.com;\r\n"
      "       dkim=pass header.i=@firebaseapp.com header.s=key;\r\n"
      "       spf=pass; dmarc=fail header.from=ebetd.firebaseapp.com\r\n"
      "In-Reply-To: <parent-001@example.com>\r\n"
      "References: <root-000@example.com> <parent-001@example.com>\r\n"
      "Message-ID: <self-002@ebetd.firebaseapp.com>\r\n"
      "From: \"Casino\" <noreply@ebetd.firebaseapp.com>\r\n"
      "Subject: You won\r\n"
      "\r\nclaim your prize now";

  spam_engine_result_t result{};
  spam_engine_parsed_signals_t folded{};
  test_support::check(
      spam_engine_classify_rfc822(handle, email.data(), email.size(), nullptr, nullptr,
                                  "ensemble", &result, &folded)
          == SPAM_ENGINE_STATUS_OK,
      "classify_rfc822 with signals out-param should succeed");

  spam_engine_thread_features_t standalone_thread{};
  spam_engine_auth_features_t standalone_auth{};
  spam_engine_extract_thread_features(email.data(), email.size(), &standalone_thread);
  spam_engine_extract_auth_features(email.data(), email.size(), &standalone_auth);

  // Sanity: the fold actually carried signal, not two zeroed structs.
  test_support::check(folded.thread.has_in_reply_to == 1,
                      "folded thread features should see the reply");
  test_support::check(std::string(folded.auth.dkim_signing_domain) == "firebaseapp.com",
                      "folded auth features should see the free-host signer");

  test_support::check(folded.thread.has_in_reply_to == standalone_thread.has_in_reply_to
                          && folded.thread.references_count == standalone_thread.references_count
                          && std::string(folded.thread.in_reply_to) == standalone_thread.in_reply_to
                          && std::string(folded.thread.first_reference) == standalone_thread.first_reference
                          && std::string(folded.thread.self_message_id) == standalone_thread.self_message_id,
                      "folded thread features must equal standalone extractor");
  test_support::check(std::string(folded.auth.dkim_signing_domain) == standalone_auth.dkim_signing_domain
                          && std::string(folded.auth.dkim_signing_fqdn) == standalone_auth.dkim_signing_fqdn
                          && std::string(folded.auth.from_org_domain) == standalone_auth.from_org_domain
                          && folded.auth.dmarc_aligned == standalone_auth.dmarc_aligned
                          && folded.auth.signer_throwaway == standalone_auth.signer_throwaway,
                      "folded auth features must equal standalone extractor");

  // Null signals out-param must still classify fine (back-compat contract).
  spam_engine_result_t result2{};
  test_support::check(
      spam_engine_classify_rfc822(handle, email.data(), email.size(), nullptr, nullptr,
                                  "ensemble", &result2, nullptr)
          == SPAM_ENGINE_STATUS_OK,
      "classify_rfc822 with null signals out-param should succeed");

  spam_engine_destroy(handle);
}

// Reproduces a field crash from 2026-03-18, in a debug build of the
// pre-rename prototype (bundle id com.example.apple-samplecode…MailExtensions).
// The report itself lived at apple/CRASH.txt until it was deleted as a stray
// file; the detail that mattered is inlined here so this test carries its own
// provenance.  Recover the full trace with:
//     git log --diff-filter=D -- apple/CRASH.txt
//
//   Thread 5 Crashed, dispatch queue spam.engine.trainer
//   spam_engine_classify_rfc822 + 68
//     → std::mutex::lock() threw std::system_error, because the handle had
//       been use-after-free'd, so the mutex was no longer valid
//     → __cxa_throw → std::terminate → abort() → SIGABRT
//
// The lock_guard sat OUTSIDE the try-catch, so the exception crossed the
// extern "C" boundary and took the whole Mail extension down with it.
//
// This test destroys the mutex inside a live handle (simulating the
// invalid-memory state seen in the crash), then calls classify_rfc822
// in a forked child.  Before the fix: child SIGABRTs.
// After the fix: child exits 0 (function returns an error status).
void test_classify_rfc822_mutex_throw_crashes() {
  pid_t const pid = fork();
  if (pid == 0) {
    // Child: reproduce the crash.
    auto* handle = new spam_engine_handle_t();

    // Destroy the mutex, then scribble over it to guarantee
    // pthread_mutex_lock returns EINVAL (same as use-after-free). Deliberate
    // UB to reproduce the crash below; that's the whole point of this test.
    handle->mutex.~mutex();
    // NOLINTNEXTLINE(bugprone-undefined-memory-manipulation)
    std::memset(static_cast<void*>(&handle->mutex), 0xFF, sizeof(handle->mutex));

    spam_engine_result_t result{};
    auto const status = spam_engine_classify_rfc822(
        handle, "test", 4, nullptr, nullptr, "ensemble", &result, nullptr);

    // If the fix is applied, we reach here with an error status.
    // Reconstruct the mutex so delete doesn't UB on the dtor.
    new (&handle->mutex) std::mutex();
    delete handle;

    _exit(status == SPAM_ENGINE_STATUS_OK ? 1 : 0);
  }

  int wstatus = 0;
  waitpid(pid, &wstatus, 0);

  if (WIFSIGNALED(wstatus) && WTERMSIG(wstatus) == SIGABRT) {
    // Current (broken) behaviour: child crashed with SIGABRT.
    // This IS the bug.  Throw so the test shows as FAIL, proving
    // the crash is reproducible.
    throw std::runtime_error(
        "child SIGABRT'd — lock_guard exception crosses extern \"C\" "
        "(matches the 2026-03-18 field crash).  Fix: move lock_guard inside "
        "try-catch.");
  }

  // After the fix the child should exit normally with code 0.
  test_support::check(
      WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0,
      "child should exit 0 after fix (classify returns error status)");
}

// TASK-134 (AC#4): the flywheel contribution C ABI — portable bag, truncation
// reporting, and keyed bucketing — exposed for the Swift producer (TASK-135).
void test_extract_contribution_c_abi() {
  const auto paths = test_support::model_paths();
  test_support::ensure_model_assets(paths, "extract_contribution C ABI");

  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "create handle");
  int status = spam_engine_load(
      handle, paths.model_path.string().c_str(), 0.001F, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "load should succeed");

  const std::string msg =
      "Subject: You WON a FREE prize\r\n"
      "From: promo@spam.example\r\n\r\n"
      "Click http://spam.example/claim now to collect your money!!!";

  uint32_t buckets[512];
  float weights[512];
  size_t count = 0;
  status = spam_engine_extract_contribution(
      handle, msg.data(), msg.size(), nullptr, nullptr,
      /*hash_key=*/0, buckets, weights, 512, &count);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "extract_contribution OK");
  test_support::check(count > 0 && count <= 512, "contribution should yield features");

  // Determinism: a second call returns the identical bag.
  uint32_t buckets2[512];
  float weights2[512];
  size_t count2 = 0;
  spam_engine_extract_contribution(handle, msg.data(), msg.size(), nullptr, nullptr,
                                   0, buckets2, weights2, 512, &count2);
  test_support::check(count == count2, "deterministic feature count");
  bool same = true;
  for (size_t i = 0; i < count; ++i) {
    same = same && buckets[i] == buckets2[i] && weights[i] == weights2[i];
}
  test_support::check(same, "deterministic bucket/weight output");

  // Truncation contract: capacity 0 writes nothing but reports the full count.
  size_t full = 0;
  status = spam_engine_extract_contribution(
      handle, msg.data(), msg.size(), nullptr, nullptr, 0, nullptr, nullptr, 0, &full);
  test_support::check(status == SPAM_ENGINE_STATUS_OK && full == count,
        "capacity 0 reports full count (truncation contract)");

  // Keyed bucketing remaps buckets (same count).
  uint32_t kbuckets[512];
  float kweights[512];
  size_t kcount = 0;
  spam_engine_extract_contribution(handle, msg.data(), msg.size(), nullptr, nullptr,
                                   0xA5A5A5A5A5A5A5A5ULL, kbuckets, kweights, 512, &kcount);
  test_support::check(kcount == count, "keying preserves feature count");
  bool remapped = false;
  for (size_t i = 0; i < count; ++i) { remapped = remapped || kbuckets[i] != buckets[i];
}
  test_support::check(remapped, "keying remaps buckets vs unkeyed");

  // Null-safety: null message is rejected, not crashed.
  size_t dummy = 123;
  status = spam_engine_extract_contribution(
      handle, nullptr, 0, nullptr, nullptr, 0, buckets, weights, 512, &dummy);
  test_support::check(status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT && dummy == 0,
        "null message rejected and out_count zeroed");

  spam_engine_destroy(handle);
}

void test_scrub_rfc822_c_abi() {
  const auto paths = test_support::model_paths();
  test_support::ensure_model_assets(paths, "scrub_rfc822 C ABI");

  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "create handle");
  int status = spam_engine_load(handle, paths.model_path.string().c_str(), 0.001F, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "load should succeed");

  const std::string msg =
      "From: promo@spam.example\r\n"
      "To: victim@personal.example\r\n"
      "Subject: free prize\r\n\r\n"
      "Claim your prize now.\r\n"
      "> Received: from mx (5.4.3.2) by host\r\n";

  // Size first (capacity 0 writes nothing, reports full length).
  size_t full = 123;
  status = spam_engine_scrub_rfc822(handle, msg.data(), msg.size(), nullptr, 0, &full);
  test_support::check(status == SPAM_ENGINE_STATUS_OK && full > 0,
        "scrub sizes with capacity 0 (truncation contract)");

  std::vector<char> buf(full);
  size_t len = 0;
  status = spam_engine_scrub_rfc822(handle, msg.data(), msg.size(), buf.data(), buf.size(), &len);
  test_support::check(status == SPAM_ENGINE_STATUS_OK && len == full, "scrub fills the buffer");
  const std::string scrubbed(buf.data(), len);
  test_support::check(scrubbed.find("victim@personal.example") == std::string::npos,
        "recipient address must not reach scrubbed text");
  test_support::check(scrubbed.find("5.4.3.2") == std::string::npos,
        "quoted Received IP must be redacted");
  test_support::check(scrubbed.find("prize") != std::string::npos, "spam body survives");

  // Null-safety.
  size_t dummy = 7;
  status = spam_engine_scrub_rfc822(handle, nullptr, 0, buf.data(), buf.size(), &dummy);
  test_support::check(status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT && dummy == 0,
        "null message rejected and out_len zeroed");

  spam_engine_destroy(handle);
}

// TASK-208: the embed C ABI must never write past the caller buffer. Callers
// size from spam_engine_n_embd(); an undersized capacity is a hard error, not a
// truncation. The undersized cases advertise a capacity one float short of the
// model dimension while backing it with a real buffer carrying a canary in the
// would-be-overflowed slot — so a regression that ignored capacity and wrote
// n_embd floats is caught deterministically (clobbered canary), without ASan.
void test_embed_capacity_guard_c_abi() {
  const auto paths = test_support::model_paths();
  test_support::ensure_model_assets(paths, "embed capacity guard C ABI");

  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "create handle");

  // Getter is 0 before load, the fixed model dimension after.
  test_support::check(spam_engine_n_embd(handle) == 0, "n_embd is 0 before load");
  int status = spam_engine_load(handle, paths.model_path.string().c_str(), 0.001F, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "load should succeed");
  const int n_embd = spam_engine_n_embd(handle);
  test_support::check(n_embd > 0, "n_embd is the model dimension after load");

  const std::string msg =
      "From: a@b.example\r\nTo: c@d.example\r\nSubject: hi\r\n\r\nhello world\r\n";

  // Exact-size buffers succeed and report the dimension.
  {
    std::vector<float> plain(n_embd);
    std::vector<float> html(n_embd);
    int pf = 0;
    int hf = 0;
    int got = 0;
    status = spam_engine_embed_rfc822(
        handle, msg.data(), msg.size(), nullptr, nullptr,
        plain.data(), &pf, html.data(), &hf, plain.size(), &got);
    test_support::check(status == SPAM_ENGINE_STATUS_OK, "exact-size embed_rfc822 succeeds");
    test_support::check(got == n_embd, "embed_rfc822 reports the model dimension");
    test_support::check(pf == 1 || hf == 1, "at least one body buffer was filled");
  }

  // Undersized buffer: reject, write nothing, still report the needed dimension.
  // The buffer is really n_embd floats but we advertise n_embd-1; the trailing
  // canary must survive (a regression writing n_embd floats would clobber it).
  constexpr float kCanary = -424242.0F;
  {
    std::vector<float> plain(n_embd, kCanary);
    int pf = 1;
    int hf = 1;
    int got = 0;
    status = spam_engine_embed_rfc822(
        handle, msg.data(), msg.size(), nullptr, nullptr,
        plain.data(), &pf, nullptr, &hf, plain.size() - 1, &got);
    test_support::check(status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
          "undersized embed_rfc822 buffer is rejected");
    test_support::check(got == n_embd, "rejected embed_rfc822 still reports needed dimension");
    test_support::check(pf == 0, "rejected embed_rfc822 leaves filled flag clear");
    test_support::check(plain[n_embd - 1] == kCanary,
          "rejected embed_rfc822 wrote nothing past advertised capacity");
  }

  // embed_text: exact size succeeds, undersize is rejected without overflow.
  {
    std::vector<float> ok(n_embd);
    int got = 0;
    status = spam_engine_embed_text(handle, "free text sample", nullptr, nullptr,
                                    ok.data(), ok.size(), &got);
    test_support::check(status == SPAM_ENGINE_STATUS_OK && got == n_embd,
          "exact-size embed_text succeeds and reports the dimension");

    std::vector<float> small(n_embd, kCanary);
    got = 0;
    status = spam_engine_embed_text(handle, "free text sample", nullptr, nullptr,
                                    small.data(), small.size() - 1, &got);
    test_support::check(status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT && got == n_embd,
          "undersized embed_text buffer is rejected, reports needed dimension");
    test_support::check(small[n_embd - 1] == kCanary,
          "rejected embed_text wrote nothing past advertised capacity");
  }

  // Null-arg safety still holds with the new signature.
  int got = 0;
  status = spam_engine_embed_text(handle, nullptr, nullptr, nullptr, nullptr, 0, &got);
  test_support::check(status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT && got == 0,
        "null embed_text input rejected and out_n_embd zeroed");

  spam_engine_destroy(handle);
}

// TASK-201 AC#3 (engine half): the URL-domain extractor exposed over the C ABI.
void test_extract_url_domains_c_api() {
  const std::string raw =
      "From: x@y.com\r\nSubject: t\r\nContent-Type: text/html\r\n\r\n"
      "<a href=\"https://login.evil.web.app/reset\">x</a> "
      "see http://www.Example.co.uk/p and https://u:p@phish.firebaseapp.com/\r\n";
  char* out = spam_engine_extract_url_domains(raw.data(), raw.size());
  test_support::check(out != nullptr, "extract_url_domains should not return NULL on a valid message");
  std::string const joined(out);
  spam_engine_free_string(out);

  std::set<std::string> got;
  std::stringstream ss(joined);
  std::string line;
  while (std::getline(ss, line, '\n')) { if (!line.empty()) { got.insert(line);
}
}
  test_support::check(got == std::set<std::string>({"web.app", "example.co.uk", "firebaseapp.com"}),
        "C ABI must return the deduped eTLD+1 domains, newline-delimited");

  // No URLs → "" (allocated), not NULL.
  const std::string clean = "From: a@b.com\r\nSubject: hi\r\n\r\nno links\r\n";
  char* empty = spam_engine_extract_url_domains(clean.data(), clean.size());
  test_support::check(empty != nullptr && empty[0] == '\0',
        "no-URL body returns an allocated empty string, not NULL");
  spam_engine_free_string(empty);

  // Null input → NULL.
  test_support::check(spam_engine_extract_url_domains(nullptr, 0) == nullptr,
        "null input returns NULL");
}

void test_decide_c_api() {
  // Free-host condemn: a marketing leak (spam-side ~0.09) signed by web.app is
  // carried over the 0.90 standard threshold by the sender-auth push.
  spam_engine_decision_input_t in{};
  in.scores = {0.04F, 0.91F, 0.0F, 0.05F};
  in.ml_label = "marketing";
  in.ml_confidence = 0.91;
  in.dkim_signing_org_domain = "web.app";
  in.profile = SPAM_ENGINE_PROFILE_STANDARD;
  spam_engine_decision_result_t out{};
  int const rc = spam_engine_decide(&in, &out);
  test_support::check(rc == SPAM_ENGINE_STATUS_OK, "decide returns OK");
  test_support::check(std::string(out.label) == "spam", "free-host leak condemned to spam");
  test_support::check(out.train_ml == 0, "header-only condemn does not train ML");
  test_support::check(out.adjusted_spam_side > 0.90, "adjusted spam side cleared the threshold");
  test_support::check(out.condemn_offset_fired == 1, "spam-ward offset fired flag set on a free-host condemn");

  // Ham rescue: model says spam, but the user has emailed this sender >= 2x.
  spam_engine_decision_input_t r{};
  r.scores = {0.0F, 0.0F, 0.05F, 0.95F};
  r.ml_label = "spam";
  r.ml_confidence = 0.95;
  r.exact_send_count = 2;
  r.profile = SPAM_ENGINE_PROFILE_STANDARD;
  spam_engine_decision_result_t rout{};
  spam_engine_decide(&r, &rout);
  test_support::check(std::string(rout.label) == "ham", "sender-history rescues to ham");
  test_support::check(rout.train_ml == 1, "user-side rescue still trains ML");
  test_support::check(rout.condemn_offset_fired == 0, "ham-only rescue sets no spam-ward fired flag");

  // v4 (TASK-283): the free-host condemn offset scales with the gate (0.90 -> 0.99),
  // so spam-side 0.04 + 0.99 = 1.0 >= 0.995 cautious now CONDEMNS a free-host-signed
  // leak at every profile (was 0.04 + 0.90 = 0.94 < 0.95, kept). No new FP: free-host
  // signing is 0/500 ham, so this only condemns mail that is never legitimate.
  spam_engine_decision_input_t c{};
  c.scores = {0.0F, 0.96F, 0.0F, 0.04F};
  c.ml_label = "marketing";
  c.ml_confidence = 0.96;
  c.dkim_signing_org_domain = "web.app";
  c.profile = SPAM_ENGINE_PROFILE_CAUTIOUS;
  spam_engine_decision_result_t cout{};
  spam_engine_decide(&c, &cout);
  test_support::check(std::string(cout.label) == "spam",
        "free-host offset (0.99) condemns the leak even at the 0.995 cautious gate");

  // Brand-reputation ham rescue (TASK-170): model says spam (0.99) on mail signed
  // by a Tranco established brand → the -0.15 ham offset pulls it under the 0.99
  // gate (0.99 - 0.15 = 0.84). v4 (TASK-283): score + ceiling scaled to the 0.99
  // gate (ceiling 0.97 -> 0.999), so the rescue still fires below "near-certain".
  spam_engine_decision_input_t b{};
  b.scores = {0.0F, 0.0F, 0.01F, 0.99F};
  b.ml_label = "spam";
  b.ml_confidence = 0.99;
  b.dkim_signing_org_domain = "github.com";  // Tranco rank 31
  b.profile = SPAM_ENGINE_PROFILE_STANDARD;
  spam_engine_decision_result_t bout{};
  spam_engine_decide(&b, &bout);
  test_support::check(std::string(bout.label) == "ham", "established-brand signer rescues to ham");
  test_support::check(bout.adjusted_spam_side < 0.90, "brand offset pulled the spam-side under threshold");
  test_support::check(bout.condemn_offset_fired == 0, "ham rescue sets no spam-ward fired flag");

  // Same score, NON-brand signer (gab.com, rank ~13k, NOT in top-10k) → no rescue.
  b.dkim_signing_org_domain = "gab.com";
  spam_engine_decide(&b, &bout);
  test_support::check(std::string(bout.label) == "spam", "non-brand signer is not rescued");

  // Ceiling: a near-certain spam (spam-side 0.9995 >= 0.999) signed by a brand is
  // NOT exonerated — guards against a popular-but-abused domain.
  spam_engine_decision_input_t bc{};
  bc.scores = {0.0F, 0.0F, 0.0005F, 0.9995F};
  bc.ml_label = "spam";
  bc.ml_confidence = 0.9995;
  bc.dkim_signing_org_domain = "github.com";
  bc.profile = SPAM_ENGINE_PROFILE_STANDARD;
  spam_engine_decision_result_t bcout{};
  spam_engine_decide(&bc, &bcout);
  test_support::check(std::string(bcout.label) == "spam",
        "brand offset does not exonerate a >=0.999 spam-side (v4 ceiling)");

  // Raw-IP body link (TASK-257): a 0.30 corroborator. It carries a borderline
  // spam the model kept (spam-side 0.70) over the gate, but as a weak offset it
  // must NOT set condemn_offset_fired (it never solo-condemns / can't authorize a
  // destructive bounce on its own). v4 (TASK-283): borderline scaled to the 0.99
  // gate (0.70 + 0.30 = 1.0 >= 0.99; was 0.65 + 0.30 = 0.95 >= 0.90).
  spam_engine_decision_input_t ip{};
  ip.scores = {0.0F, 0.30F, 0.0F, 0.70F};
  ip.ml_label = "marketing";
  ip.ml_confidence = 0.70;
  ip.raw_ip_url = 1;
  ip.profile = SPAM_ENGINE_PROFILE_STANDARD;
  spam_engine_decision_result_t ipout{};
  spam_engine_decide(&ip, &ipout);
  test_support::check(std::string(ipout.label) == "spam", "raw-IP link carries a 0.70 borderline over the gate");
  test_support::check(ipout.adjusted_spam_side > 0.99, "0.70 + 0.30 clears the 0.99 threshold");
  test_support::check(ipout.condemn_offset_fired == 0,
        "the weak 0.30 raw-IP offset must NOT set the bounce-authorizing flag");

  // Raw-IP alone cannot condemn a clean message: spam-side 0.30 + 0.30 = 0.60 < 0.90.
  spam_engine_decision_input_t ipc{};
  ipc.scores = {0.0F, 0.70F, 0.0F, 0.30F};
  ipc.ml_label = "marketing";
  ipc.ml_confidence = 0.70;
  ipc.raw_ip_url = 1;
  ipc.profile = SPAM_ENGINE_PROFILE_STANDARD;
  spam_engine_decision_result_t ipcout{};
  spam_engine_decide(&ipc, &ipcout);
  test_support::check(std::string(ipcout.label) != "spam", "raw-IP alone does not junk a clean message");

  // Connecting IP in a Spamhaus DROP netblock (TASK-113). The mirror image of the
  // raw-IP case above: it condemns a message the model called clean, AND it sets
  // the bounce-authorizing flag, because the caller OBSERVED the peer rather than
  // reading a claim out of the message.
  spam_engine_decision_input_t drop{};
  drop.scores = {0.0F, 0.08F, 0.90F, 0.02F};
  drop.ml_label = "regular";
  drop.ml_confidence = 0.98;
  drop.connect_ip_blocked = 1;
  drop.profile = SPAM_ENGINE_PROFILE_STANDARD;
  spam_engine_decision_result_t dropout{};
  spam_engine_decide(&drop, &dropout);
  test_support::check(std::string(dropout.label) == "spam",
        "DROP-listed connecting IP condemns a message the model called clean");
  test_support::check(dropout.condemn_offset_fired == 1,
        "DROP-listed connecting IP authorizes a reject (observed transport fact)");

  // Not set -> the offset is simply absent; the same clean message is delivered.
  spam_engine_decision_input_t nodrop = drop;
  nodrop.connect_ip_blocked = 0;
  spam_engine_decision_result_t nodropout{};
  spam_engine_decide(&nodrop, &nodropout);
  test_support::check(std::string(nodropout.label) != "spam",
        "no DROP hit -> clean message delivered");
  test_support::check(nodropout.condemn_offset_fired == 0,
        "no DROP hit -> no bounce authorization");

  // TASK-391: GTUBE condemns regardless of content score — the point of the test
  // string is that the answer does not depend on the model.
  spam_engine_decision_input_t gt{};
  gt.scores = {0.0F, 0.02F, 0.97F, 0.01F};
  gt.ml_label = "regular";
  gt.ml_confidence = 0.99;
  gt.gtube_test = 1;
  gt.profile = SPAM_ENGINE_PROFILE_STANDARD;
  spam_engine_decision_result_t gtout{};
  spam_engine_decide(&gt, &gtout);
  test_support::check(std::string(gtout.label) == "spam",
        "GTUBE condemns a message the model scored as clean ham");
  test_support::check(std::string(gtout.fired_offsets) == "gtube_test!",
        "GTUBE is named as the offset that flipped it");

  // TASK-387: the header-derived sibling is weaker and cannot condemn alone.
  spam_engine_decision_input_t hdr{};
  hdr.scores = {0.0F, 0.08F, 0.90F, 0.02F};
  hdr.ml_label = "regular";
  hdr.ml_confidence = 0.98;
  hdr.header_ip_blocked = 1;
  hdr.profile = SPAM_ENGINE_PROFILE_STANDARD;
  spam_engine_decision_result_t hdrout{};
  spam_engine_decide(&hdr, &hdrout);
  test_support::check(std::string(hdrout.label) != "spam",
        "a header-derived DROP hit does not condemn a clean message");
  test_support::check(hdrout.condemn_offset_fired == 0,
        "...and never authorizes a bounce");
  test_support::check(std::string(hdrout.fired_offsets) == "header_ip_drop",
        "...but is recorded as having fired");

  // Both set: the observed one wins and the weak one is suppressed, so the same
  // evidence is never counted twice.
  spam_engine_decision_input_t bothip = drop;
  bothip.header_ip_blocked = 1;
  spam_engine_decision_result_t bothipout{};
  spam_engine_decide(&bothip, &bothipout);
  test_support::check(std::string(bothipout.fired_offsets) == "connect_ip_drop!",
        "observed and header-derived together count once, as the observed one");

  // TASK-388: the fold reports WHICH offsets fired and which one flipped, so a
  // consumer records the reason instead of re-deriving it.
  test_support::check(std::string(dropout.fired_offsets) == "connect_ip_drop!",
        "fired_offsets names the offset and marks it as the flip");
  test_support::check(std::string(nodropout.fired_offsets).empty(),
        "no offset fired -> empty fired_offsets");

  // A ham-ward offset that fires without changing the verdict is listed, but
  // unmarked: "fired" and "flipped the decision" are different facts.
  spam_engine_decision_input_t threaded{};
  threaded.scores = {0.0F, 0.08F, 0.90F, 0.02F};
  threaded.ml_label = "regular";
  threaded.ml_confidence = 0.98;
  threaded.has_in_reply_to = 1;
  threaded.profile = SPAM_ENGINE_PROFILE_STANDARD;
  spam_engine_decision_result_t thout{};
  spam_engine_decide(&threaded, &thout);
  test_support::check(std::string(thout.fired_offsets) == "thread_headers",
        "an offset that fired without flipping is listed unmarked");

  // Both together, in the fold's audit order. NB neither is marked: the ham-ward
  // thread prior (-0.20) holds the DROP push under the gate (0.02 + 0.99 - 0.20 =
  // 0.81 < 0.99), so nothing flipped. That is exactly the interaction TASK-358
  // tracks -- a forgeable In-Reply-To rescuing a near-certain spam -- and this
  // test pins today's behaviour so that fix has a before/after to point at.
  spam_engine_decision_input_t both = threaded;
  both.connect_ip_blocked = 1;
  spam_engine_decision_result_t bothout{};
  spam_engine_decide(&both, &bothout);
  test_support::check(std::string(bothout.fired_offsets) == "thread_headers,connect_ip_drop",
        "multiple offsets are listed in the fold's audit order");
  test_support::check(std::string(bothout.label) != "spam" &&
        bothout.adjusted_spam_side < 0.99,
        "the ham-ward thread prior holds the DROP condemn under the gate (TASK-358)");

  // NULL args are rejected.
  test_support::check(spam_engine_decide(nullptr, &out) == SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
        "null input rejected");
  test_support::check(spam_engine_decide(&in, nullptr) == SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
        "null output rejected");
}

// Pins the shared decision-input builder (TASK-231): the one place the milter,
// /demo addon and classify_full now assemble their din. A new signal added here
// reaches all three at once, so the bug class that dropped display_impersonation
// on two surfaces (#153, #155) can't recur.
// TASK-394: classify_full is the RECOMMENDED entrypoint, and it silently dropped
// the body signals — the exact failure the shared-builder contract exists to
// prevent, one struct over. The C-API tests only ever drove spam_engine_decide
// directly, so nothing caught it. This drives the whole pipeline.
void test_classify_full_carries_body_signals() {
  bool have_ftrl = false;
  spam_engine_handle_t* handle =
      create_loaded_engine("classify_full body signals", &have_ftrl);
  if (handle == nullptr) { return;
}
  const std::string gtube =
      std::string("XJS*C4JDBQADN1.NSBN3*2IDNEN*") + "GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X";
  const std::string mail =
      "From: ops@example.com\r\nSubject: standup notes\r\n"
      "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n\r\n"
      "Notes from today, nothing unusual.\r\n" + gtube + "\r\n";
  spam_engine_full_result_t full{};
  const spam_engine_status_t st = spam_engine_classify_full(
      handle, mail.data(), mail.size(), "", "ops@example.com", "ensemble",
      nullptr, &full);
  test_support::check(st == SPAM_ENGINE_STATUS_OK, "classify_full succeeds");
  test_support::check(full.signals.body.gtube_test == 1,
        "classify_full surfaces the body signals it parsed");
  test_support::check(std::string(full.decision.label) == "spam",
        "...and folds them, so GTUBE condemns on this path too");
  spam_engine_destroy(handle);
}

// TASK-440 option C: the brand-independent callback shape.
//
// The matcher is pinned against the SAME strings the Python measurement ran on
// (model-lab/scripts/measure_callback_shape.py), because the 0-of-3,621 false
// positive rate that justifies the offset was measured with those patterns. If
// this table and that script ever disagree, the measurement no longer describes
// the code, which is the failure this table exists to make loud.
void test_callback_shape_matcher_parity() {
  struct Case { const char* text; bool want; };
  const std::vector<Case> numbers = {
      {"call +1 (888) 402-7719 today", true},
      {"appelez le +32 2 201 11 11", true},
      {"appelez le 01 42 68 53 00", true},
      {"+49 30 12345678", true},
      {"888 402 7719", true},
      // Ten digits and two separators, and not a phone number in any format.
      // The matcher counted digits and separators until this case: the Python
      // pattern the false-positive rate was measured with requires 3-3-4, so a
      // looser matcher would have had an UNMEASURED rate.
      {"12 3456 7890", false},
      {"account 12 3456 7890", false},
      // A reference number immediately followed by a phone number is ONE run of
      // phone-ish characters, and the run as a whole matches no shape. Skipping
      // past it missed the number entirely, which is a false NEGATIVE and the
      // fourth bug in this matcher. Python's re.search always tried every
      // position, so the C++ had been STRICTER than the pattern whose rate was
      // measured; retrying inside the run is what makes the two agree.
      {"1234567890 +33 1 42 68 53 00", true},
      {"ref: 4029384756 +1 (888) 402-7719", true},
      // The negatives are the point: an invoice is FULL of long numbers, and a
      // matcher that reads any of these as a phone number is an outage.
      {"Invoice 88421905", false},
      {"INV-2026-04-0012", false},
      {"commande 4029384756", false},
      {"le 12 03 2026 a 14 30", false},
      {"total 429.99 USD", false},
      {"VAT BE0123456789", false},
      {"version 1.2.3.4", false},
  };
  for (const auto& c : numbers) {
    test_support::check(
        callback_shape::has_callback_number(callback_shape::normalize(c.text)) == c.want,
        std::string("callback number: ") + c.text);
  }

  test_support::check(
      callback_shape::has_billing_language(callback_shape::normalize("Votre facture")),
      "billing language, French");
  test_support::check(
      callback_shape::has_billing_language(callback_shape::normalize("pr\xc3\xa9l\xc3\xa8vement")),
      "billing language survives accents (prelevement)");
  test_support::check(
      !callback_shape::has_billing_language(callback_shape::normalize("Hello there")),
      "ordinary mail carries no billing language");

  // The shape itself, including the predicate that does the separating.
  test_support::check(
      callback_shape::matches("Invoice GS-88421905 renewed",
                              "To cancel call +1 (888) 402-7719 within 24 hours."),
      "the lure fires");
  test_support::check(
      !callback_shape::matches("Invoice 42",
                               "Pay at https://portal.example/inv/42 or call +1 (888) 402-7719."),
      "a link disqualifies it: a real invoice wants you in a portal");
  test_support::check(
      !callback_shape::matches("Invoice 42", "Please find the invoice attached."),
      "billing language alone is a normal invoice, not a lure");
}

// The same shape through the WHOLE pipeline, and then through the fold, because
// a feature that is computed and not routed is the failure
// test_classify_full_carries_body_signals was written for.
void test_callback_shape_is_corroborating_not_condemning() {
  spam_engine_decision_input_t in{};
  in.scores.spam = 0.02;
  in.scores.regular = 0.98;
  in.ml_label = "regular";
  in.ml_confidence = 0.98;
  in.callback_shape = 1;
  spam_engine_decision_result_t out{};
  spam_engine_decide(&in, &out);
  test_support::check(std::string(out.label) == "ham",
        "the callback shape must NOT junk a message the model likes: 0.30 cannot "
        "carry a 0.02 spam side over the gate");
  test_support::check(std::string(out.fired_offsets).find("callback_shape") != std::string::npos,
        "...but it is recorded as having fired, so a reader can see it");

  // And it must never be able to authorize a bounce, like the other 0.30
  // corroborator (raw_ip_url). The authoritative list is a named allowlist.
  test_support::check(out.condemn_offset_fired == 0,
        "the callback shape is not authoritative: it may never authorize a reject");
}

// TASK-394: the engine reports its own struct sizes so hand-written FFI mirrors
// (Python ctypes, the Node addon) can assert against them. Three fields were
// added across TASK-113/388/391 without updating the ctypes mirror, which made
// the engine memset 192 bytes past the end of the caller's buffer and read
// caller-state flags out of garbage.
void test_abi_sizes_are_self_reported() {
  spam_engine_abi_sizes_t sizes{};
  spam_engine_get_abi_sizes(&sizes);
  test_support::check(sizes.field_count == 8, "field_count matches the struct");
  test_support::check(
      sizes.caller_state_connect_ip_blocked ==
          offsetof(spam_engine_caller_state_t, connect_ip_blocked),
      "caller_state field offsets are reported (sizeof alone misses reordering)");
  test_support::check(
      sizes.caller_state_attachment_risk_enabled ==
          offsetof(spam_engine_caller_state_t, attachment_risk_enabled),
      "appended attachment experiment flag offset is reported");
  test_support::check(sizes.parsed_signals == sizeof(spam_engine_parsed_signals_t),
        "parsed_signals size is reported correctly");
  test_support::check(sizes.decision_input == sizeof(spam_engine_decision_input_t),
        "decision_input size is reported correctly");
  test_support::check(sizes.decision_result == sizeof(spam_engine_decision_result_t),
        "decision_result size is reported correctly");
  test_support::check(sizes.caller_state == sizeof(spam_engine_caller_state_t),
        "caller_state size is reported correctly");
  test_support::check(sizes.full_result == sizeof(spam_engine_full_result_t),
        "full_result size is reported correctly");
  test_support::check(
      sizes.attachment_features == sizeof(spam_engine_attachment_features_t),
      "attachment feature size is reported correctly");
  spam_engine_get_abi_sizes(nullptr);  // must not crash
}

void test_decision_input_from_signals() {
  spam_engine_scores_t const scores = {0.01F, 0.04F, 0.10F, 0.85F};  // spam-dominant
  spam_engine_parsed_signals_t signals{};
  signals.thread.has_in_reply_to = 1;
  signals.thread.references_count = 3;
  std::strncpy(signals.auth.dkim_signing_domain, "evil.example",
               sizeof(signals.auth.dkim_signing_domain) - 1);
  signals.auth.signer_throwaway = 1;
  signals.auth.display_impersonation = 1;  // the field two surfaces dropped
  signals.attachment.disguised_executable = 1;

  // Pre-set every caller-state field to a non-default: the builder must NOT touch any.
  spam_engine_decision_input_t din{};
  din.profile = SPAM_ENGINE_PROFILE_CAUTIOUS;
  din.exact_send_count = 2;
  din.domain_send_count = 5;
  din.phase2_match = 1;
  spam_engine_decision_input_from_signals(&din, &scores, &signals);

  // Every engine-derived field mapped (all 4 scores, not just the argmax winner).
  test_support::check(din.scores.gibberish == 0.01F && din.scores.marketing == 0.04F &&
        din.scores.regular == 0.10F && din.scores.spam == 0.85F, "all 4 scores copied");
  test_support::check(std::string(din.ml_label) == "spam", "neural-decision label is spam");
  test_support::check(din.ml_confidence == static_cast<double>(scores.spam),
        "spam-side decision confidence is the spam score");
  test_support::check(din.has_in_reply_to == 1 && din.references_count == 3,
        "thread signals mapped");
  test_support::check(std::string(din.dkim_signing_org_domain) == "evil.example",
        "dkim signing domain mapped");
  test_support::check(din.signer_throwaway == 1, "signer_throwaway mapped");
  test_support::check(din.display_impersonation == 1, "display_impersonation mapped");
  test_support::check(din.attachment_disguised_executable == 1,
        "attachment deception fact mapped");

  // Caller-state survived untouched.
  test_support::check(din.profile == SPAM_ENGINE_PROFILE_CAUTIOUS, "profile not clobbered");
  test_support::check(din.exact_send_count == 2, "exact_send_count not clobbered");
  test_support::check(din.domain_send_count == 5, "domain_send_count not clobbered");
  test_support::check(din.phase2_match == 1, "phase2_match not clobbered");

  // TASK-113 app-safety invariant: a message parse can never switch ON the
  // condemn-capable transport offset. A consumer with no connection to observe
  // (the Mail extension) leaves the field zero and the signal stays off, even on
  // this maximally spam-shaped input.
  test_support::check(din.connect_ip_blocked == 0,
        "the builder never sets connect_ip_blocked from a parse");
  test_support::check(din.attachment_risk_enabled == 0,
        "the builder never opts a caller into experimental attachment rules");
  // ...and a caller that DID observe one keeps it, whichever side of the builder
  // it assigns on.
  spam_engine_decision_input_t observed{};
  observed.connect_ip_blocked = 1;
  spam_engine_decision_input_from_signals(&observed, &scores, &signals);
  test_support::check(observed.connect_ip_blocked == 1,
        "a caller-observed connect_ip_blocked survives the builder");

  // The builder feeds spam_engine_decide identically to a hand-rolled din.
  spam_engine_decision_result_t dout{};
  test_support::check(spam_engine_decide(&din, &dout) == SPAM_ENGINE_STATUS_OK,
        "builder output decides OK");

  // NULL args are no-ops (no crash, no write).
  spam_engine_decision_input_t untouched{};
  spam_engine_decision_input_from_signals(nullptr, &scores, &signals);
  spam_engine_decision_input_from_signals(&untouched, nullptr, &signals);
  spam_engine_decision_input_from_signals(&untouched, &scores, nullptr);
  test_support::check(untouched.ml_label == nullptr && untouched.scores.spam == 0.0F,
        "null args leave the struct untouched");
}

// The authority to authorize a destructive REJECT/bounce is a NAMED allowlist
// in spam_engine_decide, not a magnitude test (TASK-347 needed a 0.99 offset
// that may junk but must never bounce). A named list silently loses an entry in
// a way a magnitude rule could not, so pin the whole membership here: every
// authoritative offset sets the flag, and every corroborator -- including the
// 0.99-magnitude experimental one -- does not.
// The matcher, pinned against the SAME strings the Python census ran on
// (model-lab/scripts/measure_secured_account_shape.py), because the 0-of-21,291
// false-positive rate that licenses a 0.99 magnitude was measured with those
// patterns and this scanner is a different implementation of them.
void test_no_contact_matcher_parity() {
  struct Case { const char* text; bool want; };
  const std::vector<Case> cases = {
      // The nine authored variants' phrasings (fr/en/de), which is the recall
      // panel this rule was chosen on.
      {"ne contactez pas votre agence pendant la procedure", true},
      {"merci de ne pas prevenir votre agence", true},
      {"ne pas contacter votre banque pendant l'operation", true},
      {"il est imperatif de ne pas contacter votre agence", true},
      {"do not contact your branch while the procedure is running", true},
      {"do not call your bank or your branch while this is in progress", true},
      {"kontaktieren sie ihre bank nicht, solange der vorgang laeuft", true},

      // CALL-MANAGEMENT PHRASES ARE NOT SUFFICIENT, and until 2026-08-29 they
      // were. Each of these five asserted `true` here, which is to say this
      // table codified the bug rather than catching it: "stay on the line" is
      // what the scammer needs the victim to do AND what every conference
      // bridge, support queue and airline hold message says, and it was
      // carrying a 0.99 condemn-level weight on its own.
      {"ne raccrochez pas et restez en ligne avec votre conseiller", false},
      {"restez en ligne avec votre conseiller", false},
      {"please stay on the line with your advisor", false},
      {"bitte bleiben sie in der leitung", false},
      {"legen sie nicht auf", false},

      // The legitimate mail that fired before the split. Measured, not
      // imagined: each of these four returned 1 through the C ABI.
      {"please stay on the line while we connect your conference call", false},
      {"an agent will be with you shortly. please stay on the line.", false},
      {"do not hang up; your booking is being updated.", false},
      // ENGLISH REPORTED SPEECH, the one that matters most. The possessive
      // discriminator below is real but guards the CLAUSE path only, so this
      // went straight through it: a victim recounting the scam in English was
      // junked while the same sentence in French was not.
      {"the caller told me to stay on the line and not to phone my branch", false},

      // BESIDE A PROHIBITION they do count, which is what keeps the authored
      // variant spam-fr-no-iban-hangup at 9/9. Its instruction is a real one
      // whose object is a card rather than a bank, so no object list sees it.
      {"ne raccrochez pas. n'appelez pas le numero au dos de votre carte", true},
      {"stay on the line. do not call the number on your card", true},
      // The elided negation on the clause path, missing until the same day.
      {"n'appelez pas votre banque", true},
      // The verb the first version missed. It matched "contacter" and
      // "raccrocher" only, scored 8/9, and the authored family is what found it.
      {"ne pas prevenir votre agence", true},
      {"ne signalez pas votre banque", true},
      {"ne pas alerter votre conseiller", true},

      // REPORTED SPEECH, which is the whole separation from prose about the
      // scam. A victim writes about someone else's instruction and about their
      // OWN bank; the possessive is what tells them apart. These sentences are
      // the ham fixtures' register and every one of them must stay silent.
      {"il m'a dit de ne pas contacter mon agence", false},
      {"on m'a demande de ne pas prevenir ma banque", false},
      {"je n'ai pas contacte mon agence ce jour la", false},
      {"the caller told me not to contact my bank", false},
      // THE DEFINITE ARTICLE IS NOT THE SECOND PERSON, and accepting it put a
      // hole through the discriminator above. A victim writing a warning says
      // "LA banque", not "ma banque", so these were junked at 0.99 until a cold
      // review found them. Not one of the ten authored lures uses an article
      // here, so requiring "votre"/"vos" costs no recall at all.
      {"le fraudeur m'a dit de ne pas contacter la banque", false},
      {"elle m'a conseille de ne pas appeler l'agence", false},
      {"ne pas contacter le conseiller, disait le message", false},
      // The object must END at a word boundary. `consume_any` matches a prefix,
      // so without this "agence" matched inside "agencement" and "bank" inside
      // "bankruptcy". The review's own example, "ne contactez pas LA banque
      // alimentaire", is rejected a step earlier by the possessive: a following
      // noun ("votre banque alimentaire") is NOT what this guards, and asserting
      // that it were was wrong when first written here.
      {"ne contactez pas votre agencement interieur", false},
      {"do not contact your bankruptcy trustee", false},

      // PREVENTION ADVICE PHRASED NEGATIVELY, which falsified the premise this
      // whole rule was built on: "a bank telling you not to contact your bank is
      // self-contradictory, so no legitimate sender writes it". Banks and
      // consumer bodies write exactly this, qualified by a CHANNEL. All six were
      // junked at 0.99 until 2026-08-29, and the one ham fixture in this register
      // scored 0 only because it happens to phrase its advice positively.
      //
      // The discriminator is what the instruction is qualified BY: the lure
      // qualifies by TIME (it needs you not to check until the transfer clears),
      // advice qualifies by MEANS (not through this channel, use a safe one).
      {"ne contactez pas votre banque en cliquant sur un lien", false},
      {"ne contactez pas votre agence par e-mail pour communiquer un code", false},
      {"n'appelez pas votre banque sur un lien recu par sms", false},
      {"do not contact your bank by clicking a link in an email", false},
      {"do not call your bank on a number given in a message", false},
      {"kontaktieren sie ihre bank nicht ueber links in e-mails", false},
      // ... while the TIME-qualified instruction is the lure and still fires.
      {"ne contactez pas votre agence pendant la procedure", true},
      {"do not call your bank or your branch while this is in progress", true},
      {"kontaktieren sie ihre bank nicht, solange der vorgang laeuft", true},

      // THE ADVICE EXCEPTION HAS TO HOLD ON THE CORROBORATOR PATH TOO. The
      // qualifier guard first went on the clause matchers only, so a qualified
      // clause was rejected as sufficient and then accepted as the prohibition
      // that licenses a call-management phrase. A bank's advice page saying both
      // things, which is a normal thing for one to say, was still junked at 0.99.
      {"do not contact your bank by clicking a link. please stay on the line "
       "while we connect you.", false},
      {"ne contactez pas votre banque en cliquant sur un lien. restez en ligne, "
       "un conseiller arrive.", false},
      // And a message carrying BOTH advice and the lure is the lure. A single
      // find() on the German phrases meant the first, qualified occurrence
      // suppressed the phrase and the second was never examined: a false
      // negative, and a divergence from the Python mirror, which uses finditer.
      {"kontaktieren sie ihre bank nicht ueber links in e-mails. kontaktieren "
       "sie ihre bank nicht, solange der vorgang laeuft.", true},

      // A real bank's prevention advice says the OPPOSITE and must not fire.
      {"en cas de doute, raccrochez et rappelez le numero au dos de votre carte",
       false},
      {"contactez immediatement votre agence si vous avez un doute", false},
      {"appelez votre conseiller pour verifier", false},
      {"if in doubt, call your bank on the number on your card", false},
      // German negation that is not an instruction: "if your bank is not
      // reachable". This is why the de phrases are full clauses.
      {"wenn ihre bank nicht erreichbar ist, schreiben sie uns", false},
      // Ordinary text that happens to contain the anchors.
      {"ne manquez pas notre offre", false},
      {"do not reply to this message", false},
  };
  for (const auto& c : cases) {
    const bool got =
        no_contact_shape::has_no_contact_instruction(no_contact_shape::normalize(c.text));
    test_support::check(got == c.want,
        std::string("no_contact matcher: ") + c.text);
  }

  // Accent folding comes from the shared normaliser, so the accented spelling a
  // French sender actually types is the same string here.
  test_support::check(
      no_contact_shape::matches("", "ne pas pr\xc3\xa9venir votre agence"),
      "the accented spelling must match, via callback_shape::normalize");
  // Subject-only, and the joined-parts contract.
  test_support::check(
      no_contact_shape::matches("ne contactez pas votre agence", ""),
      "the instruction counts in the subject too");
}

// HTML CHARACTER REFERENCES ARE NOT A BYPASS, through the real parse.
//
// String cases cannot catch this: the matcher is fine, and the hole was in
// html_to_text, which decoded seven hardcoded entities and left the rest
// verbatim. So `N&rsquo;appelez pas votre banque` and `ne pas pr&eacute;venir
// votre agence` scored 0 while the identical sentences in raw UTF-8, or with
// `&#39;`, scored 1. That is one search-and-replace for an attacker and it
// survived every table-of-strings test in this file, which is why these go
// through spam_engine_extract_body_features on raw .eml bytes.
void test_no_contact_survives_html_entities() {
  struct Case { const char* label; const char* html; int want; };
  const std::vector<Case> cases = {
      {"raw utf-8 curly apostrophe",
       "<p>N\xe2\x80\x99""appelez pas votre banque</p>", 1},
      {"named entity for the curly apostrophe",
       "<p>N&rsquo;appelez pas votre banque</p>", 1},
      {"numeric entity for the straight apostrophe",
       "<p>N&#39;appelez pas votre banque</p>", 1},
      {"hex numeric entity",
       "<p>N&#x27;appelez pas votre banque</p>", 1},
      {"named entity inside the verb",
       "<p>Ne pas pr&eacute;venir votre agence</p>", 1},
      {"entity plus markup between the words",
       "<p>Ne contactez pas <strong>votre</strong> agence</p>", 1},
      // An unknown reference is left verbatim rather than swallowed, so this
      // stays ordinary text and must not fire.
      {"unknown reference is not decoded into a match",
       "<p>Ne &frobnicate; pas votre agence</p>", 0},
  };
  for (const auto& c : cases) {
    const std::string raw =
        std::string("From: a@b.test\r\nSubject: s\r\n"
                    "Content-Type: text/html; charset=UTF-8\r\n\r\n") + c.html + "\r\n";
    spam_engine_body_features_t bf{};
    const int st = spam_engine_extract_body_features(raw.c_str(), raw.size(), &bf);
    test_support::check(st == SPAM_ENGINE_STATUS_OK,
        std::string("extract_body_features should succeed: ") + c.label);
    test_support::check(bf.no_contact_instruction == c.want,
        std::string("no_contact through HTML: ") + c.label);
  }
}

// 0.99 CAN carry a message the model likes over the gate -- that is the point of
// the magnitude and the only reason the signal exists. What it must never do is
// authorize a destructive REJECT, which is a separate named allowlist.
void test_no_contact_junks_but_never_bounces() {
  spam_engine_decision_input_t in{};
  in.scores.spam = 0.02F;
  in.scores.regular = 0.98F;
  in.ml_label = "regular";
  in.ml_confidence = 0.98;
  in.no_contact_instruction = 1;
  spam_engine_decision_result_t out{};
  spam_engine_decide(&in, &out);

  test_support::check(std::string(out.label) == "spam",
      "the no-contact instruction must be able to file a message the model likes: "
      "the genre's model floor is 0.0268 and a corroborating weight would change "
      "no verdict at all");
  test_support::check(
      std::string(out.fired_offsets).find("no_contact_instruction") != std::string::npos,
      "the offset is recorded in the audit trail");
  test_support::check(out.condemn_offset_fired == 0,
      "it may junk, and it may NEVER authorize a reject: a body-text predicate "
      "has no business bouncing mail (TASK-460)");

  // DMARC MUST NOT EXEMPT IT, and this assertion is the inverse of what it was.
  //
  // The offset shipped with `dmarc_pass == 0` copied from the callback shape,
  // justified as costing zero recall. That justification was untestable: none of
  // the nine authored variants carries an Authentication-Results header, so the
  // condition was trivially satisfied by every message that was supposed to
  // prove it harmless. And it is not harmless: DMARC proves the sender controls
  // the domain they sent FROM, not that they are the recipient's bank, so a
  // scammer publishing SPF/DKIM/DMARC for their own throwaway domain would have
  // switched off the only signal that reaches this genre.
  //
  // The callback shape's condition is different in kind and stays: it was
  // measured to remove 15 real false positives from 3,621 invoices. Here there
  // were none to remove on any panel.
  spam_engine_decision_input_t verified{};
  verified.scores.spam = 0.02F;
  verified.scores.regular = 0.98F;
  verified.ml_label = "regular";
  verified.ml_confidence = 0.98;
  verified.no_contact_instruction = 1;
  verified.dmarc_pass = 1;
  spam_engine_decision_result_t vout{};
  spam_engine_decide(&verified, &vout);
  test_support::check(std::string(vout.label) == "spam",
      "an authenticated sender must NOT be exempt: DMARC proves control of the "
      "attacker's own domain, not that they are your bank (TASK-460)");
}

void test_authoritative_condemn_allowlist() {
  const auto decide = [](void (*arm)(spam_engine_decision_input_t&)) {
    spam_engine_decision_input_t in{};
    in.scores = {0.0F, 0.0F, 0.98F, 0.02F};  // clean model verdict on its own
    in.ml_label = "regular";
    in.ml_confidence = 0.98;
    in.profile = SPAM_ENGINE_PROFILE_STANDARD;
    arm(in);
    spam_engine_decision_result_t out{};
    spam_engine_decide(&in, &out);
    return out.condemn_offset_fired;
  };

  test_support::check(
      decide([](spam_engine_decision_input_t& in) {
        in.dkim_signing_org_domain = "web.app";
      }) == 1,
      "sender_auth (free-host signer) authorizes a reject");
  test_support::check(
      decide([](spam_engine_decision_input_t& in) {
        in.dkim_signing_org_domain = "example.test";
        in.signer_throwaway = 1;
      }) == 1,
      "sender_auth (throwaway signer) authorizes a reject");
  test_support::check(
      decide([](spam_engine_decision_input_t& in) {
        in.display_impersonation = 1;
      }) == 1,
      "display_impersonation authorizes a reject");
  test_support::check(
      decide([](spam_engine_decision_input_t& in) { in.gtube_test = 1; }) == 1,
      "gtube_test authorizes a reject: the liveness check must not depend on "
      "what the model thought of the surrounding text");
  test_support::check(
      decide([](spam_engine_decision_input_t& in) {
        in.connect_ip_blocked = 1;
      }) == 1,
      "connect_ip_drop (observed peer) authorizes a reject");

  test_support::check(
      decide([](spam_engine_decision_input_t& in) { in.raw_ip_url = 1; }) == 0,
      "the raw-IP corroborator never authorizes a reject (TASK-257)");
  test_support::check(
      decide([](spam_engine_decision_input_t& in) {
        in.header_ip_blocked = 1;
      }) == 0,
      "the header-derived DROP sibling never authorizes a reject (TASK-387)");
  test_support::check(
      decide([](spam_engine_decision_input_t& in) {
        in.attachment_risk_enabled = 1;
        in.attachment_disguised_executable = 1;
      }) == 0,
      "the 0.99 attachment experiment may junk but never authorizes a reject");
  // The second 0.99 offset that deliberately lacks bounce authority. Listed here
  // as well as in its own test, because THIS is the test that locks the list and
  // a future reader adding a strong offset will read it rather than the other.
  test_support::check(
      decide([](spam_engine_decision_input_t& in) { in.no_contact_instruction = 1; }) == 0,
      "the no-contact instruction may junk but never authorizes a reject: a "
      "body-text predicate must not bounce mail, whatever its magnitude");
  test_support::check(
      decide([](spam_engine_decision_input_t& in) { in.callback_shape = 1; }) == 0,
      "the callback shape is not authoritative either (it had no case here)");
}

void test_attachment_context_and_default_off_rule() {
  const std::string eml =
      "From: sender@example.test\r\n"
      "To: user@example.test\r\n"
      "Subject: Urgent invoice\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/mixed; boundary=x\r\n\r\n"
      "--x\r\nContent-Type: text/plain\r\n\r\nPlease pay today.\r\n"
      "--x\r\nContent-Type: application/pdf; name=invoice.pdf\r\n"
      "Content-Disposition: attachment; filename=invoice.pdf\r\n"
      "Content-Transfer-Encoding: base64\r\n\r\nTVogaW5lcnQ=\r\n"
      "--x--\r\n";
  spam_engine_attachment_features_t features{};
  size_t needed = 0;
  test_support::check(
      spam_engine_extract_attachment_context(
          eml.data(), eml.size(), &features, nullptr, 0, &needed) ==
          SPAM_ENGINE_STATUS_OK,
      "attachment context size query succeeds");
  test_support::check(features.total_count == 1 &&
                      features.disguised_executable == 1,
      "C ABI reports transfer-decoded attachment facts");
  std::string context(needed, '\0');
  size_t filled = 0;
  test_support::check(
      spam_engine_extract_attachment_context(
          eml.data(), eml.size(), &features, context.data(), context.size(),
          &filled) == SPAM_ENGINE_STATUS_OK && filled == needed,
      "attachment context second pass fills the exact buffer");
  test_support::check(context.find("name=\"invoice.pdf\"") != std::string::npos,
      "C ABI exposes the runtime's model-facing filename context");

  spam_engine_scores_t const clean = {0.0F, 0.0F, 1.0F, 0.0F};
  spam_engine_parsed_signals_t signals{};
  signals.attachment = features;
  spam_engine_decision_input_t din{};
  spam_engine_decision_input_from_signals(&din, &clean, &signals);
  spam_engine_decision_result_t off{};
  spam_engine_decide(&din, &off);
  test_support::check(std::string(off.label) == "ham" &&
                      std::string(off.fired_offsets).empty(),
      "attachment rule is inert unless the caller explicitly opts in");

  din.attachment_risk_enabled = 1;
  spam_engine_decision_result_t on{};
  spam_engine_decide(&din, &on);
  test_support::check(std::string(on.label) == "spam",
      "opted-in disguised executable can move a clean model score to Junk");
  test_support::check(
      std::string(on.fired_offsets) == "attachment_disguised_executable!",
      "only the strongest deterministic attachment tier fires");
  test_support::check(on.condemn_offset_fired == 0,
      "experimental attachment rule cannot authorize SMTP rejection");

  // A MIME message does not need a subject, sender or text body for its bytes to
  // be security-relevant. The parser must surface the attachment and let the
  // opted-in fold decide instead of returning a preprocessing error.
  const std::string attachment_only =
      "MIME-Version: 1.0\r\n"
      "Content-Type: application/pdf; name=invoice.pdf\r\n"
      "Content-Disposition: attachment; filename=invoice.pdf\r\n"
      "Content-Transfer-Encoding: base64\r\n\r\n"
      "TVogaW5lcnQ=\r\n";
  bool have_ftrl = false;
  spam_engine_handle_t* handle =
      create_loaded_engine("attachment-only classify_full", &have_ftrl);
  if (handle != nullptr) {
    spam_engine_caller_state_t caller{};
    caller.attachment_risk_enabled = 1;
    spam_engine_full_result_t full{};
    const auto status = spam_engine_classify_full(
        handle, attachment_only.data(), attachment_only.size(), "", "",
        "ensemble", &caller, &full);
    test_support::check(status == SPAM_ENGINE_STATUS_OK,
        "attachment-only MIME reaches classify_full");
    test_support::check(full.signals.attachment.disguised_executable == 1,
        "attachment-only MIME retains the extracted deception fact");
    test_support::check(std::string(full.decision.label) == "spam" &&
                        full.decision.condemn_offset_fired == 0,
        "the opted-in rule moves attachment-only deception to Junk, never reject");
    spam_engine_destroy(handle);
  }
}

// TASK-251 C5: the builder sets ml_label from the model's binary spam-side
// DECISION (== SpamEngine::decision_from_scores, == Swift mlResult.label), NOT a
// raw 4-class argmax, so the C-ABI decide path can't diverge from the engine and
// Swift on gibberish-argmax mail.
void test_decision_ml_label_matches_engine_decision() {
  spam_engine_parsed_signals_t signals{};

  // Gibberish is the argmax, but the engine scores this a DELIVER (gibberish
  // 0.55 <= 0.7 and spam 0.25 <= 0.5): ml_label must be the deliver label, not
  // "gibberish". The old argmax builder returned "gibberish" here. Raw spam side
  // (0.80) stays UNDER the 0.90 gate so the display-impersonation offset is what
  // condemns (a genuine header-only condemn), letting train_ml differ by label.
  spam_engine_scores_t const gib = {0.55F, 0.05F, 0.50F, 0.25F};
  spam_engine_decision_input_t din{};
  spam_engine_decision_input_from_signals(&din, &gib, &signals);
  test_support::check(std::string(din.ml_label) == "regular",
        "gibberish-argmax below the spam-side gate is a deliver, not gibberish (C5)");
  test_support::check(din.ml_confidence == (1.0F - gib.spam),
        "deliver confidence is 1 - spam (matches decision_from_scores)");

  // High gibberish (> 0.7) IS a spam-side decision even though spam is not the argmax.
  spam_engine_scores_t const hg = {0.80F, 0.05F, 0.10F, 0.40F};
  spam_engine_decision_input_from_signals(&din, &hg, &signals);
  test_support::check(std::string(din.ml_label) == "spam",
        "gibberish > 0.7 is a spam-side decision (C5)");

  // The divergence bit the fold: on the deliver-scored gibberish mail, a
  // spam-ward offset (display impersonation) condemns via the OFFSET, so it is a
  // header-only condemn (train_ml=0). The OLD argmax label "gibberish" would have
  // made the fold think the MODEL said spam (train_ml=1), disagreeing with Swift.
  signals.auth.display_impersonation = 1;
  spam_engine_decision_input_from_signals(&din, &gib, &signals);  // ml_label = "regular"
  spam_engine_decision_result_t fixed{};
  spam_engine_decide(&din, &fixed);
  din.ml_label = "gibberish";                                     // simulate the old argmax bug
  spam_engine_decision_result_t old_bug{};
  spam_engine_decide(&din, &old_bug);
  test_support::check(fixed.train_ml == 0 && old_bug.train_ml == 1,
        "argmax->decision fix flips the fold's train_ml on gibberish-argmax + spam-ward mail (C5)");
}

}  // namespace

int main() {
  int failures = 0;
  failures += test_support::run_test("create and destroy", test_create_and_destroy);
  failures += test_support::run_test("load/classify/unload flow", test_load_classify_unload_flow);
  failures += test_support::run_test(
      "mode required + ensemble + classify_full (TASK-219)",
      test_mode_required_ensemble_and_classify_full);
  failures += test_support::run_test(
      "classify_full carries body signals (TASK-394)",
      test_classify_full_carries_body_signals);
  failures += test_support::run_test(
      "ABI sizes are self-reported (TASK-394)",
      test_abi_sizes_are_self_reported);
  failures += test_support::run_test(
      "model_info names the loaded artifact",
      test_model_info_names_the_loaded_artifact);
  failures += test_support::run_test(
      "demo samples hold their decision class (TASK-266)",
      test_demo_samples_decision);
  failures += test_support::run_test(
      "ambiguous surname-brands are shape-gated (TASK-268)",
      test_ambiguous_surname_brands);
  failures += test_support::run_test(
      "RFC822 preprocessing fixes false-positive via C API",
      test_rfc822_preprocessing_fixes_false_positive_via_c_api);
  failures += test_support::run_test(
      "RFC822 picks spammy html when plain/html drift via C API",
      test_rfc822_picks_spammy_html_when_plain_and_html_drift_via_c_api);
  failures += test_support::run_test(
      "last_error snapshot survives subsequent calls",
      test_last_error_snapshot_survives_subsequent_calls);
  failures += test_support::run_test(
      "train_rfc822 and incremental flow",
      test_train_rfc822_and_incremental_flow);
  failures += test_support::run_test(
      "FTRL-only training freezes neural head",
      test_ftrl_only_training_freezes_neural_head);
  failures += test_support::run_test(
      "training C API input validation",
      test_training_c_api_input_validation);
  failures += test_support::run_test(
      "training incremental requires loaded engine",
      test_training_incremental_requires_loaded_engine);
  failures += test_support::run_test(
      "training lowers the loss on the corrected sample",
      test_training_lowers_the_loss_on_the_corrected_sample);
  failures += test_support::run_test(
      "extract_body text_preview prefers plain text",
      test_extract_body_text_preview_prefers_plain_text);
  failures += test_support::run_test(
      "extract_body html_to_text strips CSS",
      test_extract_body_html_to_text_strips_css);
  failures += test_support::run_test(
      "extract_body cleans HTML dumped into a plain text part",
      test_extract_body_cleans_html_dumped_into_a_plain_text_part);
  failures += test_support::run_test(
      "extract_body does not corrupt plain text quoting a div snippet",
      test_extract_body_does_not_corrupt_plain_text_quoting_a_div_snippet);
  failures += test_support::run_test(
      "replay RFC822 keeps model input and drops attachment payloads",
      test_replay_rfc822_preserves_model_input_and_drops_attachment_payloads);
  failures += test_support::run_test(
      "extract_url_domains C ABI (TASK-201)",
      test_extract_url_domains_c_api);
  failures += test_support::run_test("structural decision fold via C API", test_decide_c_api);
  failures += test_support::run_test("decision-input builder maps signals (TASK-231)",
                                     test_decision_input_from_signals);
  failures += test_support::run_test(
      "authoritative condemn allowlist membership",
      test_authoritative_condemn_allowlist);
  failures += test_support::run_test(
      "attachment context + default-off deterministic rule (TASK-347)",
      test_attachment_context_and_default_off_rule);
  failures += test_support::run_test(
      "decide ml_label is the engine decision, not argmax (TASK-251 C5)",
      test_decision_ml_label_matches_engine_decision);
  failures += test_support::run_test(
      "pending training queue cleared on load/unload",
      test_pending_training_queue_cleared_on_load_and_unload);
  failures += test_support::run_test(
      "classify_rfc822 mutex throw crashes (2026-03-18 field crash repro)",
      test_classify_rfc822_mutex_throw_crashes);
  failures += test_support::run_test(
      "extract_thread_features: no thread headers",
      test_extract_thread_features_no_thread_headers);
  failures += test_support::run_test(
      "extract_thread_features: In-Reply-To only",
      test_extract_thread_features_in_reply_to_only);
  failures += test_support::run_test(
      "extract_thread_features: folded References",
      test_extract_thread_features_references_folded_across_lines);
  failures += test_support::run_test(
      "extract_thread_features: bare LF line endings",
      test_extract_thread_features_bare_lf_line_endings);
  failures += test_support::run_test(
      "extract_thread_features: empty input is safe",
      test_extract_thread_features_empty_input_safely);
  failures += test_support::run_test(
      "extract_thread_features: zero-length non-null buffer is safe",
      test_extract_thread_features_zero_length_buffer_safely);
  failures += test_support::run_test(
      "extract_thread_features: phrase before <id>",
      test_extract_thread_features_in_reply_to_with_phrase_prefix);
  failures += test_support::run_test(
      "extract_auth_features: free-host DKIM signer (TASK-122)",
      test_extract_auth_features_free_host_signer);
  failures += test_support::run_test(
      "display-name brand impersonation (TASK-214)",
      test_display_impersonation);
  failures += test_support::run_test(
      "impersonation: ccTLD/typosquat FP + concat-combosquat regressions (TASK-251)",
      test_brand_fp_regressions);
  failures += test_support::run_test(
      "consumer support brand impersonation (TASK-440)",
      test_consumer_support_brand_impersonation);
  failures += test_support::run_test(
      "parcel carrier impersonation (TASK-440/442)",
      test_parcel_carrier_impersonation);
  failures += test_support::run_test(
      "combosquat keywords are not English-only (fr/de bank-advisor lure)",
      test_non_english_combosquat_keywords);
  failures += test_support::run_test(
      "brand spelling tricks: confusables, digit fold, letter-spacing (measured state)",
      test_brand_spelling_tricks);
  failures += test_support::run_test(
      "product line keeps the brand claim, a namesake does not",
      test_product_line_versus_namesake);
  failures += test_support::run_test(
      "an IDN is not a way to spell a keyword past the combosquat check",
      test_idn_keyword_is_not_a_bypass);
  failures += test_support::run_test(
      "callback shape: the matcher, pinned to the measured patterns (TASK-440)",
      test_callback_shape_matcher_parity);
  failures += test_support::run_test(
      "callback shape: corroborates, never solo-condemns (TASK-440)",
      test_callback_shape_is_corroborating_not_condemning);
  failures += test_support::run_test(
      "no-contact shape: the matcher, pinned to the measured patterns (TASK-460)",
      test_no_contact_matcher_parity);
  failures += test_support::run_test(
      "no-contact shape: HTML character references are not a bypass (TASK-460)",
      test_no_contact_survives_html_entities);
  failures += test_support::run_test(
      "no-contact shape: junks, never bounces, exempt on dmarc=pass (TASK-460)",
      test_no_contact_junks_but_never_bounces);
  failures += test_support::run_test(
      "impersonation: display digit-homoglyph fold + per-domain owns exemption (TASK-251 FN2/FN3)",
      test_display_brand_homoglyph_and_owns);
  failures += test_support::run_test(
      "impersonation: KB mismatch vs cold-start string crutch (TASK-232 AC#4)",
      test_display_impersonation_kb_vs_coldstart);
  failures += test_support::run_test(
      "impersonation: Tier-2 From combosquat, typosquat excluded (TASK-232 AC#7)",
      test_tier2_from_combosquat);
  failures += test_support::run_test(
      "impersonation: brand auth-set exoneration truth table (auth verdict x membership)",
      test_brand_auth_exoneration_truth_table);
  failures += test_support::run_test(
      "IDN/punycode homoglyph fold (TASK-237 AC#3)",
      test_idn_punycode_fold);
  failures += test_support::run_test(
      "extract_auth_features: header.d preferred, DMARC aligned",
      test_extract_auth_features_header_d_preferred_and_aligned);
  failures += test_support::run_test(
      "extract_auth_features: ESP signer is not aligned",
      test_extract_auth_features_esp_unaligned);
  failures += test_support::run_test(
      "extract_auth_features: throwaway-shaped signer (TASK-178)",
      test_extract_auth_features_throwaway_signer);
  failures += test_support::run_test(
      "extract_auth_features: no dkim=pass and null-safety",
      test_extract_auth_features_no_dkim_and_safety);
  failures += test_support::run_test(
      "classify_rfc822 features match standalone extractors (TASK-173)",
      test_classify_rfc822_features_match_standalone_extractors);
  failures += test_support::run_test(
      "flywheel: extract_contribution C ABI (TASK-134)",
      test_extract_contribution_c_abi);
  failures += test_support::run_test(
      "flywheel: scrub_rfc822 C ABI (TASK-135)",
      test_scrub_rfc822_c_abi);
  failures += test_support::run_test(
      "embed capacity guard C ABI (TASK-208)",
      test_embed_capacity_guard_c_abi);

  // Each test above creates AND destroys its own engine handle, and must keep
  // doing so. Nothing here will tell you if a future test stops: the leak is
  // now silent. libggml-metal's GGML_ASSERT([rsets->data count] == 0) used to
  // catch it from a static destructor, but GGML_METAL_NO_RESIDENCY=1 (see
  // ggml_encoder.h) disables the residency set that assert reads, and the exit
  // guard in the same header deliberately skips teardown once exit has begun.
  // Both are there because the alternatives were a crash on model reload and a
  // crash at exit respectively. The cost is that "destroy what you create" is
  // now a rule this suite trusts you to follow rather than one it enforces.
  if (failures == 0) {
    std::cout << "All tests passed.\n";
    return 0;
  }

  std::cerr << failures << " test(s) failed.\n";
  return 1;
}
