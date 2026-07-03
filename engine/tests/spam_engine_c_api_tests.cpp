#include "spam_engine_c_api.h"
#include "spam_engine_handle_internal.h"
#include "brand_names.h"  // direct cover for the IDN/punycode fold (TASK-237 AC#3)
#include "brand_kb.h"     // direct cover for the multi-word KB IDN cousin route
#ifdef KLAR_HAVE_TRAINING
#include "spam_engine_training_c_api.h"  // premium; absent in the open-core build
#endif
#include "test_support.h"

#include <cmath>
#include <cstring>
#include <fstream>
#include <new>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unistd.h>  // _exit
#include <string>
#include <sys/wait.h>
#include <unistd.h>

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
      0.001f,
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
  test_support::check(std::abs(sum - 1.0f) < 1e-3f, "classify probabilities should sum to ~1");
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

void test_rfc822_preprocessing_fixes_false_positive_via_c_api() {
  const auto paths = test_support::model_paths();
  test_support::ensure_model_assets(paths, "RFC822 C API false-positive regression");

  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "spam_engine_create should return a handle");

  int status = spam_engine_load(
      handle, paths.model_path.string().c_str(), 0.001f, nullptr);
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
  test_support::check(not_spam > 0.90f,
        "classify_rfc822 should recover ham classification");
  test_support::check(rfc822_result.scores.spam < 0.10f,
        "classify_rfc822 noisy ham should not be classified as spam");

  spam_engine_destroy(handle);
}

void test_rfc822_picks_spammy_html_when_plain_and_html_drift_via_c_api() {
  const auto paths = test_support::model_paths();
  test_support::ensure_model_assets(paths, "RFC822 C API plain/html drift evasion");

  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "spam_engine_create should return a handle");

  int status = spam_engine_load(
      handle, paths.model_path.string().c_str(), 0.001f, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "load should succeed for C API drift test");

  const std::string drift_rfc822 =
      "From: Promo Team <promo@example.com>\r\n"
      "To: dev@example.com\r\n"
      "Subject: Weekly project agenda\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/alternative; boundary=\"d1\"\r\n"
      "\r\n"
      "--d1\r\n"
      "Content-Type: text/plain; charset=UTF-8\r\n"
      "\r\n"
      "Hi team, sharing the project agenda and action items for tomorrow.\r\n"
      "--d1\r\n"
      "Content-Type: text/html; charset=UTF-8\r\n"
      "\r\n"
      "<html><body><p><b>BUY VIAGRA NOW!!!</b> Limited time offer. CLICK HERE.</p></body></html>\r\n"
      "--d1--\r\n";

  spam_engine_result_t result{};
  status = spam_engine_classify_rfc822(
      handle,
      drift_rfc822.c_str(),
      drift_rfc822.size(),
      nullptr,
      nullptr,
      "ensemble",
      &result,
      nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "classify_rfc822 should succeed for drift case");
  test_support::check(result.scores.spam > 0.90f,
        "classify_rfc822 should treat spammy html alternative as high-spam");
  test_support::check(result.label == 3,
        "classify_rfc822 should label plain/html drift case as spam");

  spam_engine_destroy(handle);
}

// TASK-219: mode is a REQUIRED arg (no silent bypass), ensemble blends FTRL into
// the neural verdict without overriding it, and classify_full reports every
// stage in one call.
void test_mode_required_ensemble_and_classify_full() {
  const auto paths = test_support::model_paths();
  test_support::ensure_model_assets(paths, "mode + ensemble + classify_full");

  const std::string ftrl_path = (paths.model_path / "ftrl_baseline.bin").string();
  const bool have_ftrl = std::ifstream(ftrl_path, std::ios::binary).good();

  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "spam_engine_create should return a handle");
  int status = spam_engine_load(handle, paths.model_path.string().c_str(), 0.0f,
                                have_ftrl ? ftrl_path.c_str() : nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "load (with FTRL baseline) should succeed");

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
  test_support::check(r.ftrl_score < 0.0f, "neural mode must not consult FTRL");
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
    test_support::check(r.ftrl_score >= 0.0f, "ensemble must consult a warm FTRL");
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
  test_support::check(full.ensemble_spam >= 0.0f && full.ensemble_spam <= 1.0f,
                      "classify_full ensemble_spam must be a probability");
  if (have_ftrl) {
    test_support::check(full.ftrl_score >= 0.0f, "classify_full must report the FTRL stage");
    // Escalate-only invariant: the ensemble spam side never drops below raw
    // neural, and decided_by credits FTRL exactly when it raised the spam side.
    test_support::check(full.ensemble_spam >= full.neural_scores.spam - 1e-6f,
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

#ifdef KLAR_HAVE_TRAINING
void test_train_rfc822_and_incremental_flow() {
  const auto paths = test_support::model_paths();
  test_support::ensure_model_assets(paths, "training C ABI flow");

  const auto temp_model = test_support::create_temp_model_fixture(paths.model_path);
  const std::string temp_model_path = temp_model.path().string();

  spam_engine_handle_t* handle = spam_engine_create();
  test_support::check(handle != nullptr, "spam_engine_create should return a handle");

  int status = spam_engine_load(handle, temp_model_path.c_str(), 0.001f, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "load should succeed for training flow");

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

  float avg_loss = -1.0f;
  size_t trained_count = 0;
  status = spam_engine_train_incremental(handle, &avg_loss, &trained_count);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "train_incremental should succeed");
  test_support::check(trained_count == 2, "train_incremental should process 2 queued samples");
  test_support::check(std::isfinite(avg_loss), "train_incremental should return finite avg_loss");

  // Queue should be drained after a successful training pass.
  avg_loss = -1.0f;
  trained_count = 999;
  status = spam_engine_train_incremental(handle, &avg_loss, &trained_count);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "train_incremental on empty queue should succeed");
  test_support::check(trained_count == 0, "train_incremental on empty queue should report 0 samples");
  test_support::check(avg_loss == 0.0f, "train_incremental on empty queue should reset avg_loss to 0");

  status = spam_engine_save_model(handle, temp_model_path.c_str());
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "save_model should persist trained weights");

  // Also keep direct RFC822 training API covered.
  float direct_loss = -1.0f;
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
  // The trailing good sample survived; the head (trained) and poison are gone.
  trained_count = 999;
  status = spam_engine_train_incremental(handle, &avg_loss, &trained_count);
  test_support::check(status == SPAM_ENGINE_STATUS_OK && trained_count == 1,
        "the untried tail was re-queued (1 sample), head+poison not (TASK-251)");

  spam_engine_destroy(handle);
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

  status = spam_engine_save_model(nullptr, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
        "save_model should reject null handle");

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

  float avg_loss = -1.0f;
  size_t trained_count = 999;
  status = spam_engine_train_incremental(handle, &avg_loss, &trained_count);
  test_support::check(status == SPAM_ENGINE_STATUS_RUNTIME_ERROR,
        "train_incremental should fail when engine is not loaded");
  test_support::check(spam_engine_get_last_error(handle) != nullptr,
        "train_incremental failure should expose error text");
  test_support::check(trained_count == 0, "failed train_incremental should report 0 trained samples");

  // Failed call drains queue to avoid duplicate updates on retries.
  avg_loss = -1.0f;
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

  status = spam_engine_load(handle, temp_model_path.c_str(), 0.001f, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "load should succeed");

  float avg_loss = -1.0f;
  size_t trained_count = 999;
  status = spam_engine_train_incremental(handle, &avg_loss, &trained_count);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "train_incremental should succeed after load");
  test_support::check(
      trained_count == 0,
      "load should clear any queued training samples from pre-load phase");
  test_support::check(avg_loss == 0.0f, "empty queue after load should report avg_loss=0");

  status = spam_engine_add_training_sample(handle, sample.c_str(), sample.size(), nullptr, nullptr, 2);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "add_training_sample should queue while loaded");

  status = spam_engine_unload(handle);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "unload should succeed");

  status = spam_engine_load(handle, temp_model_path.c_str(), 0.001f, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "second load should succeed");

  avg_loss = -1.0f;
  trained_count = 999;
  status = spam_engine_train_incremental(handle, &avg_loss, &trained_count);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "train_incremental should succeed after reload");
  test_support::check(
      trained_count == 0,
      "unload should clear queued training samples from previous loaded session");
  test_support::check(avg_loss == 0.0f, "empty queue after reload should report avg_loss=0");

  spam_engine_destroy(handle);
}
#endif  // KLAR_HAVE_TRAINING

void test_extract_body_text_preview_prefers_plain_text() {
  // Multipart email with both text/plain and text/html
  // text_preview should contain the plain text content, not CSS
  const auto email = test_support::fixture_google_security_alert_rfc822();

  spam_engine_email_body_t body{};
  int result = spam_engine_extract_body(email.data(), email.size(), &body);
  test_support::check(result == 0, "extract_body should succeed");

  test_support::check(body.plain_body != nullptr, "plain_body should be extracted");
  test_support::check(body.text_preview != nullptr, "text_preview should be set");

  std::string preview(body.text_preview);
  std::string plain(body.plain_body);

  // Debug output
  std::cerr << "  plain_body: " << plain.substr(0, 100) << "..." << std::endl;
  std::cerr << "  text_preview: " << preview.substr(0, 100) << "..." << std::endl;

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

void test_extract_body_html_to_text_strips_css() {
  // HTML-only email with CSS in <style> tags
  // text_preview should strip the CSS and return only body content
  const auto email = test_support::fixture_html_only_with_css_rfc822();

  spam_engine_email_body_t body{};
  int result = spam_engine_extract_body(email.data(), email.size(), &body);
  test_support::check(result == 0, "extract_body should succeed for HTML-only");

  test_support::check(body.text_preview != nullptr, "text_preview should be set");

  std::string preview(body.text_preview);

  // Debug output
  std::cerr << "  text_preview: " << preview << std::endl;

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

  // FN2 gate: the AGGRESSIVE digit fold is Tier-1 only, so a digit homoglyph of a
  // Tier-2 brand must NOT fire ('Decath1on' -> decathlon is gated out), nor a
  // digit token that folds to a non-brand word ('passw0rd' -> 'password').
  const auto digit2 = display_impersonates_brand("Decath1on Support", "notify.example");
  test_support::check(!digit2.tier1 && !digit2.tier2,
      "'Decath1on' (digit fold of a Tier-2 brand) is gated out (FN2 Tier-1 gate)");
  const auto fp = display_impersonates_brand("Passw0rd Reset", "notify.example");
  test_support::check(!fp.tier1 && !fp.tier2,
      "'Passw0rd' folds to 'password' (not a brand) so it must not fire (FN2 gate)");

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
  in.scores = {0.0f, 0.0f, 0.94f, 0.06f};
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
  };
  for (const Case& c : cases) {
    std::string eml = std::string("From: ") + c.display + " <" + c.from + ">\r\n";
    if (c.ar != nullptr) eml += std::string("Authentication-Results: ") + c.ar + "\r\n";
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
      handle, paths.model_path.string().c_str(), 0.001f, nullptr);
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

// Reproduces the crash from CRASH.txt (2026-03-18):
//   Thread 5 Crashed: spam.engine.trainer
//   mutex::lock() threw std::system_error (EINVAL) because handle was
//   use-after-free'd.  The lock_guard is outside the try-catch block,
//   so the exception crosses extern "C" → std::terminate → SIGABRT.
//
// This test destroys the mutex inside a live handle (simulating the
// invalid-memory state seen in the crash), then calls classify_rfc822
// in a forked child.  Before the fix: child SIGABRTs.
// After the fix: child exits 0 (function returns an error status).
void test_classify_rfc822_mutex_throw_crashes() {
  pid_t pid = fork();
  if (pid == 0) {
    // Child: reproduce the crash.
    auto* handle = new spam_engine_handle_t();

    // Destroy the mutex, then scribble over it to guarantee
    // pthread_mutex_lock returns EINVAL (same as use-after-free).
    handle->mutex.~mutex();
    std::memset(&handle->mutex, 0xFF, sizeof(handle->mutex));

    spam_engine_result_t result{};
    auto status = spam_engine_classify_rfc822(
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
        "(matches CRASH.txt).  Fix: move lock_guard inside try-catch.");
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
      handle, paths.model_path.string().c_str(), 0.001f, nullptr);
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
  for (size_t i = 0; i < count; ++i)
    same = same && buckets[i] == buckets2[i] && weights[i] == weights2[i];
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
  for (size_t i = 0; i < count; ++i) remapped = remapped || kbuckets[i] != buckets[i];
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
  int status = spam_engine_load(handle, paths.model_path.string().c_str(), 0.001f, nullptr);
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
  int status = spam_engine_load(handle, paths.model_path.string().c_str(), 0.001f, nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "load should succeed");
  const int n_embd = spam_engine_n_embd(handle);
  test_support::check(n_embd > 0, "n_embd is the model dimension after load");

  const std::string msg =
      "From: a@b.example\r\nTo: c@d.example\r\nSubject: hi\r\n\r\nhello world\r\n";

  // Exact-size buffers succeed and report the dimension.
  {
    std::vector<float> plain(n_embd), html(n_embd);
    int pf = 0, hf = 0, got = 0;
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
  constexpr float kCanary = -424242.0f;
  {
    std::vector<float> plain(n_embd, kCanary);
    int pf = 1, hf = 1, got = 0;
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
  std::string joined(out);
  spam_engine_free_string(out);

  std::set<std::string> got;
  std::stringstream ss(joined);
  std::string line;
  while (std::getline(ss, line, '\n')) if (!line.empty()) got.insert(line);
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
  in.scores = {0.04f, 0.91f, 0.0f, 0.05f};
  in.ml_label = "marketing";
  in.ml_confidence = 0.91;
  in.dkim_signing_org_domain = "web.app";
  in.profile = SPAM_ENGINE_PROFILE_STANDARD;
  spam_engine_decision_result_t out{};
  int rc = spam_engine_decide(&in, &out);
  test_support::check(rc == SPAM_ENGINE_STATUS_OK, "decide returns OK");
  test_support::check(std::string(out.label) == "spam", "free-host leak condemned to spam");
  test_support::check(out.train_ml == 0, "header-only condemn does not train ML");
  test_support::check(out.adjusted_spam_side > 0.90, "adjusted spam side cleared the threshold");
  test_support::check(out.condemn_offset_fired == 1, "spam-ward offset fired flag set on a free-host condemn");

  // Ham rescue: model says spam, but the user has emailed this sender >= 2x.
  spam_engine_decision_input_t r{};
  r.scores = {0.0f, 0.0f, 0.05f, 0.95f};
  r.ml_label = "spam";
  r.ml_confidence = 0.95;
  r.exact_send_count = 2;
  r.profile = SPAM_ENGINE_PROFILE_STANDARD;
  spam_engine_decision_result_t rout{};
  spam_engine_decide(&r, &rout);
  test_support::check(std::string(rout.label) == "ham", "sender-history rescues to ham");
  test_support::check(rout.train_ml == 1, "user-side rescue still trains ML");
  test_support::check(rout.condemn_offset_fired == 0, "ham-only rescue sets no spam-ward fired flag");

  // Cautious profile raises the bar: spam-side 0.04 + 0.90 = 0.94 < 0.95 keeps.
  spam_engine_decision_input_t c{};
  c.scores = {0.0f, 0.96f, 0.0f, 0.04f};
  c.ml_label = "marketing";
  c.ml_confidence = 0.96;
  c.dkim_signing_org_domain = "web.app";
  c.profile = SPAM_ENGINE_PROFILE_CAUTIOUS;
  spam_engine_decision_result_t cout{};
  spam_engine_decide(&c, &cout);
  test_support::check(std::string(cout.label) == "marketing",
        "0.94 < 0.95 cautious threshold keeps the marketing leak");

  // Brand-reputation ham rescue (TASK-170): model says spam (0.92) on mail signed
  // by a Tranco established brand → the -0.15 ham offset pulls it under 0.90.
  spam_engine_decision_input_t b{};
  b.scores = {0.0f, 0.0f, 0.08f, 0.92f};
  b.ml_label = "spam";
  b.ml_confidence = 0.92;
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

  // Ceiling: a near-certain spam (spam-side 0.98 >= 0.97) signed by a brand is
  // NOT exonerated — guards against a popular-but-abused domain.
  spam_engine_decision_input_t bc{};
  bc.scores = {0.0f, 0.0f, 0.02f, 0.98f};
  bc.ml_label = "spam";
  bc.ml_confidence = 0.98;
  bc.dkim_signing_org_domain = "github.com";
  bc.profile = SPAM_ENGINE_PROFILE_STANDARD;
  spam_engine_decision_result_t bcout{};
  spam_engine_decide(&bc, &bcout);
  test_support::check(std::string(bcout.label) == "spam",
        "brand offset does not exonerate a >=0.97 spam-side (ceiling)");

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
void test_decision_input_from_signals() {
  spam_engine_scores_t scores = {0.01f, 0.04f, 0.10f, 0.85f};  // spam-dominant
  spam_engine_parsed_signals_t signals{};
  signals.thread.has_in_reply_to = 1;
  signals.thread.references_count = 3;
  std::strncpy(signals.auth.dkim_signing_domain, "evil.example",
               sizeof(signals.auth.dkim_signing_domain) - 1);
  signals.auth.signer_throwaway = 1;
  signals.auth.display_impersonation = 1;  // the field two surfaces dropped

  // Pre-set every caller-state field to a non-default: the builder must NOT touch any.
  spam_engine_decision_input_t din{};
  din.profile = SPAM_ENGINE_PROFILE_CAUTIOUS;
  din.exact_send_count = 2;
  din.domain_send_count = 5;
  din.phase2_match = 1;
  spam_engine_decision_input_from_signals(&din, &scores, &signals);

  // Every engine-derived field mapped (all 4 scores, not just the argmax winner).
  test_support::check(din.scores.gibberish == 0.01f && din.scores.marketing == 0.04f &&
        din.scores.regular == 0.10f && din.scores.spam == 0.85f, "all 4 scores copied");
  test_support::check(std::string(din.ml_label) == "spam", "neural-decision label is spam");
  test_support::check(din.ml_confidence == static_cast<double>(scores.spam),
        "spam-side decision confidence is the spam score");
  test_support::check(din.has_in_reply_to == 1 && din.references_count == 3,
        "thread signals mapped");
  test_support::check(std::string(din.dkim_signing_org_domain) == "evil.example",
        "dkim signing domain mapped");
  test_support::check(din.signer_throwaway == 1, "signer_throwaway mapped");
  test_support::check(din.display_impersonation == 1, "display_impersonation mapped");

  // Caller-state survived untouched.
  test_support::check(din.profile == SPAM_ENGINE_PROFILE_CAUTIOUS, "profile not clobbered");
  test_support::check(din.exact_send_count == 2, "exact_send_count not clobbered");
  test_support::check(din.domain_send_count == 5, "domain_send_count not clobbered");
  test_support::check(din.phase2_match == 1, "phase2_match not clobbered");

  // The builder feeds spam_engine_decide identically to a hand-rolled din.
  spam_engine_decision_result_t dout{};
  test_support::check(spam_engine_decide(&din, &dout) == SPAM_ENGINE_STATUS_OK,
        "builder output decides OK");

  // NULL args are no-ops (no crash, no write).
  spam_engine_decision_input_t untouched{};
  spam_engine_decision_input_from_signals(nullptr, &scores, &signals);
  spam_engine_decision_input_from_signals(&untouched, nullptr, &signals);
  spam_engine_decision_input_from_signals(&untouched, &scores, nullptr);
  test_support::check(untouched.ml_label == nullptr && untouched.scores.spam == 0.0f,
        "null args leave the struct untouched");
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
  spam_engine_scores_t gib = {0.55f, 0.05f, 0.50f, 0.25f};
  spam_engine_decision_input_t din{};
  spam_engine_decision_input_from_signals(&din, &gib, &signals);
  test_support::check(std::string(din.ml_label) == "regular",
        "gibberish-argmax below the spam-side gate is a deliver, not gibberish (C5)");
  test_support::check(din.ml_confidence == static_cast<float>(1.0f - gib.spam),
        "deliver confidence is 1 - spam (matches decision_from_scores)");

  // High gibberish (> 0.7) IS a spam-side decision even though spam is not the argmax.
  spam_engine_scores_t hg = {0.80f, 0.05f, 0.10f, 0.40f};
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
      "RFC822 preprocessing fixes false-positive via C API",
      test_rfc822_preprocessing_fixes_false_positive_via_c_api);
  failures += test_support::run_test(
      "RFC822 picks spammy html when plain/html drift via C API",
      test_rfc822_picks_spammy_html_when_plain_and_html_drift_via_c_api);
  failures += test_support::run_test(
      "last_error snapshot survives subsequent calls",
      test_last_error_snapshot_survives_subsequent_calls);
#ifdef KLAR_HAVE_TRAINING
  failures += test_support::run_test(
      "train_rfc822 and incremental flow",
      test_train_rfc822_and_incremental_flow);
  failures += test_support::run_test(
      "training C API input validation",
      test_training_c_api_input_validation);
  failures += test_support::run_test(
      "training incremental requires loaded engine",
      test_training_incremental_requires_loaded_engine);
#endif  // KLAR_HAVE_TRAINING
  failures += test_support::run_test(
      "extract_body text_preview prefers plain text",
      test_extract_body_text_preview_prefers_plain_text);
  failures += test_support::run_test(
      "extract_body html_to_text strips CSS",
      test_extract_body_html_to_text_strips_css);
  failures += test_support::run_test(
      "extract_url_domains C ABI (TASK-201)",
      test_extract_url_domains_c_api);
  failures += test_support::run_test("structural decision fold via C API", test_decide_c_api);
  failures += test_support::run_test("decision-input builder maps signals (TASK-231)",
                                     test_decision_input_from_signals);
  failures += test_support::run_test(
      "decide ml_label is the engine decision, not argmax (TASK-251 C5)",
      test_decision_ml_label_matches_engine_decision);
#ifdef KLAR_HAVE_TRAINING
  failures += test_support::run_test(
      "pending training queue cleared on load/unload",
      test_pending_training_queue_cleared_on_load_and_unload);
#endif  // KLAR_HAVE_TRAINING
  failures += test_support::run_test(
      "classify_rfc822 mutex throw crashes (CRASH.txt repro)",
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

  // Each test above creates AND destroys its own engine handle, so by the
  // time we get here every Metal buffer should already be unregistered from
  // the device's residency set. If a future test forgets to destroy its
  // handle, libggml-metal will catch it: GGML_ASSERT([rsets->data count] == 0)
  // fires from the static destructor of libggml-metal's global device vector
  // at __cxa_finalize_ranges, with a clear "you haven't deallocated all
  // Metal resources before exiting" message in the log. Treat that as the
  // canonical signal that the new test leaks an engine.
  if (failures == 0) {
    std::cout << "All tests passed.\n";
    return 0;
  }

  std::cerr << failures << " test(s) failed.\n";
  return 1;
}
