#include "spam_engine_c_api.h"
#include "spam_engine_handle_internal.h"
#ifdef KLAR_HAVE_TRAINING
#include "spam_engine_training_c_api.h"  // premium; absent in the open-core build
#endif
#include "test_support.h"

#include <cmath>
#include <cstring>
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
      &result,
      nullptr);
  test_support::check(status == SPAM_ENGINE_STATUS_OK, "classify_rfc822 should succeed for drift case");
  test_support::check(result.scores.spam > 0.90f,
        "classify_rfc822 should treat spammy html alternative as high-spam");
  test_support::check(result.label == 3,
        "classify_rfc822 should label plain/html drift case as spam");

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
                                  &result, &folded)
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
                                  &result2, nullptr)
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
        handle, "test", 4, nullptr, nullptr, &result, nullptr);

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

  // NULL args are rejected.
  test_support::check(spam_engine_decide(nullptr, &out) == SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
        "null input rejected");
  test_support::check(spam_engine_decide(&in, nullptr) == SPAM_ENGINE_STATUS_INVALID_ARGUMENT,
        "null output rejected");
}

}  // namespace

int main() {
  int failures = 0;
  failures += test_support::run_test("create and destroy", test_create_and_destroy);
  failures += test_support::run_test("load/classify/unload flow", test_load_classify_unload_flow);
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
