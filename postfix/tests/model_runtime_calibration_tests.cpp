// Regression for the milter's classify path. ModelRuntime reaches its verdict
// through spam_engine_classify_full (TASK-540), which applies the artifact's
// calibration knot itself; before that the milter folded by hand and once
// compared model_info's boolean return with STATUS_OK, which left every
// calibrated artifact on its raw scale. What remains the milter's job, and what
// this pins with a stubbed C API (no 400 MiB model): the per-call profile and
// the two transport facts reach caller_state, and the engine's staged result
// lands in ClassifyResult field for field.

#include "config.h"
#include "model_runtime.h"
#include "spam_engine_c_api.h"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>

struct spam_engine_handle {
  bool loaded = false;
};

namespace {
spam_engine_caller_state_t g_caller{};
bool g_caller_was_null = false;
}

extern "C" {

spam_engine_handle_t* spam_engine_create(void) {
  return new spam_engine_handle;
}

void spam_engine_destroy(spam_engine_handle_t* handle) {
  delete handle;
}

spam_engine_status_t spam_engine_load(spam_engine_handle_t* handle,
                                      const char*, float, const char*) {
  if (handle == nullptr) return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  handle->loaded = true;
  return SPAM_ENGINE_STATUS_OK;
}

spam_engine_status_t spam_engine_unload(spam_engine_handle_t* handle) {
  if (handle == nullptr) return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  handle->loaded = false;
  return SPAM_ENGINE_STATUS_OK;
}

spam_engine_status_t spam_engine_classify_full(
    spam_engine_handle_t* handle, const char*, size_t, const char*, const char*,
    const char* mode, const spam_engine_caller_state_t* caller_state,
    spam_engine_full_result_t* out) {
  if (handle == nullptr || !handle->loaded || out == nullptr || mode == nullptr ||
      std::strcmp(mode, "ensemble") != 0) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }
  g_caller_was_null = caller_state == nullptr;
  g_caller = caller_state != nullptr ? *caller_state : spam_engine_caller_state_t{};
  *out = {};
  out->neural_scores.spam = 0.70f;     // pre-blend: must NOT be what cr.spam reports
  out->neural_scores.regular = 0.20f;
  out->neural_scores.marketing = 0.10f;
  out->ensemble_spam = 0.80f;          // the spam side the fold started from
  out->decision.calibrated_spam_side = 0.99;
  out->decision.adjusted_spam_side = 0.995;
  out->decision.condemn_offset_fired = 1;
  std::strcpy(out->decision.label, "spam");
  std::strcpy(out->decision.fired_offsets, "connect_ip_drop!");
  return SPAM_ENGINE_STATUS_OK;
}

const char* spam_engine_get_last_error(const spam_engine_handle_t*) {
  return "stub error";
}

}  // extern "C"

// read_version_file() accepts the two shapes a model directory ships with: a
// plain VERSION line, and the engine's MANIFEST.json (whose first line is `{`).
static int check_version_file_shapes() {
  int failures = 0;
  auto write = [](const char* path, const char* body) {
    FILE* f = std::fopen(path, "w");
    std::fputs(body, f);
    std::fclose(f);
  };
  auto check = [&](bool condition, const char* message) {
    std::printf("[%s] %s\n", condition ? "PASS" : "FAIL", message);
    if (!condition) ++failures;
  };
  write("/tmp/klar-test-VERSION", "  dev-20260913 \n");
  check(klar::ModelRuntime::read_version_file("/tmp/klar-test-VERSION") == "dev-20260913",
        "a VERSION file yields its trimmed first line");
  write("/tmp/klar-test-MANIFEST.json",
        "{\n  \"files\": {\"a.bin\": {\"sha256\": \"00\"}},\n"
        "  \"model_uuid\": \"21bcd2ff-beaf-41d4-aa84-8083083d3554\",\n  \"source_model\": null\n}\n");
  check(klar::ModelRuntime::read_version_file("/tmp/klar-test-MANIFEST.json")
            == "21bcd2ff-beaf-41d4-aa84-8083083d3554",
        "a MANIFEST.json yields model_uuid, not '{'");
  write("/tmp/klar-test-MANIFEST.json", "{\"files\": {}}\n");
  check(klar::ModelRuntime::read_version_file("/tmp/klar-test-MANIFEST.json").empty(),
        "a MANIFEST.json without model_uuid yields nothing rather than '{'");
  check(klar::ModelRuntime::read_version_file("/tmp/klar-test-absent").empty(),
        "a missing file yields nothing");
  return failures;
}

int main() {
  int shape_failures = check_version_file_shapes();

  klar::Config cfg;
  cfg.model_dir = "stub-model";
  cfg.model_version_file.clear();

  klar::ModelRuntime runtime;
  if (!runtime.load(cfg)) {
    std::printf("[FAIL] stub model loads\n");
    return 1;
  }

  int failures = 0;
  auto check = [&](bool condition, const std::string& message) {
    std::printf("[%s] %s\n", condition ? "PASS" : "FAIL", message.c_str());
    if (!condition) ++failures;
  };

  const auto result = runtime.classify_rfc822(
      "Subject: calibration\r\n\r\nbody", "Sender", "sender@example.test",
      /*connect_ip_blocked=*/true, /*header_ip_blocked=*/false,
      SPAM_ENGINE_PROFILE_STANDARD);

  check(result.ok, "classification succeeds");
  check(!g_caller_was_null, "the milter hands classify_full its caller state");
  check(g_caller.connect_ip_blocked == 1 && g_caller.header_ip_blocked == 0,
        "the observed connecting-IP hit reaches the fold, and only that one");
  check(g_caller.phase2_match == 0 && g_caller.exact_send_count == 0 &&
            g_caller.domain_send_count == 0 && g_caller.replied_to_own_sent == 0 &&
            g_caller.attachment_risk_enabled == 0,
        "the milter claims no local history it does not have");
  check(std::abs(result.spam - 0.80f) < 1e-6f,
        "spam reports the ensemble spam side, not the pre-blend neural score");
  check(std::abs(result.regular - 0.20f) < 1e-6f &&
            std::abs(result.marketing - 0.10f) < 1e-6f,
        "the other classes come from the neural scores");
  check(std::abs(result.calibrated_spam - 0.99f) < 1e-6f &&
            std::abs(result.adjusted_spam - 0.995f) < 1e-6f,
        "calibrated and adjusted spam sides come from the engine's fold");
  check(result.structural_condemn && result.flipped_by_offset &&
            result.fired_offsets == "connect_ip_drop!",
        "the fold's own account of what fired is carried through");

  runtime.classify_rfc822("Subject: h\r\n\r\nbody", "S", "s@example.test",
                          /*connect_ip_blocked=*/false, /*header_ip_blocked=*/true,
                          SPAM_ENGINE_PROFILE_STANDARD);
  check(g_caller.connect_ip_blocked == 0 && g_caller.header_ip_blocked == 1,
        "a header-recovered origin stays header evidence (TASK-387)");

  // The profile is per call, not cached at load: a config reload or a
  // recipient-domain policy that names another profile has to reach the fold
  // (TASK-510). Each value handed in is the one the fold runs at.
  for (const int want : {SPAM_ENGINE_PROFILE_CAUTIOUS, SPAM_ENGINE_PROFILE_AGGRESSIVE, SPAM_ENGINE_PROFILE_STANDARD}) {
    runtime.classify_rfc822("Subject: p\r\n\r\nbody", "S", "s@example.test", false, false,
                            static_cast<spam_engine_profile_t>(want));
    check(g_caller.profile == want,
          "profile " + std::to_string(want) + " reaches the fold unchanged");
  }

  return (failures + shape_failures) == 0 ? 0 : 1;
}
