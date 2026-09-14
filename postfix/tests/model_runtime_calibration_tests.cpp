// Regression for the milter's standalone classify + decide path. ModelRuntime
// cannot use spam_engine_classify_full because the milter supplies transport
// facts after parsing, so it must copy the loaded artifact's calibration knot
// explicitly. The C API's model_info query returns boolean 1/0, unlike the
// status-returning operations where success is SPAM_ENGINE_STATUS_OK (0).

#include "config.h"
#include "model_runtime.h"
#include "spam_engine_c_api.h"

#include <cmath>
#include <cstdio>
#include <cstring>

struct spam_engine_handle {
  bool loaded = false;
};

namespace {
double g_decide_knot = -1.0;
int g_model_info_calls = 0;
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

spam_engine_status_t spam_engine_classify_rfc822(
    spam_engine_handle_t* handle, const char*, size_t, const char*, const char*,
    const char*, spam_engine_result_t* out_result,
    spam_engine_parsed_signals_t* out_signals) {
  if (handle == nullptr || !handle->loaded || out_result == nullptr ||
      out_signals == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }
  *out_result = {};
  *out_signals = {};
  out_result->scores.spam = 0.80f;
  out_result->scores.regular = 0.20f;
  out_result->ftrl_score = -1.0f;
  return SPAM_ENGINE_STATUS_OK;
}

const char* spam_engine_get_last_error(const spam_engine_handle_t*) {
  return "stub error";
}

int spam_engine_model_info(const spam_engine_handle_t* handle,
                           spam_engine_model_info_t* out) {
  ++g_model_info_calls;
  if (handle == nullptr || !handle->loaded || out == nullptr) return 0;
  *out = {};
  out->spam_side_calibration_knot = 0.80;
  return 1;
}

void spam_engine_decision_input_from_signals(
    spam_engine_decision_input_t* din, const spam_engine_scores_t* scores,
    const spam_engine_parsed_signals_t*) {
  if (din == nullptr || scores == nullptr) return;
  din->scores = *scores;
  din->ml_label = "regular";
  din->ml_confidence = 0.20;
}

int spam_engine_decide(const spam_engine_decision_input_t* din,
                       spam_engine_decision_result_t* out) {
  if (din == nullptr || out == nullptr) {
    return SPAM_ENGINE_STATUS_INVALID_ARGUMENT;
  }
  *out = {};
  g_decide_knot = din->spam_side_knot;
  const double raw = din->scores.spam + din->scores.gibberish;
  double adjusted = raw;
  if (din->spam_side_knot > 0.0 && din->spam_side_knot < 1.0) {
    if (raw <= din->spam_side_knot) {
      adjusted = raw * (0.99 / din->spam_side_knot);
    } else {
      adjusted = 0.99 + (raw - din->spam_side_knot) *
          (0.01 / (1.0 - din->spam_side_knot));
    }
  }
  out->adjusted_spam_side = adjusted;
  std::strcpy(out->label, adjusted >= 0.99 ? "spam" : "regular");
  return SPAM_ENGINE_STATUS_OK;
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

  const auto result = runtime.classify_rfc822(
      "Subject: calibration\r\n\r\nbody", "Sender", "sender@example.test",
      false, false);

  int failures = 0;
  auto check = [&](bool condition, const char* message) {
    std::printf("[%s] %s\n", condition ? "PASS" : "FAIL", message);
    if (!condition) ++failures;
  };

  check(result.ok, "classification succeeds");
  check(g_model_info_calls == 1, "loaded artifact metadata is queried once");
  check(std::abs(g_decide_knot - 0.80) < 1e-12,
        "non-zero artifact calibration reaches spam_engine_decide");
  check(std::abs(result.adjusted_spam - 0.99f) < 1e-6f,
        "raw score at the artifact knot maps onto the Standard gate");

  return (failures + shape_failures) == 0 ? 0 : 1;
}
