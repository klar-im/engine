#pragma once

#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <atomic>
#include <chrono>
#include <utility>

namespace test_support {

inline void check(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

// The embedding width the loaded artifact DECLARES, in classifier_config.json.
//
// Model-independent invariants assert against this and never against a literal.
// The suite hardcoded 768 from 2026-07-27 to 2026-08-10 under a comment reading
// "should match the shipped encoder", while the encoder actually shipped to App
// Store users was public-v0 at 1024 — so installing the released model turned a
// green suite red, and the failure read as an engine bug (TASK-428 AC#1, AC#8).
//
// Templated so this header stays free of spam_engine.h: spam_engine_c_api_tests
// includes it and links only the C ABI.
template <typename Engine>
inline std::size_t declared_hidden_size(const Engine& engine) {
  const int declared = engine.model_info().hidden_size;
  check(declared > 0,
      "classifier_config.json declares no hidden_size, so there is no width to "
      "check against; a model package without one is not testable");
  // load() already refuses a package whose encoder and head disagree. Restating
  // it here is what makes `declared` usable as the encoder's width too, which is
  // the claim every caller below actually relies on.
  check(engine.n_embd() == declared,
      "encoder n_embd (" + std::to_string(engine.n_embd()) +
      ") != declared hidden_size (" + std::to_string(declared) + ")");
  return static_cast<std::size_t>(declared);
}

struct ModelPaths {
  std::filesystem::path source_dir;
  std::filesystem::path model_path;
};

// SPAM_ENGINE_TEST_MODEL_DIR points the suite at a model set other than the
// working engine/model. It exists so the demo-fixture contract can be checked
// against the model klar.im actually serves: engine/model holds whatever a
// developer is working on, which for anyone doing model work is a private
// candidate, and asserting the public demo's verdicts against a candidate is how
// klar.im served five wrong verdicts for a month while the test stayed green.
inline ModelPaths model_paths() {
  const std::filesystem::path source_dir(SPAM_ENGINE_SOURCE_DIR);
  // getenv() isn't thread-safe against a concurrent setenv(), but this reads
  // a fixed test-setup env var once per process, never concurrently.
  // NOLINTNEXTLINE(concurrency-mt-unsafe)
  if (const char* dir = std::getenv("SPAM_ENGINE_TEST_MODEL_DIR"); dir && (*dir != '\0')) {
    return ModelPaths{source_dir, std::filesystem::path(dir)};
}

  return ModelPaths{source_dir, source_dir / "model"};
}

inline std::filesystem::path gguf_model_path(const ModelPaths& paths,
                                              const std::string& variant = "encoder-q4_k_m.gguf") {
  return paths.model_path / "gguf" / variant;
}

inline bool has_gguf_model(const ModelPaths& paths,
                            const std::string& variant = "encoder-q4_k_m.gguf") {
  return std::filesystem::exists(gguf_model_path(paths, variant));
}

inline bool has_model_assets(const ModelPaths& paths) {
  return has_gguf_model(paths);
}

inline void ensure_model_assets(const ModelPaths& paths, const std::string& test_label) {
  if (has_model_assets(paths)) {
    return;
  }

  throw std::runtime_error(
      "Missing model assets for test '" + test_label
      + "'. Ensure GGUF model is present under engine/model/gguf/.");
}

inline std::string fixture_noisy_html_ham_rfc822() {
  return
      "X-Ms-Exchange-Transport-Endtoendlatency: 00:00:00.9268549\r\n"
      "X-Microsoft-Antispam-Mailbox-Delivery: ucf:0;jmr:0;ex:0;auth:1;dest:I;ENG:(5062000311)(920221119095)(90000117)(920221120095)\r\n"
      "From: Alice Example <alice@example.com>\r\n"
      "To: team@example.com\r\n"
      "Subject: Meeting agenda for tomorrow and action items\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: text/html; charset=UTF-8\r\n"
      "\r\n"
      "<html><body><p>Hi team,</p><p>Just sharing the meeting agenda for tomorrow and action items.</p>"
      "<p>Please add blockers before 5pm.</p></body></html>\r\n";
}

// Google Security Alert email - multipart/alternative with text/plain and text/html
// The text/plain part should be preferred. If HTML is used, CSS must be stripped.
inline std::string fixture_google_security_alert_rfc822() {
  return R"(Content-Type: multipart/alternative; boundary="000000000000de6d2505fff9ad64"
Subject: Security alert for test@gmail.com
From: Google <no-reply@accounts.google.com>
MIME-Version: 1.0

--000000000000de6d2505fff9ad64
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

VGhpcyBpcyBhIGNvcHkgb2YgYSBzZWN1cml0eSBhbGVydC4gQ29udGFjdCBlbWFpbCB3YXMgY2hh
bmdlZCBmb3IgeW91ciBsaW5rZWQgR29vZ2xlIEFjY291bnQu
--000000000000de6d2505fff9ad64
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html><html><head><style>.awl a {color: #FFFFFF;} .abml a {color: #000000; font-family: Roboto;}</style></head><body><p>This is a copy of a security alert. Contact email was changed for your linked Google Account.</p></body></html>
--000000000000de6d2505fff9ad64--
)";
}

// A single-part `text/plain` email whose "plain text" is actually the raw
// HTML template, tags and all — a real ESP bug (myphotobook.de's newsletter,
// 2026-09-04) confirmed live, not a hypothetical: no genuine `text/html`
// alternative exists, so there is no correct part to fall back to, and the
// only fix is recognising the "plain" part is markup and cleaning it.
inline std::string fixture_html_dumped_as_plain_rfc822() {
  return R"(Content-Type: text/plain; charset="UTF-8"
Subject: Produkt-Highlights September
From: myphotobook <info@email.myphotobook.de>
MIME-Version: 1.0

<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<div>Hallo Fotofan, es ist wieder Zeit fuer unsere Highlights.</div>
)";
}

// A genuine plain-text email that quotes a single attribute-bearing tag —
// the false-positive shape `looks_like_html_markup` must NOT treat as a
// raw-HTML-dump ESP bug (found by /codex:review): unlike
// `fixture_html_dumped_as_plain_rfc822` above, this is real correspondence
// with exactly one HTML-looking fragment early in the body, not a whole
// document.
inline std::string fixture_plain_text_quoting_a_div_snippet_rfc822() {
  return R"(Content-Type: text/plain; charset="UTF-8"
Subject: Re: button styling
From: dev@example.com
MIME-Version: 1.0

Hi, thanks for the report. The button renders as <div class="btn">Submit</div>
in our markup, so the click handler needs to bind to that element instead.
)";
}

// HTML-only email with CSS that must be stripped
inline std::string fixture_html_only_with_css_rfc822() {
  return R"(Content-Type: text/html; charset="UTF-8"
Subject: HTML with CSS
From: test@example.com
MIME-Version: 1.0

<!DOCTYPE html><html><head><style>.awl a {color: #FFFFFF; text-decoration: none;} .abml a {color: #000000; font-family: Roboto-Medium,Helvetica,Arial,sans-serif; font-weight: bold;}</style></head><body><p>Hello world, this is the actual content.</p></body></html>
)";
}

inline std::string make_unique_suffix() {
  static std::atomic<unsigned long long> counter{0};
  const auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  const auto n = counter.fetch_add(1);
  return std::to_string(now) + "-" + std::to_string(n);
}

inline void copy_required_file(
    const std::filesystem::path& src,
    const std::filesystem::path& dst) {
  check(std::filesystem::exists(src), "Missing source model file: " + src.string());
  std::filesystem::copy_file(
      src,
      dst,
      std::filesystem::copy_options::overwrite_existing);
}

inline void hard_link_or_copy_file(
    const std::filesystem::path& src,
    const std::filesystem::path& dst) {
  check(std::filesystem::exists(src), "Missing source model file: " + src.string());

  std::error_code ec;
  std::filesystem::create_hard_link(src, dst, ec);
  if (!ec) {
    return;
  }

  std::filesystem::copy_file(
      src,
      dst,
      std::filesystem::copy_options::overwrite_existing);
}

class ScopedTempModelDir {
 public:
  explicit ScopedTempModelDir(std::filesystem::path path)
      : path_(std::move(path)) {}

  // Never actually moved (every caller binds the by-value return through
  // guaranteed copy elision, `const auto x = create_temp_model_fixture(...)`),
  // so delete move too rather than default speculative surface nothing uses.
  ScopedTempModelDir(const ScopedTempModelDir&) = delete;
  ScopedTempModelDir& operator=(const ScopedTempModelDir&) = delete;
  ScopedTempModelDir(ScopedTempModelDir&&) = delete;
  ScopedTempModelDir& operator=(ScopedTempModelDir&&) = delete;

  ~ScopedTempModelDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }

  [[nodiscard]] const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
};

inline ScopedTempModelDir create_temp_model_fixture(const std::filesystem::path& source_model_path) {
  namespace fs = std::filesystem;

  const fs::path temp_path =
      fs::temp_directory_path() / ("spam-engine-model-fixture-" + make_unique_suffix());
  fs::create_directories(temp_path);

  // GGUF encoder: hard-link to avoid duplicating the 150 MB model file.
  const fs::path gguf_src = source_model_path / "gguf";
  if (fs::exists(gguf_src)) {
    const fs::path gguf_dst = temp_path / "gguf";
    fs::create_directories(gguf_dst);
    for (const auto& entry : fs::directory_iterator(gguf_src)) {
      hard_link_or_copy_file(entry.path(), gguf_dst / entry.path().filename());
    }
  }

  // Mutable classifier assets: real copies to avoid touching source model files.
  copy_required_file(
      source_model_path / "classifier_config.json",
      temp_path / "classifier_config.json");
  copy_required_file(
      source_model_path / "classifier_dense_weight.bin",
      temp_path / "classifier_dense_weight.bin");
  copy_required_file(
      source_model_path / "classifier_dense_bias.bin",
      temp_path / "classifier_dense_bias.bin");
  copy_required_file(
      source_model_path / "classifier_out_proj_weight.bin",
      temp_path / "classifier_out_proj_weight.bin");
  copy_required_file(
      source_model_path / "classifier_out_proj_bias.bin",
      temp_path / "classifier_out_proj_bias.bin");

  // Personalized snapshots carry an immutable trust-region anchor. Base models
  // legitimately omit it, so copy the complete optional set when present.
  for (const char* name : {
           "classifier_anchor_dense_weight.bin",
           "classifier_anchor_dense_bias.bin",
           "classifier_anchor_out_proj_weight.bin",
           "classifier_anchor_out_proj_bias.bin"}) {
    if (fs::exists(source_model_path / name)) {
      copy_required_file(source_model_path / name, temp_path / name);
    }
  }

  return ScopedTempModelDir(temp_path);
}

// Which half of the suite this process is running. The two ctest entries
// partition the binary rather than nesting: `spam_engine_tests` runs engine
// correctness, `spam_engine_tests --qualification-only` runs the corpus panels.
// See the qualification section below for why they are separate questions.
enum class RunMode : std::uint8_t { kCorrectnessOnly, kQualificationOnly };

inline RunMode& run_mode() {
  static RunMode mode = RunMode::kCorrectnessOnly;
  return mode;
}
inline bool qualification_enabled() {
  return run_mode() == RunMode::kQualificationOnly;
}

inline std::string& test_filter() {
  static std::string filter;
  return filter;
}
inline void set_test_filter(const std::string& f) { test_filter() = f; }

template <typename Func>
int run_test(const std::string& name, Func&& fn) {
  if (!test_filter().empty() && name.find(test_filter()) == std::string::npos) {
    return 0;  // filtered out
  }
  // --qualification-only partitions the two ctest entries instead of nesting
  // them. Without this, `make engine/qualify` re-ran all ~47 correctness tests,
  // 30 of which load the 406 MB encoder, to reach three panels.
  if (run_mode() == RunMode::kQualificationOnly) {
    return 0;
  }
  std::cerr << "[RUN] " << name << '\n';
  try {
    std::forward<Func>(fn)();
    std::cerr << "[PASS] " << name << '\n';
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "[FAIL] " << name << ": " << e.what() << '\n';
    return 1;
  } catch (...) {
    std::cerr << "[FAIL] " << name << ": unknown exception" << '\n';
    return 1;
  }
}

// === Engine correctness vs checkpoint qualification =========================
//
// Two different questions, and this binary used to return one exit code for
// both:
//
//   ENGINE CORRECTNESS — does the code do what it claims, for whatever model it
//   is handed? The embedding is the width the config declares, the envelope is
//   the one the config declares, the trust region admits a correction and bounds
//   the hundredth. True of any checkpoint. This is what gates the merge.
//
//   CHECKPOINT QUALIFICATION — is THIS checkpoint good enough to ship? Spam
//   recall under a one-sided ham stream, and the doc-23 matrix. public-v0's
//   honest answer today is FAIL, and doc-23 already records it as FAIL (0
//   measured / 2 directional / 111 missing). It ships because Gen 3 was
//   disqualified for leaking held-out messages into its evaluation (TASK-421),
//   which is a recorded trade, not a passing grade.
//
// Conflating them is what made "the shipped checkpoint scores badly"
// indistinguishable from "main is broken", and it left one cheap way out: write
// the failure up somewhere and call it expected. Splitting them removes that
// move. The threshold does not change, the assertion still runs, its result is
// still red, and it is attributed to a model UUID instead of to the engine
// (TASK-428 AC#3, AC#13).
//
// What is deliberately NOT here yet is the expected qualification outcome per
// checkpoint. Until AC#9/#10 land there is nothing to compare a number against,
// so this REPORTS rather than asserts — and report_qualification says so in the
// output, so nobody reads a printed FAIL as a tolerated one.
// Three states, not two. "not measured" is what a missing corpus produces, and
// it must never be readable as a pass.
enum class Qualification : std::uint8_t { kPass, kFail, kNotMeasured };

struct QualificationResult {
  std::string name;
  Qualification verdict = Qualification::kNotMeasured;
  std::string detail;
};

inline std::vector<QualificationResult>& qualification_results() {
  static std::vector<QualificationResult> results;
  return results;
}

// Qualification panels embed the SpamAssassin corpus, which is what actually
// blew the merge gate's 900 s budget: ~880 encoder forward passes on a two-core
// ubuntu runner with a 406 MB, 1024-dim encoder.
//
// The 88.73 s July baseline everyone reached for is not a counter-example, it is
// the same fact seen from the other side: run #30206418743 printed "[SKIP] Clean
// dataset not found" for every one of these. be4d0a81 (#475) then added `make
// model-lab/fetch-spam-assassin` to the workflow, so they began running for the
// first time — against Gen 3, at 332 s — and e293501a (#494) swapped in an
// encoder 2.5x the size of the one that was measured against.
//
// So they run when asked for, not on every pull request:
//
//     make engine/qualify        (or spam_engine_tests --qualification-only)
//
// This is the same correctness/qualification line as below, drawn at the CI
// level: whether the code is right is every PR's business, whether THIS
// checkpoint is good enough is not.
// A criterion that could not be measured. NOT a pass: `[SKIP] Clean dataset not
// found` used to return normally out of the panel body, land in the success
// branch, and print `PASS` for a measurement that never ran — which is the
// tolerated-failure state this whole split exists to prevent, one layer down.
struct QualificationSkipped : std::runtime_error {
  using std::runtime_error::runtime_error;
};
inline void skip_qualification(const std::string& why) {
  throw QualificationSkipped(why);
}

// Deliberately returns void where run_test returns an int: qualification is not
// summed into the correctness count. main() consults report_qualification()
// separately, so the two verdicts never merge into one number.
template <typename Func>
void run_qualification_test(const std::string& name, Func&& fn) {
  if (!test_filter().empty() && name.find(test_filter()) == std::string::npos) {
    return;
  }
  if (!qualification_enabled()) {
    std::cerr << "[SKIP] " << name
              << " (checkpoint qualification; run `make engine/qualify`)"
              << '\n';
    return;
  }
  std::cerr << "[RUN] " << name << " (checkpoint qualification)" << '\n';
  try {
    std::forward<Func>(fn)();
    std::cerr << "[QUALIFY-PASS] " << name << '\n';
    qualification_results().push_back({name, Qualification::kPass, ""});
  } catch (const QualificationSkipped& e) {
    std::cerr << "[QUALIFY-SKIP] " << name << ": " << e.what() << '\n';
    qualification_results().push_back(
        {name, Qualification::kNotMeasured, e.what()});
  } catch (const std::exception& e) {
    std::cerr << "[QUALIFY-FAIL] " << name << ": " << e.what() << '\n';
    qualification_results().push_back({name, Qualification::kFail, e.what()});
  } catch (...) {
    std::cerr << "[QUALIFY-FAIL] " << name << ": unknown exception" << '\n';
    qualification_results().push_back(
        {name, Qualification::kFail, "unknown exception"});
  }
}

// Returns the number of failed criteria, so a caller that DOES want to gate on
// qualification (a release gate, not the merge gate) can.
inline std::size_t report_qualification(const std::string& checkpoint_uuid) {
  if (!qualification_enabled()) { return 0;
}
  const auto& results = qualification_results();
  if (results.empty()) { return 0;
}

  std::size_t unqualified = 0;
  for (const auto& r : results) {
    if (r.verdict != Qualification::kPass) { ++unqualified;
}
  }

  std::cout << "\n=== checkpoint qualification: "
            << (checkpoint_uuid.empty()
                    ? "UNKNOWN (no model_uuid in MANIFEST.json)"
                    : checkpoint_uuid)
            << " ===\n";
  for (const auto& r : results) {
    const char* label = r.verdict == Qualification::kPass    ? "  PASS         "
                        : r.verdict == Qualification::kFail  ? "  FAIL         "
                                                             : "  NOT MEASURED ";
    std::cout << label << r.name << "\n";
    if (r.verdict != Qualification::kPass) {
      std::cout << "                 " << r.detail << "\n";
    }
  }
  std::cout << "  " << unqualified << " of " << results.size()
            << " criteria did not pass for this checkpoint.\n";
  if (unqualified > 0) {
    std::cout <<
        "  This does not gate the merge, because it is a property of the\n"
        "  checkpoint rather than of the engine. It is NOT an accepted failure:\n"
        "  nothing yet records what this checkpoint is supposed to score, so the\n"
        "  suite cannot tell a known-bad number from a fresh regression. That is\n"
        "  TASK-428 AC#9/#10, and until it lands this number needs a human.\n";
  }
  return unqualified;
}

}  // namespace test_support
