#pragma once

#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <atomic>
#include <chrono>

namespace test_support {

inline void check(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

struct ModelPaths {
  std::filesystem::path source_dir;
  std::filesystem::path model_path;
};

inline ModelPaths model_paths() {
  const std::filesystem::path source_dir(SPAM_ENGINE_SOURCE_DIR);
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

  ~ScopedTempModelDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }

  const std::filesystem::path& path() const { return path_; }

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

  return ScopedTempModelDir(temp_path);
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
  std::cerr << "[RUN] " << name << std::endl;
  try {
    fn();
    std::cerr << "[PASS] " << name << std::endl;
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "[FAIL] " << name << ": " << e.what() << std::endl;
    return 1;
  } catch (...) {
    std::cerr << "[FAIL] " << name << ": unknown exception" << std::endl;
    return 1;
  }
}

}  // namespace test_support
