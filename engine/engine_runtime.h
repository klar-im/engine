#pragma once

// What the engine knows about its own runtime, and how it says it.
//
// Two things live here because both the encoder (ggml_encoder.h, which needs
// llama.h) and the public class (spam_engine.h, which must not) describe them,
// and #823 shipped a copy of the struct in each:
//
// - EncoderRuntimeInfo: the backend the encoder actually runs on, why it is
//   not Metal when it is not, the cap in force and what the cap did since
//   load. One struct, filled by GgmlEncoder, returned by SpamEngine, copied
//   field for field into spam_engine_runtime_info_t at the C ABI.
// - The log sink. The engine used to fprintf(stderr), which a MailKit appex
//   discards, so the one process where a silent CPU fallback matters most was
//   the one that could not read the line saying so. ggml and llama expose
//   *_log_set for exactly this; this is the engine's own. Not installed, it
//   prints to stderr as before, so the CLI, the milter and the tests read
//   what they always read.

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <type_traits>
#include <vector>

namespace spam_engine {

// Why the encoder is on CPU. kNone means it is on the GPU it asked for, so
// "on a GPU" is `fallback == kNone` and needs no second field. Crosses the
// ABI by name (encoder_fallback_name), like the backend: one spelling, chosen
// here, stored verbatim by every consumer.
enum class EncoderFallback : std::uint8_t {
  kNone = 0,
  kRequestedCpu = 1,       // SPAM_ENGINE_NO_GPU was set: CPU by request
  kNoGpuDevice = 2,        // no GPU-typed device registered (no Metal plugin staged, Linux CI)
  kContextInitFailed = 3,  // a GPU device exists and refused a context (sandbox, VM)
};

inline const char* encoder_fallback_name(EncoderFallback fallback) noexcept {
  switch (fallback) {
    case EncoderFallback::kNone: return "none";
    case EncoderFallback::kRequestedCpu: return "requested_cpu";
    case EncoderFallback::kNoGpuDevice: return "no_gpu_device";
    case EncoderFallback::kContextInitFailed: return "context_init_failed";
  }
  return "unknown";
}

struct EncoderRuntimeInfo {
  // ggml's registry name, lower-cased, "MTL" spelled out as "metal": the one
  // spelling, chosen in GgmlEncoder::load_with_gpu_layers and stored verbatim
  // by every consumer.
  std::string backend = "cpu";
  // ggml_backend_dev_description of the device in use ("Apple M1 Pro").
  std::string device;
  EncoderFallback fallback = EncoderFallback::kNone;
  // The tail of ggml's own log at the moment a GPU context init failed, so a
  // support mail says why, not only that. Empty for every other fallback.
  // At most kFallbackDetailBytes, which is what fits the C ABI's buffer with
  // its NUL (the C API static_asserts the two agree).
  static constexpr std::size_t kFallbackDetailBytes = 255;
  std::string fallback_detail;
  // The cap in force after any SPAM_ENGINE_MAX_TOKENS override.
  int max_tokens = 0;
  // Since load, every sequence that reached the encoder: classify (one or two
  // per message), embed_* and training alike. `truncated` lost tokens to the
  // cap; `failed` threw before an embedding existed and is in neither of the
  // other two. The per-message figure is
  // ClassificationResult::encoder_truncated_sequences.
  std::uint64_t sequences_embedded = 0;
  std::uint64_t sequences_truncated = 0;
  std::uint64_t sequences_failed = 0;
};

// One encoded sequence and whether the cap clipped it. The flag travels with
// the embedding so a classify entry point stamps its result from what it
// embedded, never from a process-wide counter read twice.
struct EncoderEmbedding {
  std::vector<float> values;
  bool truncated = false;
};

// The last `max_bytes` of a line-oriented log, cut on line boundaries: the
// fragment of the line the window opens inside is dropped. When the window
// holds nothing but that fragment (one line longer than the window), the
// HEAD of the line is returned instead: "ggml_metal_init: error: ..." is at
// its start, and a fragment that begins mid-path names nothing. Pure, so the
// C API test covers it without a ggml context.
inline std::string log_tail_lines(const std::string& buffer, std::size_t max_bytes) {
  if (buffer.size() <= max_bytes) { return buffer; }
  const auto start = buffer.size() - max_bytes;
  if (buffer[start - 1] == '\n') { return buffer.substr(start); }
  const auto first_newline = buffer.find('\n', start);
  const bool whole_lines_follow = first_newline != std::string::npos
      && first_newline + 1 < buffer.size();
  if (whole_lines_follow) { return buffer.substr(first_newline + 1); }
  const auto line_start = buffer.rfind('\n', start - 1);
  return buffer.substr(line_start == std::string::npos ? 0 : line_start + 1, max_bytes);
}

// Numerically equal to spam_engine_log_level_t.
enum class LogLevel : std::uint8_t { kDebug = 1, kInfo = 2, kWarn = 3, kError = 4 };

using LogSink = void (*)(int level, const char* text, void* user);

// Process-global, like ggml_log_set: there is one engine library per process
// and the lines it emits before any handle exists (backend registration) have
// no handle to belong to. NULL restores stderr. `user` must outlive every
// call that can log: the sink runs outside the lock (so it may log back),
// and a set_log_sink(NULL) does not wait for a delivery in flight on another
// thread. Both apps install once and never detach.
//
// Defined in spam_engine.cpp, not inline: the state has to be ONE object,
// and an inline function-local static is one per dynamic library that
// instantiates it. set_log_sink is called from libspam_engine_c_api and
// log_line from libspam_engine, so with the inline form the two only met
// because dyld coalesced the weak symbols; -fvisibility=hidden or a static
// link would have split them, and the callback would install into a copy
// the engine never reads.
void set_log_sink(LogSink fn, void* user);

// `text` is delivered as given, newline included when the writer wrote one;
// ggml emits partial lines and a sink that reassembles them must see the
// pieces.
void log_line(LogLevel level, const char* text);

// printf-shaped, one line, newline appended. 1 KB is ample: the longest line
// the engine writes is a path plus a reason. A template rather than a C
// variadic so clang-tidy's modernize check passes; the arguments still reach
// snprintf as-is, so pass c_str() for strings and double for floats. The
// static_assert is what a C variadic would have had from -Wformat: a
// std::string under %s is a compile error here, not garbage in the appex log.
// Not named logf: that is <cmath>'s natural log, and the engine does float
// math in this namespace.
template <typename... Args>
void log_printf(LogLevel level, const char* fmt, Args... args) {
  static_assert(((std::is_arithmetic_v<Args> || std::is_pointer_v<Args>) && ...),
                "log_printf arguments must be arithmetic or pointers (c_str() a std::string)");
  std::array<char, 1024> buf{};
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
  if (std::snprintf(buf.data(), buf.size(), fmt, args...) < 0) { return; }
  log_line(level, (std::string(buf.data()) + '\n').c_str());
}

}  // namespace spam_engine
