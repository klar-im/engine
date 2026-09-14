#pragma once

// GgmlEncoder: llama.cpp/ggml encoder backend for XLM-RoBERTa-style BERT models.
//
// Drop-in replacement for the CTranslate2 encoder path. Takes the same text inputs,
// returns the same 1024-dim CLS embeddings. Uses CLS pooling and Metal GPU offload
// (n_gpu_layers=99) by default. Tokenization uses the GGUF's built-in vocab — no
// separate sentencepiece model needed.
//
// Design notes:
// - Header-only (consistent with trainable_classifier.h and ftrl_classifier.h).
// - Sequences are encoded one at a time. For batch=2 (plain+HTML in classify_rfc822),
//   that's two serial GPU calls — still 60%+ faster than CT2 on the same inputs.
//   True multi-seq batching can be added later if profiling shows it matters.
// - ggml_backend_load_all() / llama_backend_init() are called once per process via call_once.
// - Configurable token cap (default 128, set via EngineConfig::encoder_max_tokens).
//   Long inputs are truncated and EOS is re-appended at the tail. The cap is
//   bounds-checked at load() against [kMinMaxTokens, model->n_ctx_train] —
//   exceeding the model's training context triggers an unrecoverable ggml_abort
//   at encode time, so we throw early instead.

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

#include <dlfcn.h>

#include <ggml-backend.h>
#include <llama.h>

namespace spam_engine {

// dladdr() anchor: its address resolves to the shared library this header was
// compiled into (libspam_engine), which is where the engine cmake stages the
// ggml backend plugins. Used by GgmlEncoder's backend-loading fallback below.
inline void backend_plugin_dir_anchor() {}

// Bounded capture of ggml/llama native log output. ggml logs to stderr, which
// the Mail-extension sandbox discards, so a backend-load failure there surfaces
// as a silent status. Capturing it lets load() attach the real reason (e.g.
// "no backends are loaded") to the exception the C ABI hands back to Swift.
inline std::mutex& native_log_mutex() {
  static std::mutex m;
  return m;
}

inline std::string& native_log_buffer() {
  static std::string buffer;
  return buffer;
}

inline void native_log_callback(ggml_log_level /*level*/, const char* text, void* /*user*/) {
  if (text == nullptr) { return;
}
  // Keep dev/CLI behaviour unchanged: ggml normally prints to stderr.
  std::fputs(text, stderr);
  std::scoped_lock const lock(native_log_mutex());
  std::string& buffer = native_log_buffer();
  buffer.append(text);
  constexpr size_t kMaxNativeLog = 4096;  // keep only the recent tail
  if (buffer.size() > kMaxNativeLog) {
    buffer.erase(0, buffer.size() - kMaxNativeLog);
  }
}

inline std::string drain_native_log() {
  std::scoped_lock const lock(native_log_mutex());
  std::string out = native_log_buffer();
  native_log_buffer().clear();
  return out;
}

// True once process exit has torn down, or is about to tear down, ggml's own
// statics. See install_exit_teardown_guard() for why this exists and why the
// flag is set where it is.
inline bool& ggml_exit_teardown_started() {
  static bool started = false;
  return started;
}

// Freeing a llama_context after ggml's backend statics are gone is a wild jump
// through a dangling function pointer, not a clean no-op: the process dies in
// llama_context::~llama_context with SIGBUS/SIGSEGV. That is reachable whenever
// teardown is deferred to an atexit handler, because handlers run in reverse
// registration order and the ggml backend plugins are dlopen'd LAZILY on the
// first load — so a handler a caller registered at startup (the natural place)
// always runs AFTER ggml has already torn itself down.
//
// This guard makes that ordering safe for every binding instead of asking each
// one to get the rule right. Registering here, immediately after the first
// successful load, is what makes it work: everything ggml registers it
// registers during that load, so this handler runs BEFORE all of it. Callers
// that tear down properly (explicitly, or from a handler registered after a
// load) run earlier still and see the flag clear, so they do the real work.
// Anything running after this point deliberately leaks the model instead: the
// process is exiting, and GGML_METAL_NO_RESIDENCY=1 (set below) means an
// undestroyed handle no longer trips libggml-metal's residency-set assert.
inline void install_exit_teardown_guard() {
  static std::once_flag guard_flag;
  std::call_once(guard_flag, [] {
    std::atexit([] { ggml_exit_teardown_started() = true; });
  });
}

// Disable ggml's Metal residency-set optimization (ggml 0.17+). It has a
// teardown-tracking bug that aborts on model UNLOAD for some models
// (GGML_ASSERT([rsets->data count] == 0), ggml-metal-device.m). Production
// reloads models (SpamTrainer night-training, SpamEngineClient swap), so it
// would crash. Validated 2026-07-28: eliminates the abort with no memory leak
// (RSS plateaus across 12 load/unload cycles) and no latency change (residency
// sets help batched work, not per-email classify). Must run before the Metal
// device is created, and before any getenv() anywhere in the process can
// observe a partial write to environ — hence its own call_once, called both
// from GgmlEncoder::load() and from SpamEngine::load() before that function's
// own getenv() calls, so two SpamEngine instances loading concurrently for
// the first time serialize on it instead of racing (codex review, TASK-478).
// overwrite=0 respects an explicit override.
inline void ensure_ggml_env_configured() {
  static std::once_flag flag;
  std::call_once(flag, [] {
    // NOLINTNEXTLINE(concurrency-mt-unsafe) — call_once makes this race-free.
    setenv("GGML_METAL_NO_RESIDENCY", "1", 0);
  });
}

class GgmlEncoder {
 public:
  GgmlEncoder() = default;

  ~GgmlEncoder() {
    // Leak deliberately rather than crash; see install_exit_teardown_guard().
    if (ggml_exit_teardown_started()) { return;
}
    if (ctx_) { llama_free(ctx_);
}
    if (model_) { llama_model_free(model_);
}
  }

  GgmlEncoder(const GgmlEncoder&) = delete;
  GgmlEncoder& operator=(const GgmlEncoder&) = delete;
  GgmlEncoder(GgmlEncoder&&) = delete;
  GgmlEncoder& operator=(GgmlEncoder&&) = delete;

  // Smallest cap that produces a sensible encoding: BOS + a handful of content
  // tokens + EOS. Below this the head sees almost nothing useful and CLS
  // pooling reduces to the special-token embedding.
  static constexpr int kMinMaxTokens = 8;

  void load(const std::string& gguf_path, int max_tokens) {
    if (max_tokens < kMinMaxTokens) {
      throw std::invalid_argument(
          "GgmlEncoder: max_tokens=" + std::to_string(max_tokens) +
          " below minimum " + std::to_string(kMinMaxTokens));
    }
    max_tokens_ = max_tokens;
    // Must happen before the Metal device is created (TASK-367); its own
    // call_once (see ensure_ggml_env_configured) is what makes it race-free
    // against SpamEngine::load()'s getenv() calls, not this one below.
    ensure_ggml_env_configured();
    // ggml_backend_load_all() registers backends from shared libs; calling it
    // multiple times within a process exceeds GGML_SCHED_MAX_BACKENDS.
    // Guard with call_once so tests that create multiple engines don't abort.
    static std::once_flag init_flag;
    std::call_once(init_flag, [] {
      // Route ggml/llama logs through our capture so a backend-load failure can
      // report why (installed before load_all so the backend-registration log
      // is captured too).
      ggml_log_set(native_log_callback, nullptr);
      llama_log_set(native_log_callback, nullptr);

      // OUR plugins first. The engine cmake and the app bundler both stage the
      // ggml backend plugins next to the engine libs, so the directory this
      // code was loaded from holds the exact plugins we ship, sign and test.
      // Loading them by path is deterministic and needs no other directory to
      // be readable.
      //
      // ggml_backend_load_all() is the fallback, and it must stay a fallback:
      // besides the executable directory and CWD it enumerates the
      // GGML_BACKEND_DIR compiled into libggml, which for the Homebrew build we
      // ship is /opt/homebrew/Cellar/ggml/<v>/libexec. On a developer Mac that
      // path EXISTS but is unreadable from inside the Mail-extension sandbox,
      // and fs::directory_iterator throws rather than skipping it. Running it
      // first therefore killed model load before our own plugins were ever
      // tried, and the appex silently classified nothing. Both calls are
      // wrapped: an unreadable search path is not a reason to fail.
      std::string searched_dir;
      std::string load_error;
      auto const try_load = [&load_error](auto&& fn) {
        try {
          fn();
        } catch (const std::exception& e) {
          if (load_error.empty()) { load_error = e.what();
}
        }
      };

      Dl_info info{};
      if (dladdr(reinterpret_cast<const void*>(&backend_plugin_dir_anchor), &info) != 0
          && info.dli_fname != nullptr) {
        searched_dir = std::filesystem::path(info.dli_fname).parent_path().string();
        try_load([&] { ggml_backend_load_all_from_path(searched_dir.c_str()); });
      }
      if (ggml_backend_dev_count() == 0) {
        try_load([] { ggml_backend_load_all(); });
      }

      // Hard-fail with a descriptive, Swift-visible reason if still no backend.
      // This is the failure that silently no-op'd the Mail extension for weeks:
      // the appex ships no ggml backend plugins, so the model never loaded and
      // the C ABI returned an empty "Unknown error". Turn it into a real error.
      if (ggml_backend_dev_count() == 0) {
        throw std::runtime_error(
            std::string("ggml registered no compute backends (searched ") +
            (searched_dir.empty() ? std::string("the executable directory")
                                  : "'" + searched_dir + "' and the executable "
                                                         "directory") +
            "); the ggml backend plugin libraries are missing next to the engine "
            "library. " +
            (load_error.empty() ? std::string()
                                : "Loader error: " + load_error + ". ") +
            "Native log: " + drain_native_log());
      }

      llama_backend_init();
    });
    // SPAM_ENGINE_NO_GPU forces CPU (n_gpu=0) — lets the backend-parity probe
    // measure CI-CPU vs prod-Metal divergence on the same model (TASK-204).
    // the only setenv() in this class runs inside the call_once above, so by
    // this point env mutation is done.
    const int default_gpu_layers =
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        std::getenv("SPAM_ENGINE_NO_GPU") != nullptr ? 0 : 99;
    load_with_gpu_layers(gguf_path, default_gpu_layers);
    // After the load, never before: ggml's device statics are constructed
    // lazily during it, and this must be registered later than all of them.
    install_exit_teardown_guard();
  }

  std::vector<std::vector<float>> embed_batch(const std::vector<std::string>& texts) {
    std::vector<std::vector<float>> results;
    results.reserve(texts.size());
    for (const auto& text : texts) {
      results.push_back(embed_one(text));
    }
    return results;
  }

  // Embedding dimension of the loaded model (0 before load). Fixed for the
  // model's lifetime, so callers size output buffers from this exactly once.
  [[nodiscard]] int n_embd() const noexcept { return n_embd_; }

  // True only when this loaded instance requested offload, a GPU backend was
  // registered, and context creation succeeded without the CPU fallback.
  [[nodiscard]] bool uses_gpu() const noexcept { return uses_gpu_; }

 private:
  // Pre-truncation tokenize buffer. Large enough to absorb any realistic email
  // before we truncate to max_tokens_. Independent of the runtime cap.
  static constexpr int kTokenBufSize = 8192;

  int                max_tokens_ = 128;
  llama_model*       model_ = nullptr;
  llama_context*     ctx_   = nullptr;
  const llama_vocab* vocab_ = nullptr;
  int                n_embd_ = 0;
  bool               uses_gpu_ = false;
  // Persistent buffer to avoid per-call allocation churn during batch
  // embedding (training processes hundreds/thousands of samples).
  std::vector<llama_token> token_buf_;

  std::vector<float> embed_one(const std::string& text) {
    // Tokenize to a large buffer first, then truncate to max_tokens_.
    // We pass add_special=true, but the GGUF metadata `add_bos_token` was
    // set to False during conversion (a `convert_hf_to_gguf.py` quirk for
    // XLM-RoBERTa-derived models — see PARITY_PLAN.md and the encoder-bug
    // investigation in this commit's parent). The metadata override wins,
    // so llama_tokenize does NOT prepend the <s> BOS even though we ask
    // for it. Without the <s> at position 0, CLS pooling reads the
    // embedding of the *first content token*, not the [CLS] embedding the
    // upstream HF head was trained against.
    //
    // Manually prepend the BOS ourselves so the tokenization is identical
    // to HF's `tokenizer.encode(text)`. This is the right fix regardless
    // of the GGUF metadata: we always want <s> at position 0 for CLS
    // pooling on a bidirectional encoder model.
    //
    // assign() (not resize()) so any unwritten slots are zeroed. The
    // llama.cpp header doesn't guarantee buffer contents on a negative
    // (buffer-too-small) return — without this, the persistent buffer
    // could expose stale tokens from the previous email.
    token_buf_.assign(kTokenBufSize, 0);
    int n = llama_tokenize(vocab_, text.c_str(), static_cast<int32_t>(text.size()),
                           token_buf_.data(), static_cast<int32_t>(token_buf_.size()),
                           /*add_special=*/true, /*parse_special=*/false);
    if (n < 0) {
      // Buffer too small: llama_tokenize wrote NOTHING and returns -(required
      // count). Re-tokenize into a local exactly-sized scratch so we keep the
      // real leading tokens. Setting n = buffer size here (the old behaviour)
      // would encode a buffer full of zeroed BOS ids: a content-free CLS
      // embedding for any email over kTokenBufSize tokens (long digests). The
      // scratch is local (freed at scope exit) so the persistent token_buf_
      // doesn't ratchet up to a huge email's token count for the process life.
      const int needed = -n;
      std::vector<llama_token> scratch(needed, 0);
      int cnt = llama_tokenize(vocab_, text.c_str(), static_cast<int32_t>(text.size()),
                               scratch.data(), static_cast<int32_t>(scratch.size()),
                               /*add_special=*/true, /*parse_special=*/false);
      if (cnt < 0) {
        // Exact-size buffer should always succeed; guard defensively.
        cnt = needed;
      }
      // Only the leading max_tokens_ survive truncation below, so copy just
      // those back into the persistent buffer.
      const int keep = std::min(cnt, max_tokens_);
      token_buf_.assign(scratch.begin(), scratch.begin() + keep);
      n = cnt;
    }
    if (n > max_tokens_) {
      // Truncate and restore EOS at the last position (mirrors CT2 path).
      n = max_tokens_;
      token_buf_[n - 1] = llama_vocab_eos(vocab_);
    }
    token_buf_.resize(n);

    // Prepend BOS if llama_tokenize didn't add it (the metadata-override case).
    const llama_token bos = llama_vocab_bos(vocab_);
    if (token_buf_.empty() || token_buf_.front() != bos) {
      token_buf_.insert(token_buf_.begin(), bos);
      // Re-truncate if prepending pushed us over the limit.
      if (static_cast<int>(token_buf_.size()) > max_tokens_) {
        token_buf_.resize(max_tokens_);
        token_buf_[max_tokens_ - 1] = llama_vocab_eos(vocab_);
      }
    }

    // Clear context memory so each call is independent.
    llama_memory_clear(llama_get_memory(ctx_), /*data=*/false);

    // Encode as a single sequence (seq_id = 0 via batch_get_one).
    auto const batch = llama_batch_get_one(token_buf_.data(), static_cast<int32_t>(token_buf_.size()));
    if (llama_encode(ctx_, batch) != 0) {
      throw std::runtime_error("GgmlEncoder: llama_encode failed");
    }

    // CLS pooling: llama.cpp returns the pooled embedding for seq 0.
    const float* emb = llama_get_embeddings_seq(ctx_, 0);
    if (!emb) {
      throw std::runtime_error("GgmlEncoder: embedding extraction returned null (pooling misconfigured?)");
    }
    return {emb, emb + n_embd_};
  }

  // Try to load with the given GPU layer count. If context creation fails
  // (e.g. Metal unavailable in sandbox/VM), retry with CPU only (n_gpu=0).
  //
  // NOTE: the Metal fallback calls ggml_backend_unload(MTL) which is a
  // GLOBAL operation — it disables Metal for ALL encoder instances in the
  // process. This is intentional: once one instance detects that Metal is
  // blocked (sandbox/VM), all subsequent instances should skip it too
  // rather than repeating the failed init. The backend registry is
  // process-global and initialized once via call_once above.
  void load_with_gpu_layers(const std::string& gguf_path, int n_gpu_layers) {
    // ggml 0.17 may still choose an initialized Metal backend for context work
    // when model layers and KQV are CPU-only. That breaks the documented
    // SPAM_ENGINE_NO_GPU contract in sandboxes/VMs where Metal is present but
    // cannot create a command queue. Explicit CPU mode is process-wide, so unload
    // MTL before model/context creation just as the GPU-failure fallback does.
    if (n_gpu_layers == 0) {
      auto *metal_reg = ggml_backend_reg_by_name("MTL");
      if (metal_reg) { ggml_backend_unload(metal_reg);
}
    }

    auto mparams = llama_model_default_params();
    mparams.n_gpu_layers = n_gpu_layers;

    model_ = llama_model_load_from_file(gguf_path.c_str(), mparams);
    if (!model_) {
      throw std::runtime_error("GgmlEncoder: failed to load model: " + gguf_path);
    }

    // Clamp the cap against the model's training context. Exceeding n_ctx_train
    // at encode time triggers GGML_ASSERT(n_ubatch >= n_tokens) → ggml_abort()
    // — uncatchable, kills the host process. Better to fail load() with a
    // recoverable exception.
    const int n_ctx_train = llama_model_n_ctx_train(model_);
    if (max_tokens_ > n_ctx_train) {
      const int requested = max_tokens_;
      llama_model_free(model_);
      model_ = nullptr;
      throw std::invalid_argument(
          "GgmlEncoder: max_tokens=" + std::to_string(requested) +
          " exceeds model n_ctx_train=" + std::to_string(n_ctx_train));
    }

    auto cparams = llama_context_default_params();
    cparams.n_ctx = max_tokens_;
    cparams.n_batch = max_tokens_;
    cparams.embeddings = true;
    // Pooling defaults to CLS (XLM-RoBERTa). ModernBERT-family bases (e.g. mmBERT)
    // train with MEAN pooling; override per-model with SPAM_ENGINE_POOLING=mean.
    // (Measurement hook for the base-model bake-off; TASK-364 makes it manifest-driven.)
    cparams.pooling_type = LLAMA_POOLING_TYPE_CLS;
    // NOLINTNEXTLINE(concurrency-mt-unsafe) — see the getenv() note above.
    if (const char* pool = std::getenv("SPAM_ENGINE_POOLING"); pool && (std::string(pool) == "mean")) {
      cparams.pooling_type = LLAMA_POOLING_TYPE_MEAN;
}

    // Encoder-only model: no autoregressive decoding, KV offload irrelevant.
    // Disabling avoids Metal init when n_gpu_layers=0 (e.g. sandbox/CPU fallback).
    cparams.offload_kqv = (n_gpu_layers > 0);

    ctx_ = llama_init_from_model(model_, cparams);
    if (!ctx_ && n_gpu_layers > 0) {
      // GPU init failed (e.g. Metal blocked in sandbox) — retry CPU-only.
      // Unload MTL so context init doesn't try to init it again on retry.
      auto *metal_reg = ggml_backend_reg_by_name("MTL");
      if (metal_reg) { ggml_backend_unload(metal_reg);
}
      llama_model_free(model_);
      model_ = nullptr;
      load_with_gpu_layers(gguf_path, 0);
      return;
    }
    if (!ctx_) {
      llama_model_free(model_);
      model_ = nullptr;
      throw std::runtime_error("GgmlEncoder: failed to create context");
    }

    uses_gpu_ = n_gpu_layers > 0 &&
        (ggml_backend_dev_by_type(GGML_BACKEND_DEVICE_TYPE_GPU) != nullptr ||
         ggml_backend_dev_by_type(GGML_BACKEND_DEVICE_TYPE_IGPU) != nullptr);

    n_embd_ = llama_model_n_embd(model_);
    vocab_ = llama_model_get_vocab(model_);
  }
};

}  // namespace spam_engine
