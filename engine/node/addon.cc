// N-API addon embedding the Klar spam engine directly in the website node
// process. Keeps ONE model resident, loaded lazily on the first classify and
// swapped when a call names a different directory, and runs classify on a libuv
// worker thread (Napi::AsyncWorker) so the marketing site is never blocked.
// Replaces the separate demo_server process + port 8765.
//
// The engine C API serializes access per handle, so concurrent classify calls
// from the worker pool queue safely against the single shared handle.
//
// Lifetime: the Metal backend asserts at process exit if any engine handle is
// still alive (see spam_engine_c_api.h). We register a Node env cleanup hook
// that destroys the handle before exit.

#include <napi.h>

#include <sys/stat.h>

#include <cstdint>
#include <cstring>
#include <exception>
#include <mutex>
#include <string>
#include <vector>

#include "spam_engine_c_api.h"

namespace {

// ── ABI drift guard ─────────────────────────────────────────────────────────
// This addon is one of the hand-written FFI mirrors spam_engine_c_api.h warns
// about, and it is the one most likely to go stale: the .node is a build
// artifact that nothing invalidates when the engine's headers change, so a
// `make engine/build` months later leaves a binary whose structs are the old,
// SHORTER ones. The engine then writes its current parsed_signals (1568 bytes
// today) into the worker's older, smaller member, straight through the two
// members that follow it, and the classify path corrupts memory instead of
// failing.
//
// That is not hypothetical. A .node built 2026-07-14 against a header that
// changed five times between the 21st and the 30th aborted the website's dev
// server on one specific fixture: the overflow landed on the std::vector that
// collects URL domains, and its next emplace_back computed a capacity out of
// smashed pointers and threw std::length_error. The verdict-changing version of
// the same bug is worse and silent, which is why the header reports its own
// sizes and asks every mirror to assert against them.
//
// So: check at module load, and refuse to export anything on a mismatch. A
// startup error naming the stale file is recoverable; a corrupted heap is not.
const char* kAbiFieldNames[] = {"parsed_signals", "decision_input",
                                "decision_result", "caller_state",
                                "full_result",     "result",
                                "scores", "attachment_features"};
constexpr uint32_t kAbiFieldCount = 8;
// The names and the count are edited by hand and read together in the loop
// below, so a struct added to one and not the other would walk off the end of
// the names. The header asks for exactly this ("adding a struct here means
// adding a field here AND bumping field_count"); this is that rule, enforced.
static_assert(sizeof(kAbiFieldNames) / sizeof(*kAbiFieldNames) == kAbiFieldCount,
              "kAbiFieldNames and kAbiFieldCount disagree");

// Returns "" when this build agrees with the loaded engine, else what differs.
std::string CheckAbi() {
  // Deliberately NOT sized by our own spam_engine_abi_sizes_t. This is the one
  // call that has to survive the drift it exists to detect: if the engine's
  // descriptor has grown more fields than ours, sizing the buffer from our
  // struct would overflow it in the very function meant to catch overflows.
  // A generous uint32_t array, aligned for the struct, cannot.
  alignas(spam_engine_abi_sizes_t) uint32_t raw[64] = {};
  spam_engine_get_abi_sizes(reinterpret_cast<spam_engine_abi_sizes_t*>(raw));

  const uint32_t engine_field_count = raw[0];
  if (engine_field_count != kAbiFieldCount) {
    return "the engine describes " + std::to_string(engine_field_count) +
           " ABI structs, this addon knows " + std::to_string(kAbiFieldCount) +
           "; the addon was built against a different spam_engine_c_api.h";
  }

  const uint32_t ours[kAbiFieldCount] = {
      static_cast<uint32_t>(sizeof(spam_engine_parsed_signals_t)),
      static_cast<uint32_t>(sizeof(spam_engine_decision_input_t)),
      static_cast<uint32_t>(sizeof(spam_engine_decision_result_t)),
      static_cast<uint32_t>(sizeof(spam_engine_caller_state_t)),
      static_cast<uint32_t>(sizeof(spam_engine_full_result_t)),
      static_cast<uint32_t>(sizeof(spam_engine_result_t)),
      static_cast<uint32_t>(sizeof(spam_engine_scores_t)),
      static_cast<uint32_t>(sizeof(spam_engine_attachment_features_t)),
  };

  std::string bad;
  for (uint32_t i = 0; i < kAbiFieldCount; ++i) {
    // raw[0] is field_count, so the i-th size sits at raw[i + 1].
    const uint32_t theirs = raw[i + 1];
    if (theirs == ours[i]) continue;
    if (!bad.empty()) bad += ", ";
    bad += std::string(kAbiFieldNames[i]) + " engine=" +
           std::to_string(theirs) + " addon=" + std::to_string(ours[i]);
  }
  return bad;
}

// One process-wide engine handle, lazily loaded. `mutex` guards the whole
// lifecycle — load, classify, and destroy — so the env cleanup hook can never
// free the handle while a worker is mid-classify.
//
// ONE model is resident at a time. `path` is the directory that model came from,
// and asking for a different one swaps it (see EnsureLoadedLocked). The demo
// server is a 2 GB RAM box and XLM-R-large is 407 MB, so holding two is not an
// option; the mutex is what makes the swap safe, since it is already held across
// every classify.
struct EngineState {
  spam_engine_handle_t* handle = nullptr;
  bool loaded = false;
  std::string path;
  std::mutex mutex;
};

EngineState g_engine;

// Destroy the handle before process exit (Metal lifetime contract). Registered
// once via napi_add_env_cleanup_hook. Takes the mutex so it waits for any
// in-flight classify before freeing the handle.
void CleanupEngine(void* /*arg*/) {
  std::lock_guard<std::mutex> lock(g_engine.mutex);
  if (g_engine.handle) {
    if (g_engine.loaded) spam_engine_unload(g_engine.handle);
    spam_engine_destroy(g_engine.handle);
    g_engine.handle = nullptr;
    g_engine.loaded = false;
    g_engine.path.clear();
  }
}

// Load the requested model, swapping the resident one if a different directory
// is asked for. Returns "" on success, else an error string. Idempotent for the
// model already loaded; the caller MUST hold g_engine.mutex.
std::string EnsureLoadedLocked(const std::string& model_path) {
  if (g_engine.loaded && g_engine.path == model_path) return "";

  if (!g_engine.handle) {
    g_engine.handle = spam_engine_create();
    if (!g_engine.handle) return "failed to create engine handle";
  }

  // Drop the resident model BEFORE allocating the next one, so peak memory is
  // one encoder rather than two. SpamEngine::load unloads internally as well, so
  // this is not what makes the swap correct; what it buys is the failure path.
  // Clearing `loaded`/`path` here means a load that fails leaves the state
  // saying "nothing is loaded" instead of still claiming the model whose weights
  // have already been freed underneath it.
  if (g_engine.loaded) {
    spam_engine_unload(g_engine.handle);
    g_engine.loaded = false;
    g_engine.path.clear();
  }

  // FTRL re-enabled (TASK-219): the auto-bypass that let a cold/parity-skewed
  // FTRL override the neural head is gone — classify now ENSEMBLES FTRL P(spam)
  // into the neural verdict at a low fixed weight (0.2), and the baseline is
  // parity-fixed (trained on the canonical inference envelope). Load the FTRL
  // weights only if the file is actually present next to the model (stat-guard),
  // so a model dir without ftrl_baseline.bin still runs neural-only cleanly.
  const std::string ftrl_path = model_path + "/ftrl_baseline.bin";
  struct stat st_buf;
  const bool ftrl_present = stat(ftrl_path.c_str(), &st_buf) == 0;
  spam_engine_status_t st = spam_engine_load(
      g_engine.handle, model_path.c_str(), /*learning_rate=*/0.0f,
      ftrl_present ? ftrl_path.c_str() : nullptr);
  if (st != SPAM_ENGINE_STATUS_OK) {
    const char* err = spam_engine_get_last_error(g_engine.handle);
    return std::string("model load failed: ") + (err && *err ? err : "unknown");
  }
  g_engine.loaded = true;
  g_engine.path = model_path;
  return "";
}

// Fill a JS object from spam_engine_model_info. Shared by the classify result
// and the standalone modelInfo() export so the two can never describe the same
// artifact differently. `mi` must come from a successful spam_engine_model_info.
Napi::Object ModelInfoObject(Napi::Env env, const spam_engine_model_info_t& mi) {
  Napi::Object out = Napi::Object::New(env);
  // An empty uuid means "this directory carries no manifest", which is a real
  // and different answer from any uuid. Null, not "", so a consumer cannot print
  // it as a model name by accident.
  out.Set("uuid", mi.uuid[0] == '\0' ? env.Null()
                                     : Napi::String::New(env, mi.uuid).As<Napi::Value>());
  out.Set("sourceModel", mi.source_model[0] == '\0'
                             ? env.Null()
                             : Napi::String::New(env, mi.source_model).As<Napi::Value>());
  out.Set("hiddenSize", Napi::Number::New(env, mi.hidden_size));
  out.Set("numLabels", Napi::Number::New(env, mi.num_labels));
  out.Set("rawInput", Napi::Boolean::New(env, mi.raw_input != 0));
  out.Set("structuralMarkers", Napi::Boolean::New(env, mi.structural_markers != 0));
  out.Set("attachmentContext", Napi::Boolean::New(env, mi.attachment_context != 0));
  return out;
}

// AsyncWorker that runs one classify (text or rfc822) off the JS thread and
// resolves a promise with {class, confidence, scores}.
class ClassifyWorker : public Napi::AsyncWorker {
 public:
  ClassifyWorker(Napi::Env env, std::string payload, bool is_eml,
                 std::string model_path, std::string mode, bool debug)
      : Napi::AsyncWorker(env),
        deferred_(Napi::Promise::Deferred::New(env)),
        payload_(std::move(payload)),
        is_eml_(is_eml),
        model_path_(std::move(model_path)),
        mode_(std::move(mode)),
        debug_(debug) {}

  Napi::Promise Promise() { return deferred_.Promise(); }

  void Execute() override {
    // This addon is built with NAPI_DISABLE_CPP_EXCEPTIONS, so node-addon-api
    // does NOT wrap Execute() in a try/catch, while the compiler still has
    // exceptions on (GCC_ENABLE_CPP_EXCEPTIONS / -fexceptions in binding.gyp).
    // Anything thrown here therefore unwinds into a libuv C callback and
    // terminates the process: no stack, no rejected promise, the whole host
    // gone. For the website that means the marketing site dies because a demo
    // fixture misbehaved. Catch at the boundary and reject instead.
    try {
      Run();
    } catch (const std::exception& e) {
      SetError(std::string("classify failed: ") + e.what());
    } catch (...) {
      SetError("classify failed: unknown C++ exception");
    }
  }

  // The former body of Execute(), unchanged. Split out so the handler above is
  // just the boundary.
  void Run() {
    // Runs on a libuv worker thread (NOT the JS thread) so the multi-second cold
    // model load never blocks the event loop. Hold the mutex across load +
    // classify: it serializes the load-once dance and keeps the cleanup hook
    // from freeing the handle mid-classify. The engine serializes classify per
    // handle anyway, so this adds no real contention.
    std::lock_guard<std::mutex> lock(g_engine.mutex);
    std::string load_err = EnsureLoadedLocked(model_path_);
    if (!load_err.empty()) {
      SetError(load_err);
      return;
    }

    spam_engine_status_t st;
    if (is_eml_) {
      // Capture the structural signals (sender-auth + thread) the same parse
      // already produces, so we can run the decision-layer fold and show them.
      // mode_ defaults to "ensemble" (neural head + low-weight FTRL blend,
      // TASK-219); the /demo ?mode= override can force "neural"/"ftrl".
      st = spam_engine_classify_rfc822(g_engine.handle, payload_.data(),
                                       payload_.size(), "", "", mode_.c_str(),
                                       &result_, &signals_);
    } else {
      st = spam_engine_classify(g_engine.handle, payload_.c_str(), "", "",
                                mode_.c_str(), &result_);
    }
    if (st != SPAM_ENGINE_STATUS_OK) {
      const char* err = spam_engine_get_last_error(g_engine.handle);
      SetError(err && *err ? err : "classification failed");
      return;
    }

    // Structural decision-layer fold — the SAME verdict the Apple extension
    // produces: folds the sender-auth / thread offsets onto the model's
    // spam-side and applies the standard threshold. For plain text there are no
    // headers, so signals_ is zeroed and no offset fires (verdict == neural).
    spam_engine_decision_input_t din{};
    spam_engine_decision_input_from_signals(&din, &result_.scores, &signals_);
    din.profile = SPAM_ENGINE_PROFILE_STANDARD;
    spam_engine_decide(&din, &decision_);

    // Which artifact produced this verdict, read here rather than by a separate
    // modelInfo() call afterwards. Under the mutex the answer is the model that
    // actually ran; outside it, a swap for the next request could already have
    // happened, and the verdict would be attributed to the wrong model. That
    // matters more than it sounds: the demo has silently changed model
    // underneath us before and nobody noticed for a month.
    has_model_ = spam_engine_model_info(g_engine.handle, &model_) == 1;

    // Distinct link domains for the reputation/explanation panel (EML only).
    if (is_eml_) {
      char* urls =
          spam_engine_extract_url_domains(payload_.data(), payload_.size());
      if (urls) {
        for (const char* p = urls; *p;) {
          const char* nl = std::strchr(p, '\n');
          const size_t len = nl ? static_cast<size_t>(nl - p) : std::strlen(p);
          if (len > 0) url_domains_.emplace_back(p, len);
          if (!nl) break;
          p = nl + 1;
        }
        spam_engine_free_string(urls);
      }
    }
  }

  void OnOK() override {
    Napi::Env env = Env();
    Napi::Object scores = Napi::Object::New(env);
    scores.Set("gibberish", Napi::Number::New(env, result_.scores.gibberish));
    scores.Set("marketing", Napi::Number::New(env, result_.scores.marketing));
    scores.Set("regular", Napi::Number::New(env, result_.scores.regular));
    scores.Set("spam", Napi::Number::New(env, result_.scores.spam));

    // Sender-authentication + thread signals (zeroed for plain text).
    Napi::Object auth = Napi::Object::New(env);
    auth.Set("dkimSigningDomain", Napi::String::New(env, signals_.auth.dkim_signing_domain));
    auth.Set("fromOrgDomain", Napi::String::New(env, signals_.auth.from_org_domain));
    auth.Set("dmarcAligned", Napi::Boolean::New(env, signals_.auth.dmarc_aligned != 0));
    auth.Set("signerThrowaway", Napi::Boolean::New(env, signals_.auth.signer_throwaway != 0));
    auth.Set("displayImpersonation", Napi::Boolean::New(env, signals_.auth.display_impersonation != 0));

    Napi::Object thread = Napi::Object::New(env);
    thread.Set("hasInReplyTo", Napi::Boolean::New(env, signals_.thread.has_in_reply_to != 0));
    thread.Set("referencesCount", Napi::Number::New(env, signals_.thread.references_count));

    Napi::Array urls = Napi::Array::New(env, url_domains_.size());
    for (size_t i = 0; i < url_domains_.size(); ++i) {
      urls.Set(i, Napi::String::New(env, url_domains_[i]));
    }

    Napi::Object signals = Napi::Object::New(env);
    signals.Set("auth", auth);
    signals.Set("thread", thread);
    signals.Set("urlDomains", urls);

    // The structural fold = what Klar actually does with the message.
    Napi::Object decision = Napi::Object::New(env);
    decision.Set("label", Napi::String::New(env, decision_.label));
    decision.Set("confidence", Napi::Number::New(env, decision_.confidence));
    decision.Set("adjustedSpamSide", Napi::Number::New(env, decision_.adjusted_spam_side));
    decision.Set("condemnOffsetFired", Napi::Boolean::New(env, decision_.condemn_offset_fired != 0));

    Napi::Object out = Napi::Object::New(env);
    out.Set("class", Napi::String::New(env, spam_engine_label_name(result_.label)));
    out.Set("confidence", Napi::Number::New(env, result_.confidence));
    out.Set("scores", scores);
    out.Set("isEml", Napi::Boolean::New(env, is_eml_));
    out.Set("signals", signals);
    out.Set("decision", decision);
    out.Set("decidedBy", Napi::String::New(env, result_.decided_by));
    // Null only if the engine refused to describe itself, which is a fault
    // worth seeing rather than papering over with the last model we knew about.
    out.Set("model", has_model_ ? ModelInfoObject(env, model_).As<Napi::Value>() : env.Null());

    // ?debug — only the per-stage internals NOT already on the result: the mode
    // that ran, and the FTRL P(spam) before the blend (-1 = cold/off). The
    // verdict source is out.decidedBy and the ensemble spam side is
    // out.scores.spam; to see the pure neural number, re-run with mode=neural.
    if (debug_) {
      Napi::Object dbg = Napi::Object::New(env);
      dbg.Set("mode", Napi::String::New(env, mode_));
      dbg.Set("ftrlScore", Napi::Number::New(env, result_.ftrl_score));
      out.Set("debug", dbg);
    }
    deferred_.Resolve(out);
  }

  void OnError(const Napi::Error& e) override {
    deferred_.Reject(e.Value());
  }

 private:
  Napi::Promise::Deferred deferred_;
  std::string payload_;
  bool is_eml_;
  std::string model_path_;
  std::string mode_;
  bool debug_;
  spam_engine_result_t result_{};
  spam_engine_parsed_signals_t signals_{};
  spam_engine_decision_result_t decision_{};
  spam_engine_model_info_t model_{};
  bool has_model_ = false;
  std::vector<std::string> url_domains_;
};

// classify(payload: string|Buffer, isEml: boolean, modelPath: string,
//          mode?: string, debug?: boolean) -> Promise
Napi::Value Classify(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) {
    Napi::TypeError::New(env, "classify(payload, isEml, modelPath[, mode][, debug])")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }

  std::string payload;
  if (info[0].IsBuffer()) {
    Napi::Buffer<char> buf = info[0].As<Napi::Buffer<char>>();
    payload.assign(buf.Data(), buf.Length());
  } else if (info[0].IsString()) {
    payload = info[0].As<Napi::String>().Utf8Value();
  } else {
    Napi::TypeError::New(env, "payload must be a string or Buffer")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }

  bool is_eml = info[1].As<Napi::Boolean>().Value();
  std::string model_path = info[2].As<Napi::String>().Utf8Value();

  // mode: optional 4th arg, default "ensemble". The engine is the single source
  // of truth for valid modes (ensemble|neural|ftrl) — an invalid value comes
  // back as SPAM_ENGINE_STATUS_INVALID_ARGUMENT and the worker rejects the
  // promise with the engine's own message (see Execute), so no list is duplicated
  // here.
  std::string mode = info.Length() > 3 && info[3].IsString()
                         ? info[3].As<Napi::String>().Utf8Value()
                         : "ensemble";
  bool debug = info.Length() > 4 && info[4].ToBoolean().Value();

  // The model is loaded lazily inside the worker (off the event loop) — see
  // ClassifyWorker::Execute. Classify() only validates args and dispatches.
  ClassifyWorker* worker = new ClassifyWorker(
      env, std::move(payload), is_eml, std::move(model_path), std::move(mode), debug);
  Napi::Promise promise = worker->Promise();
  worker->Queue();
  return promise;
}

// modelInfo(modelPath) -> { uuid, sourceModel, hiddenSize, numLabels, rawInput,
// structuralMarkers } | null
//
// Synchronous on purpose: it reads fields the engine already holds after load,
// so there is nothing to take off the event loop. Loads the model if it is not
// loaded yet, exactly as classify does, so the first call from a cold process is
// the one that pays.
//
// It SWAPS the resident model when asked for a different directory, which costs
// a full load on the JS thread. Every hot-path caller reads `model` off the
// classify result instead; this is for a caller naming a model deliberately (the
// /demo selector listing what it can offer, /dev/models describing this host).
Napi::Value ModelInfo(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "modelInfo(modelPath)").ThrowAsJavaScriptException();
    return env.Null();
  }
  const std::string model_path = info[0].As<Napi::String>().Utf8Value();

  std::lock_guard<std::mutex> lock(g_engine.mutex);
  if (!EnsureLoadedLocked(model_path).empty()) return env.Null();

  spam_engine_model_info_t mi{};
  if (spam_engine_model_info(g_engine.handle, &mi) != 1) return env.Null();
  return ModelInfoObject(env, mi);
}

}  // namespace

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  // Before anything can call classify: refuse to load against an engine whose
  // structs are not the ones this binary was compiled against. Throwing here
  // surfaces as a require() failure the consumer already handles (the website
  // treats a non-loading addon as ClassifierUnavailableError and serves a 500
  // on the demo endpoint), which is exactly the degradation we want, instead of
  // a heap corruption several calls later.
  const std::string abi_error = CheckAbi();
  if (!abi_error.empty()) {
    Napi::Error::New(env,
                     "klar_engine addon is stale: " + abi_error +
                         ". Rebuild it with `make website/engine-addon`.")
        .ThrowAsJavaScriptException();
    return exports;
  }

  napi_add_env_cleanup_hook(env, CleanupEngine, nullptr);
  exports.Set("classify", Napi::Function::New(env, Classify));
  exports.Set("modelInfo", Napi::Function::New(env, ModelInfo));
  return exports;
}

NODE_API_MODULE(klar_engine, Init)
