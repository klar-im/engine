// N-API addon embedding the Klar spam engine directly in the website node
// process. Loads the model ONCE on first classify, then runs classify on a
// libuv worker thread (Napi::AsyncWorker) so the marketing site is never
// blocked. Replaces the separate demo_server process + port 8765.
//
// The engine C API serializes access per handle, so concurrent classify calls
// from the worker pool queue safely against the single shared handle.
//
// Lifetime: the Metal backend asserts at process exit if any engine handle is
// still alive (see spam_engine_c_api.h). We register a Node env cleanup hook
// that destroys the handle before exit.

#include <napi.h>

#include <sys/stat.h>

#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "spam_engine_c_api.h"

namespace {

// One process-wide engine handle, lazily loaded. `mutex` guards the whole
// lifecycle — load, classify, and destroy — so the env cleanup hook can never
// free the handle while a worker is mid-classify.
struct EngineState {
  spam_engine_handle_t* handle = nullptr;
  bool loaded = false;
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
  }
}

// Load the model if not already loaded. Returns "" on success, else an error
// string. Idempotent; the caller MUST hold g_engine.mutex.
std::string EnsureLoadedLocked(const std::string& model_path) {
  if (g_engine.loaded) return "";

  if (!g_engine.handle) {
    g_engine.handle = spam_engine_create();
    if (!g_engine.handle) return "failed to create engine handle";
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
  return "";
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

}  // namespace

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  napi_add_env_cleanup_hook(env, CleanupEngine, nullptr);
  exports.Set("classify", Napi::Function::New(env, Classify));
  return exports;
}

NODE_API_MODULE(klar_engine, Init)
