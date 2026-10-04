import Foundation
import SpamEngineCAPI

func fail(_ message: String) -> Never {
  fputs("[FAIL] \(message)\n", stderr)
  exit(1)
}

func statusOK(_ status: spam_engine_status_t) -> Bool {
  status == SPAM_ENGINE_STATUS_OK
}

let sourceDir: String
if CommandLine.arguments.count > 1 {
  sourceDir = CommandLine.arguments[1]
} else {
  sourceDir = "."
}

let modelPath = "\(sourceDir)/model"

// The encoder file is whatever the artifact declares; run_swift_c_api_smoke.sh
// reads classifier_config.json and hands the name over, so this cannot skip on
// a filename the released set never had (gen3-v6 ships encoder-q8_0.gguf).
let encoderFile = ProcessInfo.processInfo.environment["KLAR_ENCODER_FILE"] ?? "encoder-q4_k_m.gguf"
if !FileManager.default.fileExists(atPath: "\(modelPath)/gguf/\(encoderFile)") {
  print("[SKIP] Swift C API smoke: model assets not found (\(encoderFile))")
  exit(0)
}

guard let handle = spam_engine_create() else {
  fail("spam_engine_create returned null")
}
defer { spam_engine_destroy(handle) }

if spam_engine_is_loaded(handle) != 0 {
  fail("new handle should start unloaded")
}

var result = spam_engine_result_t(
  label: 0,
  confidence: 0,
  scores: spam_engine_scores_t(marketing: 0, regular: 0, spam: 0),
  decided_by: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
  ftrl_score: -1
)

let preLoadStatus = "BUY VIAGRA NOW".withCString { text in
  spam_engine_classify(handle, text, nil, nil, "ensemble", &result)
}
if statusOK(preLoadStatus) {
  fail("classify before load should fail")
}

// The log callback, installed the way the appex installs it: a @convention(c)
// function with the receiver behind `user`. The engine's own load line must
// arrive; ggml's chatter arrives as DEBUG (TASK-505 L).
final class LogSpy {
  var sawLoadLine = false
  var sawNativeLine = false
}
let spy = LogSpy()
let spyPointer = Unmanaged.passUnretained(spy).toOpaque()
spam_engine_set_log_callback({ level, text, user in
  guard let text, let user else { return }
  let line = String(cString: text)
  let receiver = Unmanaged<LogSpy>.fromOpaque(user).takeUnretainedValue()
  if level == SPAM_ENGINE_LOG_INFO.rawValue && line.hasPrefix("[spam_engine] loaded backend=") {
    receiver.sawLoadLine = true
  }
  if level == SPAM_ENGINE_LOG_DEBUG.rawValue && !line.contains("[spam_engine]") {
    receiver.sawNativeLine = true
  }
}, spyPointer)

let loadStatus = modelPath.withCString { modelPathCString in
  spam_engine_load(handle, modelPathCString, 0.001, nil)
}
spam_engine_set_log_callback(nil, nil)
if !statusOK(loadStatus) {
  if let err = spam_engine_get_last_error(handle) {
    fail("load failed: \(String(cString: err))")
  }
  fail("load failed without error")
}

if spam_engine_is_loaded(handle) != 1 {
  fail("handle should be loaded after load")
}

if !spy.sawLoadLine {
  fail("the engine's '[spam_engine] loaded backend=' line never reached the log callback")
}
if !spy.sawNativeLine {
  fail("no ggml/llama line reached the log callback as DEBUG")
}

// The runtime record is runtime evidence, read through the same Swift import
// the app uses (TASK-505 L). Under SPAM_ENGINE_NO_GPU the reason must be
// requested_cpu; on the Metal path a CI sandbox may fall back, so only the
// record's own consistency is asserted there.
var runtime = spam_engine_runtime_info_t()
if spam_engine_runtime_info(handle, &runtime) != 1 {
  fail("runtime_info should succeed on a loaded handle")
}
let backend = withUnsafeBytes(of: &runtime.backend) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
let fallback = withUnsafeBytes(of: &runtime.fallback) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
if (backend == "cpu") != (fallback != "none") {
  fail("backend '\(backend)' disagrees with fallback '\(fallback)'")
}
if ProcessInfo.processInfo.environment["SPAM_ENGINE_NO_GPU"] != nil && fallback != "requested_cpu" {
  fail("SPAM_ENGINE_NO_GPU set but fallback reads '\(fallback)'")
}
if runtime.max_tokens <= 0 || runtime.sequences_embedded != 0 || runtime.sequences_truncated != 0 {
  fail("runtime_info after load: cap=\(runtime.max_tokens) embedded=\(runtime.sequences_embedded) truncated=\(runtime.sequences_truncated)")
}

let classifyStatus = "Hi team, just sharing tomorrow's meeting agenda.".withCString { text in
  "Alice".withCString { sender in
    "alice@example.com".withCString { email in
      spam_engine_classify(handle, text, sender, email, "ensemble", &result)
    }
  }
}
if !statusOK(classifyStatus) {
  if let err = spam_engine_get_last_error(handle) {
    fail("classify failed: \(String(cString: err))")
  }
  fail("classify failed without error")
}

let scoreSum = result.scores.marketing
  + result.scores.regular
  + result.scores.spam
if abs(scoreSum - 1.0) > 0.001 {
  fail("scores should sum to ~1 (got \(scoreSum))")
}

let unloadStatus = spam_engine_unload(handle)
if !statusOK(unloadStatus) {
  fail("unload failed")
}

if spam_engine_is_loaded(handle) != 0 {
  fail("handle should be unloaded after unload")
}
runtime.max_tokens = -1
if spam_engine_runtime_info(handle, &runtime) != 0 || runtime.max_tokens != -1 {
  fail("runtime_info on an unloaded handle must fail and leave out untouched")
}

let postUnloadStatus = "BUY VIAGRA NOW".withCString { text in
  spam_engine_classify(handle, text, nil, nil, "ensemble", &result)
}
if statusOK(postUnloadStatus) {
  fail("classify after unload should fail")
}

print("[PASS] Swift C API smoke")
