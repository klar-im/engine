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

if !FileManager.default.fileExists(atPath: "\(modelPath)/gguf/encoder-q4_k_m.gguf") {
  print("[SKIP] Swift C API smoke: model assets not found")
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
  scores: spam_engine_scores_t(gibberish: 0, marketing: 0, regular: 0, spam: 0),
  decided_by: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
  ftrl_score: -1
)

let preLoadStatus = "BUY VIAGRA NOW".withCString { text in
  spam_engine_classify(handle, text, nil, nil, "ensemble", &result)
}
if statusOK(preLoadStatus) {
  fail("classify before load should fail")
}

let loadStatus = modelPath.withCString { modelPathCString in
  spam_engine_load(handle, modelPathCString, 0.001, nil)
}
if !statusOK(loadStatus) {
  if let err = spam_engine_get_last_error(handle) {
    fail("load failed: \(String(cString: err))")
  }
  fail("load failed without error")
}

if spam_engine_is_loaded(handle) != 1 {
  fail("handle should be loaded after load")
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

let scoreSum = result.scores.gibberish
  + result.scores.marketing
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

let postUnloadStatus = "BUY VIAGRA NOW".withCString { text in
  spam_engine_classify(handle, text, nil, nil, "ensemble", &result)
}
if statusOK(postUnloadStatus) {
  fail("classify after unload should fail")
}

print("[PASS] Swift C API smoke")
