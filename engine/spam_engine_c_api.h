#pragma once

// The Klar engine's C ABI, in two sections:
//
//   Product ABI      what a shipping consumer calls: the Mail extension and
//                    Klar Plus (Swift), the milter, spamd, the demo addon.
//                    A verdict is ONE call, spam_engine_classify_full.
//   Measurement ABI  at the end of this file: what only model-lab and the
//                    engine's tests call, to measure the pipeline piecewise.
//
// `make engine/shape` lists the callers of every function here.

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ════ Product ABI ═══════════════════════════════════════════════════════════

typedef struct spam_engine_handle spam_engine_handle_t;

typedef enum spam_engine_status {
  SPAM_ENGINE_STATUS_OK = 0,
  SPAM_ENGINE_STATUS_INVALID_ARGUMENT = 1,
  SPAM_ENGINE_STATUS_RUNTIME_ERROR = 2,
} spam_engine_status_t;

// The three classes of the product taxonomy. A legacy 4-label artifact
// (public-v0) also scores "gibberish"; the engine adds that probability to
// `spam`, the side it always counted toward, so this struct never carries it.
typedef struct spam_engine_scores {
  float marketing;
  float regular;
  float spam;
} spam_engine_scores_t;

// `label`/`confidence` are the engine's DELIVERY DECISION — not the semantic
// argmax. `label` is only ever spam or regular: the decision layer folds the
// neural classes into junk-vs-deliver (marketing → deliver=regular unless
// spam-like — see decision_from_scores), and `confidence` is that decision's
// confidence (e.g. 1 - P(spam)), NOT scores[label]. `scores` holds the stable
// three-slot semantic envelope; a loaded model may have fewer physical rows, in
// which case unavailable semantics are zero. Take its argmax for the predicted
// class (which CAN be marketing, unlike label). A "show me the classifier" UI
// should display argmax(scores); a "should this be junked" caller uses label.
//
// ENSEMBLE NOTE (TASK-219): in mode="ensemble", FTRL is folded ESCALATE-ONLY —
// `scores.spam` = max(neural, w*ftrl + (1-w)*neural), i.e. FTRL can only RAISE
// the spam side (catch personalized spam), never lower it. So scores.spam == raw
// neural whenever FTRL was not more suspicious than the neural head (the common
// day-0 case); it is the blended value only when FTRL escalated (decided_by then
// = "ftrl+neural"). marketing/regular stay raw neural, so the three
// values are NOT a normalized softmax and do not sum to 1. That spam side is what
// feeds the decision fold. In mode="neural" (or cold FTRL) `scores` is the pure
// neural distribution in that stable envelope and `ftrl_score` is -1.
typedef struct spam_engine_result {
  int label;             // decision: 3=spam or 2=regular only (1=marketing and
                         // 0=gibberish complete the label numbering, never set)
  float confidence;      // confidence in the DECISION (not scores[label])
  spam_engine_scores_t scores;  // stable semantic envelope; see note
  char decided_by[32];  // "ftrl", "neural", "ftrl+neural", etc.
  float ftrl_score;     // FTRL P(spam), -1 if FTRL not available
} spam_engine_result_t;

// Structural conversation-thread signals (see extract function below for the
// full contract). Defined here because classify_rfc822 fills these from its own
// parse via the spam_engine_parsed_signals out-param (TASK-173).
typedef struct spam_engine_thread_features {
  int  has_in_reply_to;        // 0 or 1
  int  references_count;       // 0..N (every <id> in References:)
  char in_reply_to[256];       // NUL-terminated; empty if absent or too long
  char first_reference[256];   // first <id> from References:; empty if absent
  char self_message_id[256];   // own Message-ID:; empty if absent or too long
} spam_engine_thread_features_t;

// Sender-authentication signals (see extract function below for the full
// contract).
typedef struct spam_engine_auth_features {
  char dkim_signing_domain[256];  // NUL-terminated; empty if absent or too long
  char from_org_domain[256];      // NUL-terminated From: org-domain
  int  dmarc_aligned;             // 0 or 1
  char dkim_signing_fqdn[256];    // full signer FQDN, pre-org-reduction
  int  signer_throwaway;          // 0 or 1 — throwaway-shaped signer (TASK-178)
  int  display_impersonation;     // 0 or 1 — From display claims a brand the
                                  // From org-domain isn't (TASK-214)
  int  kb_brand_dmarc_pass;       // 0 or 1 — From org-domain is a curated KB brand
                                  // sending domain, receiver-verified dmarc=pass,
                                  // not a shared platform (TASK-337/334 rescue)
  // APPENDED (TASK-440), never inserted: this struct crosses the C ABI.
  int  dmarc_pass;                // 0 or 1: the receiving MTA's Authentication-
                                  // Results say dmarc=pass, for any sender. Looser than
                                  // dmarc_aligned: a message aligned via SPF
                                  // rather than DKIM passes here and not there.
} spam_engine_auth_features_t;

// Structural body-URL signals (TASK-257). Only raw_ip_url is surfaced: its two
// siblings (url_shortener, shared_bare_cdn) were ablated and NOT wired (see the
// block comment in decision_layer.h).
typedef struct spam_engine_url_features {
  int raw_ip_url;                 // 0 or 1: a body link's host is a bare IP literal
} spam_engine_url_features_t;

// Structural BODY signals that are not about links.
typedef struct spam_engine_body_features {
  int gtube_test;                // 0 or 1: the GTUBE test string is present
  // APPENDED after gtube_test, which was the last member (TASK-440).
  int callback_shape;            // 0 or 1: billing language + a callback number
                                 // + no link anywhere. See callback_shape.h.
  // APPENDED after callback_shape (TASK-460), never inserted.
  int no_contact_instruction;    // 0 or 1: an instruction NOT to check with your
                                 // bank ("ne contactez pas votre agence",
                                 // "restez en ligne"). The bank-advisor scam's
                                 // second message. See no_contact_shape.h.
} spam_engine_body_features_t;

// Bounded attachment facts. These describe decoded bytes/container structure;
// they are not an antivirus verdict. `context` is returned separately by
// spam_engine_extract_attachment_context so this fixed ABI struct stays small.
//
// ZERO IS NOT "NO ATTACHMENT RISK": nothing here is populated unless the MIME
// parse ran, and it runs only when the loaded artifact declares
// attachment_context=true, or (classify_full only) the caller sets
// caller_state.attachment_risk_enabled. Through spam_engine_classify_rfc822 a
// public-v0 artifact therefore always reports zeros, because public-v0
// deliberately does not pay for attachment/ZIP inspection (TASK-347). A caller
// that wants the facts without a model uses
// spam_engine_extract_attachment_context, which always parses.
typedef struct spam_engine_attachment_features {
  int total_count;
  uint64_t total_bytes;
  int archive_member_count;
  int disguised_executable;
  int archive_disguised_executable;
  int dangerous_type;
  int archive_dangerous_type;
  int macro_document;
  int encrypted_archive;
  int truncated;
  int parse_failed;
} spam_engine_attachment_features_t;

// All structural (non-content) signals the engine extracts during
// classify_rfc822's single parse (TASK-173). Bundled into one optional out-param
// rather than one-per-signal so adding the Nth signal (e.g. TASK-170's
// reputation-gated rescue) is a new field here, not a new call-site parameter.
typedef struct spam_engine_parsed_signals {
  spam_engine_thread_features_t thread;
  spam_engine_auth_features_t   auth;
  spam_engine_url_features_t    url;
  spam_engine_body_features_t   body;   // appended (C ABI: never insert)
  spam_engine_attachment_features_t attachment; // appended (C ABI)
} spam_engine_parsed_signals_t;

// Thread-safety: functions serialize access per handle for classify/load/unload/error state.
// Do not call spam_engine_destroy concurrently with other handle operations.
//
// LIFETIME CONTRACT (read this):
// Every handle returned by spam_engine_create MUST be destroyed while the
// process is still running — before exit() is called, not merely before the
// process is gone. Destroying one from an exit-time handler is the trap:
// handlers run in reverse registration order, and ggml's backend plugins are
// dlopen'd lazily on the FIRST load, so a handler registered at startup runs
// after ggml has already destroyed its own statics. Freeing a llama_context
// then jumps through a dangling function pointer and the process dies with
// SIGBUS inside llama_context::~llama_context. That is the KlarPlus
// night-training crash of 2026-08-18.
//
// Mitigations callers MUST apply:
//   * C++ tests / binaries: wrap the handle in RAII or destroy it in a
//     try/catch before returning from main(). Never call exit() with a
//     live handle.
//   * Python ctypes scripts: wrap classify/embed loops in try/finally and
//     call spam_engine_destroy in the finally block. Do NOT use
//     os._exit() to "skip" finalizers — that hides bugs and leaks.
//   * Swift: `static let shared` singleton deinit does NOT run at process
//     exit, so an `atexit()` hook is a reasonable safety net — but register it
//     AFTER the first successful spam_engine_load, never on first use of the
//     singleton, or it inherits the ordering bug above. See
//     SpamEngineClient.installAtexitHook. The hook stays a net: tear down on
//     the real quit path (applicationWillTerminate, or explicitly before
//     NSApp.terminate in a headless run).
//
// A caller that gets this wrong now leaks the model at exit instead of
// crashing — ggml_encoder.h installs its own guard, and
// GGML_METAL_NO_RESIDENCY=1 means an undestroyed handle no longer trips
// libggml-metal's residency-set assert
// (GGML_ASSERT([rsets->data count] == 0)). Neither is licence to skip the
// contract: both are backstops, and a leak at exit still hides the bug.
// engine/tests/atexit_teardown_test.cpp holds the line.
spam_engine_handle_t* spam_engine_create(void);
void spam_engine_destroy(spam_engine_handle_t* handle);

// Load the engine. gguf_model_path: NULL or empty = model_path + "/gguf/" + the
// artifact's classifier_config.json `gguf_encoder_file` (default encoder-q4_k_m.gguf).
// ftrl_path: NULL or empty to disable FTRL pre-filter.
//
// Encoder token cap: not exposed as a parameter; runtime override via the env
// var SPAM_ENGINE_MAX_TOKENS (see EngineConfig::encoder_max_tokens). Avoids
// growing every load signature for a knob we tune from the shell.
spam_engine_status_t spam_engine_load(
    spam_engine_handle_t* handle,
    const char* model_path,
    float learning_rate,
    const char* ftrl_path);
spam_engine_status_t spam_engine_unload(spam_engine_handle_t* handle);

// Embedding dimension (float count) of the loaded model, or 0 if the handle is
// NULL or not loaded. FIXED for the lifetime of the loaded model, so callers
// size the buffers for spam_engine_embed_rfc822 / spam_engine_embed_text from
// this value ONCE after load and reuse the buffer per message — there is no
// per-call sizing dance.
int spam_engine_n_embd(const spam_engine_handle_t* handle);

// ── Runtime info (TASK-505 L) ───────────────────────────────────────────────
// The backend the encoder ACTUALLY runs on after load, and why it is on CPU
// when it is. Runtime evidence, not the absence of SPAM_ENGINE_NO_GPU: the
// engine falls back Metal->CPU silently, and until this a Mac on the fallback
// classified 5-6x slower per email with nothing to say so.
//
// Same shape as spam_engine_model_info: one fixed-size struct, one call, so a
// support mail, a log line, the benchmark and the apps read one record. The
// size is reported by spam_engine_get_abi_sizes (`runtime_info`).
typedef struct spam_engine_runtime_info {
  // ggml's registry name, lower-cased, "MTL" spelled out as "metal". THE one
  // spelling: apps store it verbatim rather than keeping words of their own.
  char backend[16];
  // ggml_backend_dev_description of the device in use ("Apple M1 Pro").
  char device[64];
  // Why it is on CPU, by name, the same way: "none" (on the GPU it asked
  // for, so this is also the "uses GPU" answer), "requested_cpu"
  // (SPAM_ENGINE_NO_GPU was set), "no_gpu_device" (no GPU-typed device
  // registered), "context_init_failed" (a GPU refused a context: sandbox,
  // VM). Spelled once, in engine_runtime.h's encoder_fallback_name.
  char fallback[24];
  // The tail of ggml's own log at the moment a GPU context init failed;
  // empty for every other fallback value.
  char fallback_detail[256];
  // The cap in force after any SPAM_ENGINE_MAX_TOKENS override.
  int max_tokens;
  // Since load, every sequence the encoder saw: classify (one or two per
  // message: plain and html are embedded separately), embed_* and training
  // alike. `truncated` lost tokens to the cap; `failed` threw before an
  // embedding existed and is counted in neither of the other two. The
  // per-message figure is `encoder_truncated_sequences` on the full result.
  uint64_t sequences_embedded;
  uint64_t sequences_truncated;
  uint64_t sequences_failed;
} spam_engine_runtime_info_t;

// Returns 1 and fills *out; returns 0 with out untouched for a NULL handle,
// a NULL out, or an unloaded handle (same contract as spam_engine_model_info).
int spam_engine_runtime_info(const spam_engine_handle_t* handle,
                             spam_engine_runtime_info_t* out);

// ── Log callback ────────────────────────────────────────────────────────────
// Where the engine's own lines ("[spam_engine] loaded backend=metal ...",
// the env-override notices) and ggml/llama's native output go. Process-global
// like ggml_log_set, because the lines written before any handle exists
// (backend registration) belong to no handle. NULL restores stderr, which is
// also the default, so a CLI or milter that never calls this reads what it
// always read. `text` arrives as written, newline included; ggml emits
// partial lines. The engine's own lines are INFO or WARN; ggml's are DEBUG
// (its loader prints about 600 lines per model load, measured on gen3-v6)
// except its WARN and ERROR; a continuation fragment keeps its line's level.
// The callback runs on the thread that logged, outside the engine's lock, and
// a NULL install does not wait for a delivery in flight on another thread:
// `user` must outlive every load or classify that can still log. A caller
// that detaches must have joined those first.
typedef enum spam_engine_log_level {
  SPAM_ENGINE_LOG_DEBUG = 1,
  SPAM_ENGINE_LOG_INFO = 2,
  SPAM_ENGINE_LOG_WARN = 3,
  SPAM_ENGINE_LOG_ERROR = 4,
} spam_engine_log_level_t;

typedef void (*spam_engine_log_fn)(int level, const char* text, void* user);

void spam_engine_set_log_callback(spam_engine_log_fn fn, void* user);

// What the loaded artifact says it is, so a caller can name the model behind a
// verdict. Fixed-size buffers, so there is nothing to free.
//
// `uuid` is read from a MANIFEST.json in the model directory, which
// download-models.sh installs after verifying every byte. It is EMPTY for a
// hand-assembled directory, and empty means "unknown", never "fine". The
// remaining fields come from classifier_config.json and are always populated for
// a model the engine could load.
//
// Answering "which model is this host running?" previously meant hashing files
// on the box against every historical UUID on S3. That is how the public demo
// went a month serving an artifact that was never released.
//
// Returns 1 on success, 0 for a NULL/unloaded handle or NULL out (out untouched).
typedef struct {
  char uuid[64];
  char source_model[128];
  int hidden_size;
  int num_labels;
  int raw_input;          // 0 = the public-v0 legacy envelope, 1 = raw text
  int structural_markers; // 1 when the artifact opts into marker enrichment
  double spam_side_calibration_knot; // 0 = undeclared (identity). Otherwise the
                          // point on this artifact's spam side that the product's
                          // Standard gate is mapped onto. spam_engine_classify_full
                          // applies it; reported so a caller can see that it did.
  int attachment_context; // 1 when the artifact opts into bounded attachment
                          // context prepended to the email. APPENDED: C ABI.
} spam_engine_model_info_t;

int spam_engine_model_info(const spam_engine_handle_t* handle,
                           spam_engine_model_info_t* out);

// THE `mode` ARGUMENT of every classify call is REQUIRED (no silent default —
// TASK-219). One of:
//   "ensemble" — neural head + FTRL P(spam) blended into the spam side (the
//                recommended production mode). FTRL only contributes once warm;
//                cold/absent FTRL falls back to pure neural.
//   "neural"   — neural head only; FTRL never consulted (ftrl_score = -1).
//   "ftrl"     — FTRL only; neural skipped (diagnostic / A-B).
// NULL, empty, or an unknown value returns SPAM_ENGINE_STATUS_INVALID_ARGUMENT.

// Extract CLS embeddings for raw RFC822 bytes via the canonical pipeline:
// preprocess + model-declared input calibration + encode. The
// returned embeddings are bit-identical to what classify_rfc822 would feed
// the head — so this is the function training callers (e.g. the Python
// retrain script) MUST use to keep training and inference distributions
// aligned. See engine/PARITY_PLAN.md.
//
// Returns up to TWO embeddings per call: one for the plain-text body and
// one for the html body. Both bodies are present in multipart/alternative
// messages, only one in single-part messages — train_rfc822 internally
// trains on both when present, so training callers should mirror that by
// passing both output buffers and reading back whichever ones got filled.
// Inference callers that only want one embedding can pass NULL for the
// other buffer (or use either of the two filled ones).
//
// sender_name / sender_email: caller-supplied sender metadata (matches the
//   classify_rfc822 parameters); pass NULL or empty to fall back to the
//   parsed From header.
// out_plain_embedding: caller-allocated buffer of at least out_capacity floats,
//   or NULL. Filled with the embedding of the model-calibrated plain body if non-NULL
//   and the message has a plain body part.
// out_plain_filled: set to 1 if out_plain_embedding was populated, 0 if
//   the body part is absent or out_plain_embedding was NULL.
// out_html_embedding / out_html_filled: same for the html body part.
// out_capacity: capacity (float count) of EACH provided output buffer. Both
//   buffers share the same embedding dimension. Always set to spam_engine_n_embd().
//   If out_capacity < n_embd the call writes nothing, sets *out_n_embd to the
//   required dimension, and returns SPAM_ENGINE_STATUS_INVALID_ARGUMENT — a
//   partial embedding is meaningless, so an undersized buffer is a hard error,
//   not a truncation hint.
// out_n_embd: set to the model's embedding dimension (so a caller that guessed
//   too small can resize), regardless of whether a buffer was filled.
spam_engine_status_t spam_engine_embed_rfc822(
    spam_engine_handle_t* handle,
    const char* raw_email,
    size_t raw_email_len,
    const char* sender_name,
    const char* sender_email,
    float* out_plain_embedding,
    int* out_plain_filled,
    float* out_html_embedding,
    int* out_html_filled,
    size_t out_capacity,
    int* out_n_embd);

// out_signals: OPTIONAL. When non-NULL, filled with the structural signals
// (thread + sender-auth) extracted during the same GMime parse this call already
// does (TASK-173), so the caller doesn't re-parse the message to get them.
// Zero-initialised first; pass NULL to skip. On any failure status it is left
// zeroed (safe "no signals" default).
//
// `mode` is REQUIRED (see the note above): "ensemble" | "neural" | "ftrl".
spam_engine_status_t spam_engine_classify_rfc822(
    spam_engine_handle_t* handle,
    const char* raw_email,
    size_t raw_email_len,
    const char* sender_name,
    const char* sender_email,
    const char* mode,
    spam_engine_result_t* out_result,
    spam_engine_parsed_signals_t* out_signals);

// Flywheel (TASK-134): extract a PORTABLE, state-independent contribution bag
// from an RFC822 message — the derived `{bucket -> signed weight}` representation
// the FTRL head trains on, bucketed identically on every device. This is the only
// thing the flywheel ever uploads; never raw text. It is computed only — nothing
// in the engine transmits it. `hash_key != 0` keys the buckets (HMAC-style).
//
// Output is written into caller-allocated parallel arrays out_buckets/out_weights
// of `capacity` entries; *out_count is set to the TOTAL feature count. If
// *out_count > capacity the result was truncated — re-call with a larger buffer
// (a few hundred buckets is ample for one email). sender_name/sender_email may be
// NULL. Returns OK even when truncated; check *out_count.
spam_engine_status_t spam_engine_extract_contribution(
    spam_engine_handle_t* handle,
    const char* raw_rfc822,
    size_t raw_rfc822_len,
    const char* sender_name,
    const char* sender_email,
    uint64_t hash_key,
    uint32_t* out_buckets,
    float* out_weights,
    size_t capacity,
    size_t* out_count);

const char* spam_engine_get_last_error(const spam_engine_handle_t* handle);

// Email body extraction (uses GMime, no engine handle needed).
typedef struct spam_engine_email_body {
  char* html_body;     // Raw HTML content (caller must free with spam_engine_free_string)
  char* plain_body;    // Raw plain text content (caller must free)
  char* subject;       // Decoded subject (caller must free)
  char* from;          // Decoded from header (caller must free)
  char* text_preview;  // Plain text for preview: plain_body if available, else HTML-to-text (caller must free)
  char* date;          // RFC2822 date header value (caller must free)
} spam_engine_email_body_t;

// Extract email body parts from RFC822 data. Returns 0 on success.
// All non-null string fields in out_body must be freed with spam_engine_free_string.
int spam_engine_extract_body(
    const char* raw_email,
    size_t raw_email_len,
    spam_engine_email_body_t* out_body);

// Build the version-1 replay RFC822 representation used when a Klar Plus
// corpus source exceeds 10 MiB. The call follows the standard size-dance:
// `out_buf` may be NULL with capacity 0; `*out_len` always receives the total
// byte length. Attachment payloads are removed, while original headers,
// inline text/HTML (and therefore URLs), and attachment MIME metadata remain.
spam_engine_status_t spam_engine_make_replay_rfc822(
    const char* raw_email,
    size_t raw_email_len,
    char* out_buf,
    size_t capacity,
    size_t* out_len);

// Free a string returned by spam_engine_extract_body.
void spam_engine_free_string(char* str);

// Newline-delimited list of the distinct eTLD+1 domains of every http(s) URL in
// the body (TASK-201 link reputation; uses GMime, no engine handle needed). The
// caller frees the result with spam_engine_free_string. Returns "" (empty, still
// allocated) when the body has no URLs, or NULL on parse failure / OOM. A
// consumer splits on '\n' and matches each domain against a bundled blocklist.
char* spam_engine_extract_url_domains(const char* raw_email, size_t raw_email_len);

// ── ABI self-description (TASK-394) ─────────────────────────────────────────
// Every struct below crosses the C ABI into hand-written FFI mirrors (Python
// ctypes, the Node addon, Swift). A mirror that drifts does not fail loudly: the
// engine memsets or writes past the end of the caller's shorter buffer, which
// corrupts the heap and, worse, makes the engine read caller-state fields out of
// garbage — a nonzero read of a condemn-capable flag silently changes verdicts.
// That happened (three fields added across TASK-113/388/391 with no mirror
// update). So the engine reports its own sizes and mirrors assert against them.
//
// `field_count` is every uint32_t after itself (sizes and offsets alike), so
// the engine derives it from sizeof, a Python mirror from its own field list,
// and the Node addon from the header it compiled against: a field added on one
// side alone goes red. The C test pins the literal, which is its job.
typedef struct spam_engine_abi_sizes {
  uint32_t field_count;        // number of uint32_t fields that follow
  uint32_t parsed_signals;
  uint32_t decision_result;
  uint32_t caller_state;
  uint32_t full_result;
  uint32_t result;
  uint32_t scores;
  uint32_t attachment_features;
  // sizeof() alone cannot catch REORDERING of same-width fields, and this API
  // has already had fields reordered once. caller_state is the struct where that
  // would be worst: the engine READS it out of a caller-supplied buffer, so
  // swapping two ints there does not corrupt memory — it silently feeds the
  // wrong value into a condemn-capable flag and changes verdicts. So its field
  // offsets are reported too. The other structs the engine only WRITES, where a
  // size mismatch is the failure that matters and is already covered.
  uint32_t caller_state_phase2_match;
  uint32_t caller_state_exact_send_count;
  uint32_t caller_state_domain_send_count;
  uint32_t caller_state_profile;
  uint32_t caller_state_connect_ip_blocked;
  uint32_t caller_state_attachment_risk_enabled;
  uint32_t runtime_info;  // appended (TASK-505 L); counted in field_count
  uint32_t caller_state_replied_to_own_sent;  // appended 2026-09-24
  uint32_t caller_state_header_ip_blocked;    // appended (TASK-540)
} spam_engine_abi_sizes_t;

// Fills *out with sizeof() for each ABI struct, as this build sees them.
void spam_engine_get_abi_sizes(spam_engine_abi_sizes_t* out);

// ── Structural decision layer (TASK-179) ────────────────────────────────────
// spam_engine_classify_full folds the soft structural offsets onto the model's
// spam-side confidence and applies the filtering-profile threshold, returning
// the SAME verdict the Apple extension's ClassificationService produces, so the
// milter, spamd and the demo reach an identical decision instead of shipping
// the engine's raw gate. The fold itself is internal (decision_input.h).

typedef enum spam_engine_profile {
  SPAM_ENGINE_PROFILE_STANDARD = 0,
  SPAM_ENGINE_PROFILE_CAUTIOUS = 1,
  SPAM_ENGINE_PROFILE_LEARNING = 2,  // forces the cautious threshold
  SPAM_ENGINE_PROFILE_AGGRESSIVE = 3,  // the product's third profile (0.95); appended,
                                       // so the three values above keep their ABI
} spam_engine_profile_t;

typedef struct spam_engine_decision_result {
  char label[16];                // final label, NUL-terminated
  double confidence;
  double adjusted_spam_side;     // spam-side after the signed fold (clamped 0..1)
  int train_ml;                  // 0 on a header-only (offset) condemn, else 1
  // 1 if an AUTHORITATIVE spam-WARD structural offset fired. An independent
  // strong signal a consumer can require as corroboration before a destructive
  // REJECT/bounce, so no single scorer's blind spot bounces legit mail. The 0.30
  // raw-IP corroborator (TASK-257) fires but deliberately does NOT set this: it
  // must never authorize a bounce on its own.
  //
  // The authoritative set is a NAMED ALLOWLIST in the fold (decision_input.h) --
  // sender_auth, display_impersonation, gtube_test, connect_ip_drop -- not a
  // magnitude test. It was a magnitude test until TASK-347 added a 0.99
  // experimental offset that may junk but must never authorize a bounce, which
  // an ">= the standard gate" rule cannot express. So a NEW authoritative offset
  // has to be added to that list by hand; a large magnitude alone no longer
  // grants the power. The list is locked by a decide test.
  int condemn_offset_fired;
  // Which structural offsets actually fired, comma-separated, in the fold's audit
  // order: "<classifier_id>[!]", where the "!" marks the one credited with
  // flipping the decision (at most one). Empty when the model decided alone.
  //
  // A STRING rather than a struct array because this crosses the C ABI with no
  // allocation: consumers log it, stamp it in a header, or store it, none of
  // which need the numbers. It exists so a consumer records what the fold DID
  // instead of re-deriving it from the inputs and drifting (TASK-388). Truncated
  // (never unterminated) if the ids somehow exceed the buffer.
  char fired_offsets[192];
  // The spam side AFTER per-artifact calibration and BEFORE any offset: exactly
  // what the fold starts from. APPENDED, never inserted.
  //
  // Without it a tool cannot attribute a verdict to a layer. `ensemble_spam` on
  // the full result is the UNCALIBRATED score, and decide() calibrates before
  // adding offsets, so on any artifact with a non-zero knot the whole
  // ensemble-to-adjusted delta reads as structural. Observed on the Gen-3 v5
  // candidate: 0.4459 became 0.4971 with fired_offsets empty, which
  // model-lab/scripts/score_email.py reported as the offsets doing something.
  // public-v0 has a zero knot, which is why it went unnoticed.
  //
  // Equal to the calibrated ensemble when no offset fires, so
  // `adjusted_spam_side - calibrated_spam_side` is the structural contribution
  // and nothing else. Consumers that do not calibrate see it equal to the input.
  double calibrated_spam_side;
} spam_engine_decision_result_t;

// ── Single self-evident pipeline entrypoint (TASK-219) ──────────────────────
// Runs the WHOLE verdict in one call: FTRL P(spam) → neural head → ensemble
// blend → structural decision-layer fold. The only verdict path: the two-call
// dance it replaced (classify_rfc822 + a hand-assembled decide) let a caller
// silently drop the structural layer (the /demo did exactly that pre-TASK-218)
// and later fold a calibrated model on the raw scale, so the decide entry
// points left this header (TASK-540). Reports each stage so the pipeline is
// inspectable rather than hidden.
//
// Caller-state offsets (Message-ID DB hit, send-counts, profile) come from the
// consumer's local store; pass NULL for `caller_state` when there is none and
// those offsets simply don't fire. Engine-derived offsets (thread headers, DKIM
// signer) are extracted from the same parse and folded automatically. `mode` is
// REQUIRED (see the `mode` note above).
typedef struct spam_engine_caller_state {
  int phase2_match;        // Message-ID DB hit (0/1)
  int exact_send_count;    // user's outbound count to this exact address
  int domain_send_count;   // ...to this domain
  int profile;             // spam_engine_profile_t
  int connect_ip_blocked;  // the IP that CONNECTED to this MTA is in a Spamhaus
                           // DROP netblock (0/1, TASK-113). A server-side
                           // consumer only: set it from an address you OBSERVED,
                           // never from a Received header: below the accepting
                           // MTA's own line those are attacker-written, and this
                           // offset is condemn-capable. See ip_blocklist.h.
  int attachment_risk_enabled; // default-off deterministic attachment experiment
  int replied_to_own_sent; // the Phase-2 hit was on the user's OWN OUTBOUND
                           // Message-ID, not merely a parent we classified as
                           // ham. A strict subset of phase2_match, and the only
                           // one allowed to veto the display-impersonation
                           // condemn: phase2_match is also set by a parent WE
                           // classified as ham, which an attacker manufactures
                           // by sending one benign message and replying to it.
                           // APPENDED, like every field here: the struct crosses
                           // the C ABI and an insert shifts every offset after it.
  int header_ip_blocked;   // the same DROP hit on an origin recovered from the
                           // Received chain behind a TRUSTED relay (0/1,
                           // TASK-387). Its own field with a weaker offset, so
                           // header evidence can never be laundered into
                           // connect_ip_blocked's condemn. APPENDED (TASK-540).
} spam_engine_caller_state_t;

typedef struct spam_engine_full_result {
  // Stage 1 — FTRL pre-filter
  float ftrl_score;                  // P(spam), -1 if FTRL unavailable/cold
  // Stage 2 — neural head (raw semantic envelope; neural_spam == scores.spam)
  spam_engine_scores_t neural_scores;
  // Stage 2.5 — ensemble: the spam side actually folded into the decision layer
  // (== neural P(spam) when FTRL didn't contribute).
  float ensemble_spam;
  char decided_by[32];               // "ftrl+neural" | "neural" | "ftrl"
  // Stage 3 — structural decision-layer fold: the FINAL verdict.
  spam_engine_decision_result_t decision;
  // Engine-derived signals that fed stage 3 (for display / audit).
  spam_engine_parsed_signals_t signals;
  // How many of this message's encoder sequences the token cap clipped (0, 1
  // or 2: plain and html embed separately; 0 when the head did not run).
  // Appended (C ABI: never insert); a consumer built against the older struct
  // reads everything above it unchanged. TASK-505 L.
  uint32_t encoder_truncated_sequences;
} spam_engine_full_result_t;

// Returns SPAM_ENGINE_STATUS_OK and fills *out (zeroed first), or an error
// status (INVALID_ARGUMENT on null handle/raw/out or bad mode). On any error
// *out is left zeroed (safe "deliver, no offsets" default).
spam_engine_status_t spam_engine_classify_full(
    spam_engine_handle_t* handle,
    const char* raw_email,
    size_t raw_email_len,
    const char* sender_name,
    const char* sender_email,
    const char* mode,
    const spam_engine_caller_state_t* caller_state,
    spam_engine_full_result_t* out);

// ════ Measurement ABI ═══════════════════════════════════════════════════════
// Called only by model-lab and the engine's tests: the pipeline taken apart so
// each stage can be measured on its own, at parse speed where no model is
// needed. No shipping consumer calls these; a verdict is classify_full.

// Classify free text: the model's scores and its own spam/regular call, with
// no parse and no structural fold. `mode` as in the note above.
spam_engine_status_t spam_engine_classify(
    spam_engine_handle_t* handle,
    const char* text,
    const char* sender_name,
    const char* sender_email,
    const char* mode,
    spam_engine_result_t* out_result);

// Load with an explicit GGUF encoder path (overrides the default derived from model_path).
spam_engine_status_t spam_engine_load_ggml(
    spam_engine_handle_t* handle,
    const char* model_path,
    const char* gguf_model_path,
    float learning_rate,
    const char* ftrl_path);
int spam_engine_is_loaded(const spam_engine_handle_t* handle);

// Extract a CLS embedding for a free-text input (e.g. synthetic samples that
// don't have an RFC822 envelope). Applies the model-declared input format with
// the supplied sender metadata so the result has the same calibrated shape
// `embed_rfc822` produces.
//
// Use this for training data that isn't email-shaped. For real emails use
// spam_engine_embed_rfc822 so the GMime preprocessing pipeline runs.
//
// out_embedding: caller-allocated buffer of at least out_capacity floats.
// out_capacity: its capacity (float count); set to spam_engine_n_embd(). If
//   out_capacity < n_embd the call writes nothing, sets *out_n_embd to the
//   required dimension, and returns SPAM_ENGINE_STATUS_INVALID_ARGUMENT.
// out_n_embd: set to the model's embedding dimension.
spam_engine_status_t spam_engine_embed_text(
    spam_engine_handle_t* handle,
    const char* text,
    const char* sender_name,
    const char* sender_email,
    float* out_embedding,
    size_t out_capacity,
    int* out_n_embd);

// Flywheel (TASK-135): the PII-scrubbed body text that extract_contribution
// hashes — the representative body part with quoted/forwarded recipient-routing
// headers redacted and inline data: URIs stripped (GMime has already dropped
// attachments and split real headers). Exposed for auditing the scrub at scale
// (offline PII harness) — the contribution bag is computed from
// exactly this text, so anything absent here is absent from the upload.
//
// The scrubbed text is written (NOT null-terminated) into out_buf of `capacity`
// bytes; *out_len is set to the TOTAL byte length. If *out_len > capacity the
// result was truncated — re-call with a larger buffer. out_buf may be NULL to
// size first (capacity 0). Returns OK even when truncated; check *out_len.
spam_engine_status_t spam_engine_scrub_rfc822(
    spam_engine_handle_t* handle,
    const char* raw_rfc822,
    size_t raw_rfc822_len,
    char* out_buf,
    size_t capacity,
    size_t* out_len);

// HTML -> plain text (no engine handle needed): strips tags and DROPS the
// content of <script>/<style> elements.
//
// Exposed so offline pipelines (training-set construction, LLM labelling) get
// EXACTLY the text the engine feeds the model. A second implementation in
// Python did not drop <style> content, so raw CSS entered training data as if
// it were prose — one rule with two implementations drifts, so there is one.
//
// The text is written (NOT null-terminated) into out_buf of `capacity` bytes;
// *out_len is set to the TOTAL byte length. If *out_len > capacity the result
// was truncated — re-call with a larger buffer. out_buf may be NULL to size
// first (capacity 0). Returns OK even when truncated; check *out_len.
spam_engine_status_t spam_engine_html_to_text(
    const char* html,
    size_t html_len,
    char* out_buf,
    size_t capacity,
    size_t* out_len);

// Structural conversation-thread signals (uses GMime, no engine handle needed):
// In-Reply-To / References presence and chain length, plus the Message-IDs a
// Phase 2 (Message-ID DB) lookup reuses. classify_full reports the same struct
// from its own parse in `signals.thread`.
//
// Buffer sizes are generous for real-world Message-IDs (RFC 5322 has no hard
// limit but production IDs are typically <128 chars). Over-long values are
// stored as the empty string (treated as absent).
//
// Returns 0 on success, non-zero on parser failure. Even on parser failure,
// out_features is zero-initialised so callers can treat "no features" as a
// safe default.
int spam_engine_extract_thread_features(
    const char* raw_email,
    size_t raw_email_len,
    spam_engine_thread_features_t* out_features);

// Sender-authentication features parsed from the receiving MTA's
// Authentication-Results (its run of headers, as edge_authentication_results in
// email_preprocessor.cpp reads them). dkim_signing_domain is the cryptographically-asserted DKIM signing
// org-domain (header.d/.i) — empty if no dkim=pass. dmarc_aligned is 1 when
// dmarc=pass AND the signing org-domain equals the From org-domain (TASK-122).
// classify_full reports the same struct from its own parse in `signals.auth`.
//
// Returns 0 on success, non-zero on parser failure. out_features is
// zero-initialised even on failure so callers can treat "no features" as a
// safe default (no offset).
int spam_engine_extract_auth_features(
    const char* raw_email,
    size_t raw_email_len,
    spam_engine_auth_features_t* out_features);

// Extract the structural BODY features (GTUBE, callback shape, no-contact
// instruction) from RFC822 data. No model handle is needed, which is the whole
// point: the parity harnesses that decide whether a body predicate may ship have
// to run it over tens of thousands of messages, and going through classify_full
// costs a full inference per message (~85 ms, so ~37 minutes on the ham panels).
// A check that slow is a check nobody runs, and the repo has the scars to prove
// it. The sibling of spam_engine_extract_auth_features, with the same contract:
// returns 0 on success, non-zero on parser failure, and out_features is
// zero-initialised even on failure so "no features" is a safe default.
int spam_engine_extract_body_features(
    const char* raw_email,
    size_t raw_email_len,
    spam_engine_body_features_t* out_features);

// Parse RFC822 attachments and return the exact bounded context an artifact
// declaring attachment_context=true receives. No model handle is needed. The
// text is written without a terminator; size-first/truncation contract matches
// spam_engine_html_to_text. `out_features` is optional and zeroed first.
spam_engine_status_t spam_engine_extract_attachment_context(
    const char* raw_email,
    size_t raw_email_len,
    spam_engine_attachment_features_t* out_features,
    char* out_buf,
    size_t capacity,
    size_t* out_len);

#ifdef __cplusplus
}
#endif
