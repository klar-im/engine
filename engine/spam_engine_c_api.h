#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct spam_engine_handle spam_engine_handle_t;

typedef enum spam_engine_status {
  SPAM_ENGINE_STATUS_OK = 0,
  SPAM_ENGINE_STATUS_INVALID_ARGUMENT = 1,
  SPAM_ENGINE_STATUS_RUNTIME_ERROR = 2,
} spam_engine_status_t;

typedef struct spam_engine_scores {
  float gibberish;
  float marketing;
  float regular;
  float spam;
} spam_engine_scores_t;

// `label`/`confidence` are the engine's DELIVERY DECISION — not the 4-class
// argmax. `label` is only ever spam or regular: the decision layer folds the
// neural classes into junk-vs-deliver (gibberish/marketing → deliver=regular
// unless spam-like — see decision_from_scores), and `confidence` is that
// decision's confidence (e.g. 1 - P(spam)), NOT scores[label]. `scores` holds
// the 4-class prediction; take its argmax for the predicted class (which CAN be
// marketing/gibberish, unlike label). A "show me the classifier" UI should
// display argmax(scores); a "should this be junked" caller uses label.
//
// ENSEMBLE NOTE (TASK-219): in mode="ensemble", FTRL is folded ESCALATE-ONLY —
// `scores.spam` = max(neural, w*ftrl + (1-w)*neural), i.e. FTRL can only RAISE
// the spam side (catch personalized spam), never lower it. So scores.spam == raw
// neural whenever FTRL was not more suspicious than the neural head (the common
// day-0 case); it is the blended value only when FTRL escalated (decided_by then
// = "ftrl+neural"). gibberish/marketing/regular stay raw neural, so the four
// values are NOT a normalized softmax and do not sum to 1. That spam side is what
// feeds spam_engine_decide. In mode="neural" (or cold FTRL) `scores` is the pure
// neural softmax and `ftrl_score` is -1.
typedef struct spam_engine_result {
  int label;             // decision: spam or regular only (never marketing/gibberish)
  float confidence;      // confidence in the DECISION (not scores[label])
  spam_engine_scores_t scores;  // 4-class; scores.spam is ensemble-blended (see note)
  char decided_by[32];  // "ftrl", "neural", "ftrl+neural", etc.
  float ftrl_score;     // FTRL P(spam), -1 if FTRL not available
} spam_engine_result_t;

// Canonical name for a result label (0=gibberish, 1=marketing, 2=regular,
// 3=spam, else "unknown"). Returns a static string literal — never free it.
const char* spam_engine_label_name(int label);

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
} spam_engine_auth_features_t;

// All structural (non-content) signals the engine extracts during
// classify_rfc822's single parse (TASK-173). Bundled into one optional out-param
// rather than one-per-signal so adding the Nth signal (e.g. TASK-170's
// reputation-gated rescue) is a new field here, not a new call-site parameter.
typedef struct spam_engine_parsed_signals {
  spam_engine_thread_features_t thread;
  spam_engine_auth_features_t   auth;
} spam_engine_parsed_signals_t;

// Thread-safety: functions serialize access per handle for classify/load/unload/error state.
// Do not call spam_engine_destroy concurrently with other handle operations.
//
// LIFETIME CONTRACT (read this):
// Every handle returned by spam_engine_create MUST be destroyed before the
// process exits. The Metal backend (libggml-metal) registers a static
// destructor that walks the global device's residency set and asserts if
// any Metal buffers are still alive — including buffers owned by an
// undestroyed engine handle. Leaving a handle alive at exit produces:
//
//   GGML_ASSERT([rsets->data count] == 0)
//   "you haven't deallocated all Metal resources before exiting"
//
// Mitigations callers MUST apply:
//   * C++ tests / binaries: wrap the handle in RAII or destroy it in a
//     try/catch before returning from main(). Never call exit() with a
//     live handle.
//   * Python ctypes scripts: wrap classify/embed loops in try/finally and
//     call spam_engine_destroy in the finally block. Do NOT use
//     os._exit() to "skip" finalizers — that hides bugs and leaks.
//   * Swift / Apple Mail extension: `static let shared` singleton deinit
//     does NOT run at process exit. Register an `atexit()` hook on first
//     use that calls a public `shutdown()` which destroys the handle.
//     See SpamEngineClient.installAtexitHook for the canonical pattern.
spam_engine_handle_t* spam_engine_create(void);
void spam_engine_destroy(spam_engine_handle_t* handle);

// Load the engine. gguf_model_path: NULL or empty = model_path + "/gguf/encoder-q4_k_m.gguf".
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

// Load with an explicit GGUF encoder path (overrides the default derived from model_path).
spam_engine_status_t spam_engine_load_ggml(
    spam_engine_handle_t* handle,
    const char* model_path,
    const char* gguf_model_path,
    float learning_rate,
    const char* ftrl_path);
spam_engine_status_t spam_engine_unload(spam_engine_handle_t* handle);
int spam_engine_is_loaded(const spam_engine_handle_t* handle);

// Embedding dimension (float count) of the loaded model, or 0 if the handle is
// NULL or not loaded. FIXED for the lifetime of the loaded model, so callers
// size the buffers for spam_engine_embed_rfc822 / spam_engine_embed_text from
// this value ONCE after load and reuse the buffer per message — there is no
// per-call sizing dance.
int spam_engine_n_embd(const spam_engine_handle_t* handle);

// `mode` is REQUIRED (no silent default — TASK-219). One of:
//   "ensemble" — neural head + FTRL P(spam) blended into the spam side (the
//                recommended production mode). FTRL only contributes once warm;
//                cold/absent FTRL falls back to pure neural.
//   "neural"   — neural head only; FTRL never consulted (ftrl_score = -1).
//   "ftrl"     — FTRL only; neural skipped (diagnostic / A-B).
// NULL, empty, or an unknown value returns SPAM_ENGINE_STATUS_INVALID_ARGUMENT.
//
// Example:
//   spam_engine_result_t r;
//   spam_engine_classify(h, "hello", NULL, NULL, "ensemble", &r);
spam_engine_status_t spam_engine_classify(
    spam_engine_handle_t* handle,
    const char* text,
    const char* sender_name,
    const char* sender_email,
    const char* mode,
    spam_engine_result_t* out_result);

// Extract CLS embeddings for raw RFC822 bytes via the canonical pipeline:
// preprocess + build_input_text(transcript, customer_info) + encode. The
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
//   or NULL. Filled with the embedding of the wrapped plain body if non-NULL
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

// Extract a CLS embedding for a free-text input (e.g. synthetic gibberish
// samples that don't have an RFC822 envelope). Wraps via build_input_text
// with the supplied sender metadata so the result is in the same canonical
// shape `embed_rfc822` produces — the head sees one and only one input
// distribution regardless of source.
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

// out_signals: OPTIONAL. When non-NULL, filled with the structural signals
// (thread + sender-auth) extracted during the same GMime parse this call already
// does (TASK-173), so the caller doesn't re-parse the message to get them.
// Zero-initialised first; pass NULL to skip. On any failure status it is left
// zeroed (safe "no signals" default).
//
// `mode` is REQUIRED (see spam_engine_classify): "ensemble" | "neural" | "ftrl".
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

// Free a string returned by spam_engine_extract_body.
void spam_engine_free_string(char* str);

// Structural conversation-thread signals (uses GMime, no engine handle needed).
// Used by the Mail extension as a soft ham bias when an inbound message
// looks like a reply (presence of In-Reply-To / References, longer
// References chain). Phase 2 (Message-ID DB) reuses self_message_id and
// first_reference for bypass-resistant lookups.
// spam_engine_thread_features_t is defined above (near the result struct) so it
// can also be filled by spam_engine_classify_rfc822's optional out-param.
//
// Buffer sizes are generous for real-world Message-IDs (RFC 5322 has no hard
// limit but production IDs are typically <128 chars). Over-long values are
// stored as the empty string (treated as absent).
//
// Extract structural thread features from RFC822 data. Returns 0 on success,
// non-zero on parser failure. Even on parser failure, out_features is
// zero-initialised so callers can treat "no features" as a safe default.
int spam_engine_extract_thread_features(
    const char* raw_email,
    size_t raw_email_len,
    spam_engine_thread_features_t* out_features);

// Sender-authentication features parsed from the topmost Authentication-Results
// header. dkim_signing_domain is the cryptographically-asserted DKIM signing
// org-domain (header.d/.i) — empty if no dkim=pass. dmarc_aligned is 1 when
// dmarc=pass AND the signing org-domain equals the From org-domain. See
// TASK-122; the Swift SenderAuthClassifier turns a free-hosting signer into a
// soft spam offset. spam_engine_auth_features_t is defined above (near the
// result struct) so it can also be filled by classify_rfc822's optional out-param.
//
// Extract sender-authentication features from RFC822 data. Returns 0 on
// success, non-zero on parser failure. out_features is zero-initialised even on
// failure so callers can treat "no features" as a safe default (no offset).
int spam_engine_extract_auth_features(
    const char* raw_email,
    size_t raw_email_len,
    spam_engine_auth_features_t* out_features);

// Newline-delimited list of the distinct eTLD+1 domains of every http(s) URL in
// the body (TASK-201 link reputation; uses GMime, no engine handle needed). The
// caller frees the result with spam_engine_free_string. Returns "" (empty, still
// allocated) when the body has no URLs, or NULL on parse failure / OOM. A
// consumer splits on '\n' and matches each domain against a bundled blocklist.
char* spam_engine_extract_url_domains(const char* raw_email, size_t raw_email_len);

// ── Structural decision layer (TASK-179) ────────────────────────────────────
// Folds the soft structural offsets onto the model's spam-side confidence and
// applies the filtering-profile threshold, returning the SAME verdict the Apple
// extension's ClassificationService produces. Pure arithmetic — no engine
// handle, no model, no parse. Lets the postfix milter / Stalwart plugin / CLI
// reach an identical decision instead of shipping the engine's raw gate.
//
// The engine-derived inputs (thread headers, DKIM signer) come from
// spam_engine_extract_*; the caller-state inputs (Message-ID DB hit,
// send-counts) come from the consumer's local store — pass 0 when it has none
// (the milter), which simply means those ham-ward offsets don't fire.

typedef enum spam_engine_profile {
  SPAM_ENGINE_PROFILE_STANDARD = 0,
  SPAM_ENGINE_PROFILE_CAUTIOUS = 1,
  SPAM_ENGINE_PROFILE_LEARNING = 2,  // forces the cautious threshold
} spam_engine_profile_t;

typedef struct spam_engine_decision_input {
  spam_engine_scores_t scores;   // 4-class softmax (from classify)
  const char* ml_label;          // model's spam-side DECISION: "spam" or "regular"
                                 // (not a raw argmax; == the engine's binary label)
  double ml_confidence;          // model confidence, used on the non-spam keep path
  // Engine-derived (from the parsed message):
  int has_in_reply_to;           // 0 or 1
  int references_count;          // 0..N
  const char* dkim_signing_org_domain;  // eTLD+1; NULL/"" if none
  int signer_throwaway;          // 0 or 1
  int display_impersonation;     // 0 or 1 — From display impersonates a brand (TASK-214)
  // Caller-state (local DBs); pass 0 if unavailable:
  int phase2_match;              // Message-ID DB hit (0 or 1)
  int exact_send_count;          // user's outbound count to this exact address
  int domain_send_count;         // ...to this domain
  int profile;                   // spam_engine_profile_t
} spam_engine_decision_input_t;

typedef struct spam_engine_decision_result {
  char label[16];                // final label, NUL-terminated
  double confidence;
  double adjusted_spam_side;     // spam-side after the signed fold (clamped 0..1)
  int train_ml;                  // 0 on a header-only (offset) condemn, else 1
  // 1 if a spam-WARD structural offset fired (free-host / throwaway DKIM signer
  // today; URL reputation later). An independent strong signal a consumer can
  // require as corroboration before a destructive REJECT/bounce — so no single
  // scorer's blind spot can bounce legitimate mail.
  int condemn_offset_fired;
} spam_engine_decision_result_t;

// Fill the engine-derived fields of *din from a classification's scores and
// parsed signals: copies scores, computes ml_label/ml_confidence (the model's
// spam-side decision from the scores, matching the engine and Swift, not a raw
// argmax -- TASK-251 C5), and maps the thread/auth signal fields. Leaves the caller-state
// fields (phase2_match, exact/domain_send_count, profile) untouched; the caller
// owns those. No-op if any pointer is NULL.
//
// The single place this fold is assembled, shared by every consumer of the engine
// (milter, /demo addon, classify_full) so a new signal can't be silently dropped
// on one surface (TASK-231). din->dkim_signing_org_domain points into *signals,
// which must outlive the subsequent spam_engine_decide() call.
void spam_engine_decision_input_from_signals(
    spam_engine_decision_input_t* din,
    const spam_engine_scores_t* scores,
    const spam_engine_parsed_signals_t* signals);

// Returns SPAM_ENGINE_STATUS_OK and fills *out, or
// SPAM_ENGINE_STATUS_INVALID_ARGUMENT if in/out is NULL.
int spam_engine_decide(const spam_engine_decision_input_t* in,
                       spam_engine_decision_result_t* out);

// ── Single self-evident pipeline entrypoint (TASK-219) ──────────────────────
// Runs the WHOLE verdict in one call: FTRL P(spam) → neural head → ensemble
// blend → structural decision-layer fold. Replaces the error-prone two-call
// dance (spam_engine_classify_rfc822 + spam_engine_decide) that let a caller
// silently drop the structural layer (the /demo did exactly that pre-TASK-218).
// Reports each stage so the pipeline is inspectable rather than hidden.
//
// Caller-state offsets (Message-ID DB hit, send-counts, profile) come from the
// consumer's local store; pass NULL for `caller_state` (the milter / demo have
// none) and those ham-ward offsets simply don't fire. Engine-derived offsets
// (thread headers, DKIM signer) are extracted from the same parse and folded
// automatically. `mode` is REQUIRED (see spam_engine_classify).
typedef struct spam_engine_caller_state {
  int phase2_match;        // Message-ID DB hit (0/1)
  int exact_send_count;    // user's outbound count to this exact address
  int domain_send_count;   // ...to this domain
  int profile;             // spam_engine_profile_t
} spam_engine_caller_state_t;

typedef struct spam_engine_full_result {
  // Stage 1 — FTRL pre-filter
  float ftrl_score;                  // P(spam), -1 if FTRL unavailable/cold
  // Stage 2 — neural head (raw 4-class; neural_spam == scores.spam here)
  spam_engine_scores_t neural_scores;
  // Stage 2.5 — ensemble: the spam side actually folded into the decision layer
  // (== neural P(spam) when FTRL didn't contribute).
  float ensemble_spam;
  char decided_by[32];               // "ftrl+neural" | "neural" | "ftrl"
  // Stage 3 — structural decision-layer fold: the FINAL verdict.
  spam_engine_decision_result_t decision;
  // Engine-derived signals that fed stage 3 (for display / audit).
  spam_engine_parsed_signals_t signals;
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

#ifdef __cplusplus
}
#endif
