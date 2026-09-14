# Engine Architecture

## Scope

This document covers the C++ inference and lightweight online-learning engine under `/engine`.
It does not cover offline experimentation tooling or host-side integration code.

## Purpose

The engine provides a local spam classification core that:

- Loads a quantized GGUF encoder via llama.cpp/ggml.
- Runs a model-declared classifier head. The public model has four labels
  (`gibberish`, `marketing`, `regular`, `spam`); the successor release candidate
  uses the compact `marketing`, `regular`, `spam` layout. The engine maps both
  through `classifier_config.json` rather than positional assumptions.
- Combines a fast statistical pre-filter (FTRL) with a neural head.
- Optionally updates the classifier head weights from user feedback (online learning), with L2 anchoring to the offline-trained baseline to prevent catastrophic forgetting.

The base transformer encoder stays frozen in all current C++ executables.

## High-Level Components

### 0) Stable Engine API (`spam_engine`)

- Public header: [spam_engine.h](spam_engine.h)
- Implementation: [spam_engine.cpp](spam_engine.cpp)
- CMake target: shared library `spam_engine`

Primary API surface:

- `load(config)`
- `classify(...)` / `classify_rfc822(...)` / `classify_transcript(...)`
- `embed(text)` / `embed_batch(texts, progress_callback)`
- `train(...)` / `train_embedding(...)`
- `save(...)`

The C ABI in [spam_engine_c_api.h](spam_engine_c_api.h) is the integration boundary for Swift-side consumption (and any other FFI).

### 1) Model Assets (`/engine/model`)

- `gguf/encoder-q4_k_m.gguf`: quantized XLM-RoBERTa encoder in GGUF format (the only encoder asset).
- `classifier_dense_weight.bin`, `classifier_dense_bias.bin`, `classifier_out_proj_weight.bin`, `classifier_out_proj_bias.bin`: standalone classifier head weights, byte-extracted from the HuggingFace model via `engine/export_classifier_weights.py`. Cos=1.000 equivalent to HF PyTorch at inference time.
- `classifier_config.json`: head metadata (hidden size, num labels, required
  `label_map`, model-specific `input_format`, `structural_markers`, and
  `attachment_context`). `raw`
  plus markers is used by the successor candidate;
  absent/`legacy_wrapped` preserves the public-v0 `User (email)` envelope. The
  public baseline and FTRL keep unmarked input. The immutable historical Gen 3
  object is the one named raw-plus-markers compatibility exception because it
  predates the fields; all new artifacts declare them. `attachment_context`
  defaults false and is enabled only for a head trained on the bounded
  summary/email/details template produced by `attachment_features.cpp`.
- `ftrl_baseline.bin`: optional pre-trained FTRL weights for the statistical pre-filter.

### 2) Inference Backbone

- `GgmlEncoder` ([ggml_encoder.h](ggml_encoder.h)) wraps llama.cpp's `llama_model` + `llama_context`. Uses CLS pooling, configurable token cap (`EngineConfig::encoder_max_tokens`, default 128: the label-flipping signal sits in the subject and the first few sentences, self-attention is O(n²), and 128 vs 512 measured 3.6x faster on a 720-token message with the same FPR on three corpora), GPU offload (Metal) by default with automatic CPU fallback.
- Tokenization is the GGUF's built-in vocab — no separate sentencepiece model.

### 3) Classifier Head

- `TrainableClassifierHead` ([trainable_classifier.h](trainable_classifier.h)):
  - Forward: dense (`hidden -> hidden`) + tanh, output projection (`hidden -> declared labels`), softmax.
  - Backward: cross-entropy loss + Adam optimizer.
  - **L2 anchoring**: each parameter update includes a `2 * l2_lambda * (w - w_orig)` penalty pulling weights back toward the offline-trained baseline. Original weights are stored at construction.
  - **Gradient clipping**: global L2 norm clipped to `max_grad_norm` (default 1.0) before the Adam step.
  - Save / load updated head weights via `classifier_*.bin`.

### 4) FTRL Pre-filter

- `FtrlClassifier` ([ftrl_classifier.h](ftrl_classifier.h)) is a fast statistical scorer using hashed n-gram + URL/exclamation features.
- Used as an escalate-only ensemble (TASK-219): the neural model always runs, and the FTRL score can only raise the spam side (`spam' = max(neural.spam, w * ftrl + (1 - w) * neural.spam)`, weight `ftrl_ensemble_weight`), never exonerate. A cold FTRL (fewer than `ftrl_min_learns` observed examples) is ignored.

### 5) Executables

- `spam_classifier` ([main.cpp](main.cpp)) — minimal inference CLI/demo using `spam_engine`.
- `spam_benchmark` ([benchmark.cpp](benchmark.cpp)) — encoder timing harness.

## Runtime Data Flow

1. Input text (or RFC822 / transcript) is calibrated through
   `SpamEngine::calibrate_input()`. The neural representation comes from the
   loaded head's `classifier_config.json`; the FTRL representation remains the
   established legacy envelope because its frozen baseline was trained on that
   shape. Public v0 does no attachment work. An attachment-context artifact or
   explicitly opted-in deterministic-rule experiment enables RFC822 attachment
   decoding, capped before inspection; ZIP reading is in-memory, one level deep,
   and bounded by file, aggregate-byte and entry limits. No member is written or
   executed. Parsing remains independent from policy: an attachment-only message
   with no extractable sender, subject or body still returns its facts so the
   artifact-controlled representation and caller-controlled rule can each apply.
2. (Optional) A warm FTRL scores the legacy-envelope representation from a hashed feature vector; the score is blended in after step 5, escalate-only (it can raise the spam side, never lower it).
3. llama.cpp tokenizes via the GGUF's built-in vocab (BOS + tokens + EOS, truncated to `encoder_max_tokens`).
4. `GgmlEncoder` runs `llama_encode` and extracts the model-declared CLS-pooled
   embedding (1024 dimensions for public-v0, 768 for the e5 release candidate).
5. `TrainableClassifierHead` computes logits → softmax over the artifact's declared labels, then maps them into the stable semantic score vector.
6. Decision mapping produces the final class.
7. Optional path: user feedback is calibrated through the same model-specific
   neural representation used for inference, then triggers a single Adam step
   on the head with L2 anchoring + gradient clipping. The corresponding
   legacy-envelope text trains FTRL, and `save()` persists both learners.

## Build and Dependency Architecture

- Build system: CMake ([CMakeLists.txt](CMakeLists.txt)).
- Setup script: [scripts/setup.sh](scripts/setup.sh).
  - **macOS**: installs `gmime`, `libarchive`, `xxhash`, `llama.cpp`, `nlohmann-json` via Homebrew. The engine links the system libarchive ABI and uses the Homebrew package for headers.
  - **Linux**: installs system deps including `libarchive-dev` via `apt`, then downloads the pre-built llama.cpp release tarball (`b8660`) plus headers from the source archive into `engine/deps/llama-install`, generates `llama.pc` and `ggml.pc` pkg-config stubs, and points cmake at the install via `-DLLAMA_INSTALL=...`.
- Main runtime dependencies:
  - llama.cpp / ggml (encoder + tokenization)
  - GMime 3 (RFC822 MIME parsing)
  - nlohmann/json (head config parsing)
  - xxhash (header-only, FTRL feature hashing)

## Boundaries

- Engine is the serving/training core.
- Offline evaluation and optional fine-tuning live outside the engine. The shipped classifier head is extracted from a HuggingFace model via `engine/export_classifier_weights.py`; offline head retraining is part of the private training pipeline, not this repo.
- Host integrations consume the engine via the C ABI in `spam_engine_c_api.h`.
- The structural decision layer (`decision_layer.h`) folds non-content signals onto the model score: thread-reply headers, sender-auth (`Authentication-Results` DKIM/DMARC parse), and the brand-impersonation / reputation signals (`brand_kb.h`, `brand_names.h`, `brand_reputation.h`). The brand and reputation tables ship as code plus committed data snapshots (Tranco-derived reputation + a curated brand KB); the data-generation pipeline is maintained out-of-tree, so the snapshots are regenerated upstream, not from this repo.

## Current Constraints

- Decision thresholds and learning hyperparameters are exposed via `EngineConfig` but not yet config-file-driven.
- Online learning keeps the encoder frozen. Each accepted correction applies
  one bounded Adam head step; distinct plain and HTML representations form one
  averaged batch. FTRL learns once from the plain or sole representation.
- `save(<explicit path>)` creates a self-contained snapshot. Klar Plus stages it
  in a unique version directory, verifies it, and atomically moves the current
  symlink while retaining rollback. Calling `save()` without an explicit path
  still overwrites the loaded directory and is not the app deployment path.

## Trust boundary: the sender-auth layer reads, it does not verify

The sender-auth signals (`extract_auth_features`) are PARSED from the message's
own `Authentication-Results` header; the engine does not itself verify DKIM or
DMARC. Two consequences follow, and they are safe or unsafe depending on where the
engine runs:

- With NO `Authentication-Results` header, `DmarcVerdict` is `Unknown`, and the
  brand layer exonerates a sender that IS on a KB-canonical domain (it assumes the
  MTA would have caught a forgery). So a direct From-forgery of a canonical brand
  domain passes the brand layer on an un-authenticated message.
- The topmost `Authentication-Results` header is trusted. An attacker who can
  inject headers (i.e. the message reaches the engine before a trusted MTA has
  stamped and sanitized AR) can supply a forged `dkim=pass; dmarc=pass`.

This is FINE behind iCloud Mail or Gmail (the Apple Mail / companion deployments):
the provider has already authenticated and rewritten `Authentication-Results`
before the engine ever sees the message, and strips client-supplied ones. It is
NOT fine for the Postfix milter on its own: the milter must run AFTER an
authenticating filter (e.g. OpenDMARC/OpenDKIM stamping a trusted AR and removing
inbound forgeries), or the engine's auth signals must be treated as advisory. See
`postfix/README.md` for the milter ordering requirement.
