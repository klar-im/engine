# Klar Engine

A self-hostable spam-detection **engine** built on a multilingual transformer
(XLM-RoBERTa) classifier. It scores mail on-device — no data leaves your server.

The engine is the core; *milters* embed it. This repo ships the engine plus a
reference Postfix milter built on it; other integrations (e.g. a Stalwart milter)
are separate consumers of the same C ABI.

This repo is the **open-core** of [Klar](https://klar.im). It is AGPLv3 (see
`LICENSE`).

## What's here

- `engine/` — the C++ inference core: GGML/llama.cpp encoder + a 4-label
  classifier head, with a stable C ABI (`engine/spam_engine_c_api.h`) for
  embedding in other languages.
- `postfix/` — the reference milter: a Postfix-facing daemon (config, policy,
  event store, health endpoint, CLI) plus a Docker E2E stack (Postfix + Dovecot),
  showing how to embed the engine.

## Models are separate from the code

The engine ships **no weights**. You load a model directory at runtime. Two options:

| | Production model (default) | Demo model |
|---|---|---|
| Source | [`icosha/spam-xlmr-v1`](https://huggingface.co/icosha/spam-xlmr-v1) (public, **CC-BY-NC-4.0**) + Klar S3/CDN (see `LICENSE-MODEL.md`) | [`icosha/klar-spam-demo`](https://huggingface.co/icosha/klar-spam-demo) (public, AGPLv3) |
| Quality | the shipping classifier | toy, proves the pipeline, ~0.79 binary acc |
| Use | real filtering / self-hosting at quality (free for non-commercial use) | a lighter smoke-test download |

```bash
make setup                                   # C/C++ deps (llama.cpp, gmime, xxhash, json)
make import                                  # Python deps + pull/convert the model
make build
./engine/build/spam_classifier ./engine/model   # classify a built-in sample
```

`import` installs the Python conversion deps (`engine/requirements-demo.txt`)
and needs `convert_hf_to_gguf.py` from llama.cpp (on PATH after `make setup` on
macOS). Use a virtualenv if your distro marks the system Python externally-managed.

`make import` defaults to the production model (`icosha/spam-xlmr-v1`), converts
the encoder to GGUF, and extracts the classifier head into `engine/model/`. Point
`MODEL=` at any XLM-RoBERTa spam model (e.g. `MODEL=icosha/klar-spam-demo` for the
lighter toy) to convert your own.

## Embed it

The engine is a C ABI you link into a client or server. Load a model once, then
classify:

- `engine/spam_engine_c_api.h` — `classify(text, sender_name, sender_email, mode)`
  for plain text (short/social messages included), or `classify_rfc822(...)` for a
  full `.eml`, which handles the MIME parse, multipart part-selection, and
  sender-auth extraction. From Swift, C#, Rust, etc. it is a P/Invoke or FFI call
  over the same ABI.
- `engine/node/` ([`@klar/engine`](engine/node/README.md)) — a Node.js N-API
  binding: `classifyText` / `classifyEml` for Electron/Node clients.
- `engine/spam_engine_training_c_api.h` — on-device learning: `train_rfc822` /
  `add_training_sample` / `train_incremental` learn from user corrections ("mark
  as spam") locally. Nothing leaves the machine; centralized/flywheel retraining
  is separate and not in this repo.

`postfix/` is a full worked example: the same C ABI embedded in a Postfix milter
(`postfix/scripts/train_from_imap.py` shows the training loop over an IMAP folder).

## Licence

- **Code:** AGPLv3 (`LICENSE`). The network-use copyleft means if you offer this
  as a service, your modifications must be shared. Commercial licences without the
  AGPL obligations are available — contact hello@klar.im.
- **Models:** separately licensed (`LICENSE-MODEL.md`). The demo model is AGPLv3
  (runs this repo out of the box); the production model is CC-BY-NC-4.0 (free for
  non-commercial use with attribution, paid licence for commercial use).
