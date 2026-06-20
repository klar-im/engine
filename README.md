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

| | Demo model | Production model |
|---|---|---|
| Source | [`icosha/klar-spam-demo`](https://huggingface.co/icosha/klar-spam-demo) (public) | Klar S3/CDN, separate **commercial** licence (see `LICENSE-MODEL.md`) |
| Quality | toy — proves the pipeline, ~0.79 binary acc | the shipping classifier |
| Use | clone-and-run out of the box | real filtering / self-hosting at quality |

```bash
make setup                                   # C/C++ deps (llama.cpp, gmime, xxhash, json)
make import-demo                             # Python deps + pull/convert the demo model
make build
./engine/build/spam_classifier ./engine/model   # classify a built-in sample
```

`import-demo` installs the Python conversion deps (`engine/requirements-demo.txt`)
and needs `convert_hf_to_gguf.py` from llama.cpp (on PATH after `make setup` on
macOS). Use a virtualenv if your distro marks the system Python externally-managed.

`make import-demo` downloads the demo model, converts the encoder to GGUF, and
extracts the classifier head into `engine/model/`. Point `MODEL=` at any
XLM-RoBERTa spam model to convert your own.

## Licence

- **Code:** AGPLv3 (`LICENSE`). The network-use copyleft means if you offer this
  as a service, your modifications must be shared. Commercial licences without the
  AGPL obligations are available — contact hello@klar.im.
- **Models:** separate and proprietary. The demo and production weights are both
  under the Klar Model License (`LICENSE-MODEL.md`) — the demo may be used freely
  to run this repo, but it is not open source.
