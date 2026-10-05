# Klar Engine

## Klar for Stalwart

Klar replaces Stalwart's built-in spam filter with a multilingual transformer
classifier that runs on your own server: Stalwart hands each inbound message to
the `klar-milterd` milter, and a per-mailbox Sieve rule files on its verdict.

Install on Linux (x86_64 or arm64, systemd), from prebuilt release binaries:

```bash
curl -fsSL https://raw.githubusercontent.com/klar-im/engine/main/install.sh | sudo KLAR_ACCEPT_MODEL_LICENSE=1 sh
```

`KLAR_ACCEPT_MODEL_LICENSE=1` records that you accept the model's licence
(CC-BY-NC-4.0, `LICENSE-MODEL.md`); the installer downloads the model,
verified file by file, and starts the `klar-milterd` service. Then point
Stalwart at it with `stalwart-cli` admin credentials:

```bash
export STALWART_URL=http://127.0.0.1:8080 STALWART_USER=admin STALWART_PASSWORD=...
python3 /opt/klar/share/stalwart/scripts/apply.py --milter-host 127.0.0.1 --milter-port 8891
```

The full guide (shadow mode, per-mailbox filing, the container, sizing) is
[`stalwart/README.md`](stalwart/README.md). On Postfix, run the installer with
`KLAR_MTA=postfix` and follow [`postfix/README.md`](postfix/README.md).

## The engine

A self-hostable spam-detection engine built on a multilingual transformer
(XLM-RoBERTa) classifier. It scores mail on-device: no data leaves your server.

The engine is the core; milters embed it. This repo ships the engine, the
milter built on it (`postfix/`, one daemon for Postfix, Stalwart and any
libmilter MTA), and the Stalwart wiring (`stalwart/`: the objects that point
Stalwart at the milter, the Sieve that files on its verdict, a compose stack).

This repo is the open-core of [Klar](https://klar.im), licensed AGPLv3 (see
`LICENSE`).

## What's here

- `engine/` is the C++ inference core: a GGML/llama.cpp encoder plus a
  model-declared classifier head, with a stable C ABI
  (`engine/spam_engine_c_api.h`) for embedding in other languages.
- `postfix/` is the reference milter: a Postfix-facing daemon (config, policy,
  event store, health endpoint, CLI) plus a Docker end-to-end stack (Postfix
  and Dovecot) that shows how to embed the engine.
- `stalwart/` is the Stalwart wiring: config fragments, `apply.py` over
  `stalwart-cli`, the filing Sieve, a compose end-to-end stack.
- `install.sh` is the one-line installer for the release binaries.
- `AGENTS.md` is for an AI agent doing the install for you: what to check, what
  to run, and that the model licence stays your decision.

## Run it behind your mail server

![Your mail server hands the message to klar-milterd at DATA; the engine classifies it on the same box and answers with X-Klar headers; the server delivers and a rule files on the verdict. The milter keeps no message, only metadata in its event store.](postfix/docs/klar-milter.png)

The message never leaves your server: Klar reads it there and writes its
verdict into the headers. (The figure is an Excalidraw scene,
[`postfix/docs/klar-milter.excalidraw`](postfix/docs/klar-milter.excalidraw);
open it at excalidraw.com to edit it.)

- **Stalwart**: [`stalwart/README.md`](stalwart/README.md). Four objects
  applied through `stalwart-cli` (`stalwart/scripts/apply.py`, idempotent), a
  per-mailbox Sieve include, and a shadow mode that keeps Stalwart scoring
  beside Klar so you can compare the two on your own mail first.
- **Postfix**: [`postfix/README.md`](postfix/README.md). The same daemon with
  OpenDKIM and OpenDMARC ahead of it, a systemd unit, and a Docker end-to-end
  stack.
- **The binaries**: every release attaches `klar-milterd-<version>-linux-x86_64.tar.gz`
  and `-linux-arm64.tar.gz` (with `.sha256`), built by this repo's CI on
  glibc 2.35 (x86_64) and 2.39 (arm64) with every other library bundled and
  no weights. `install.sh`
  installs them; read it before piping it to a shell.
- **The image**: `ghcr.io/klar-im/klar-milterd` (linux/amd64 and linux/arm64),
  built from `postfix/docker/Dockerfile` with no weights; the container
  fetches the model into its volume on first start, only with
  `KLAR_ACCEPT_MODEL_LICENSE=1`.

## The model is separate from the code

The engine ships with no weights. You load a model directory at runtime. The
default is the production model, the same classifier the Klar apps ship,
pinned by `postfix/model/released-manifest.json` and fetched by
`fetch_model.sh` (today gen3-v6, Klar's fine-tune of the MIT-licensed
`intfloat/multilingual-e5-base` encoder, a 304 MB Q8_0 GGUF plus a three-class
head), distributed under CC-BY-NC-4.0 (free for non-commercial use with
attribution; commercial use needs a paid licence, see `LICENSE-MODEL.md`).

```bash
make setup                                   # C/C++ deps (llama.cpp, gmime, xxhash, json)
KLAR_ACCEPT_MODEL_LICENSE=1 make model       # fetch the production model, verified against the pinned manifest
make build
./engine/build/spam_classifier ./engine/model engine/tests/data/demo-samples/spam.en.eml   # prints: spam
```

`make model` downloads the seven files the manifest pins into `engine/model/`
and checks every one by digest; it refuses to start until
`KLAR_ACCEPT_MODEL_LICENSE=1` records that you accept `LICENSE-MODEL.md`. The
same script is what the milter container runs on first start.

To run your own classifier instead, `make import MODEL=<hf-repo>` converts any
XLM-RoBERTa spam model from Hugging Face (encoder to GGUF, head extracted). It
installs the Python conversion deps (`engine/requirements-import.txt`) and
needs `convert_hf_to_gguf.py` from llama.cpp (on PATH after `make setup` on
macOS); use a virtualenv if your distro marks the system Python
externally-managed. `MODEL` defaults to Klar's first public model,
`icosha/spam-xlmr-v1`, which is not the production model any more.

## Embed it

The engine is a C ABI you link into a client or server. Load a model once,
then classify:

- `engine/spam_engine_c_api.h`: `classify(text, sender_name, sender_email, mode)`
  for plain text (short and social messages included), or `classify_rfc822(...)`
  for a full `.eml`, which handles the MIME parse, multipart part selection, and
  sender-auth extraction. From Swift, C#, Rust, and similar languages it is a
  P/Invoke or FFI call over the same ABI.
- `engine/node/` ([`@klar/engine`](engine/node/README.md)): a Node.js N-API
  binding with `classifyText` and `classifyEml` for Electron and Node clients.
- `engine/spam_engine_training_c_api.h`: on-device learning. `train_rfc822`,
  `add_training_sample`, and `train_incremental` learn from user corrections
  (marking a message as spam) locally. Nothing leaves the machine; centralized
  or flywheel retraining is separate and not in this repo.

`postfix/` is a full worked example: the same C ABI embedded in a Postfix
milter. `postfix/scripts/train_from_imap.py` shows the training loop over an
IMAP folder.

## Licence

- Code: AGPLv3 (`LICENSE`). The network-use copyleft means that if you offer
  this as a service, your modifications must be shared. Commercial licences
  without the AGPL obligations are available; contact hello@klar.im.
- Model: separately licensed (`LICENSE-MODEL.md`) under CC-BY-NC-4.0: free for
  non-commercial use with attribution, paid licence for commercial use.
- Dependencies, and why each is compatible (libmilter's Sendmail License
  included): `THIRD_PARTY_LICENSES.md`.

## Contributing

Issues and pull requests are welcome; `CONTRIBUTING.md` explains how a change
travels through the mirror. Vulnerabilities go to security@klar.im, not the
tracker: `SECURITY.md`.
