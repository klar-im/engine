# @klar/engine

Native Node.js (N-API) addon that embeds the Klar spam-classification engine in
a Node process. It wraps the engine C API (`engine/spam_engine_c_api.h`), keeps
ONE model resident, and runs each classification on a libuv worker thread so the
event loop is never blocked. Concurrent calls serialize on the single engine
handle (which the engine already does internally).

## Build

The engine shared library must be built first, then the addon:

```sh
make engine/build              # builds libspam_engine_c_api (+ libspam_engine)
cd engine/node && npm install  # node-gyp builds the addon against it
```

## One model at a time, and how it changes

The model directory is resolved from `KLAR_ENGINE_MODEL` (default: `../model`)
and loaded lazily on the first classify. Every call may name a different one as
its last argument, and asking for a different directory **swaps** the resident
model: the old one is unloaded before the new one is read, so peak memory is one
encoder rather than two. That is not a nicety on the 2 GB RAM demo box, where
XLM-R-large is 407 MB.

Two consequences for callers:

- **A swap costs a full load**, hundreds of milliseconds against a repeat call's
  ~20. A host that mixes models should serialize them and admit no request for a
  second model while one is in flight against the first (klar.im's demo server
  does this with a one-slot admission queue in front of `classifyEml`).
- **Every result carries `model`**, the artifact that produced *that* verdict,
  read inside the addon while it still holds the load lock. Do not ask
  afterwards. `modelInfo()` answers about whatever is resident *now*, which after
  a swap is a different model, and it loads one to answer. Reading it separately
  is how klar.im spent a month attributing verdicts to a model it was not
  running.

**Rebuild the addon whenever `engine/spam_engine_c_api.h` changes.** `make
website/engine-addon` declares that dependency, so a plain `make
website/engine-addon` after an engine change does the right thing and is a no-op
otherwise.

## Why the addon refuses to load sometimes

`addon.cc` asserts its compiled `sizeof()` for every ABI struct against
`spam_engine_get_abi_sizes()` at module load, and throws rather than export
`classify` on a mismatch:

```text
klar_engine addon is stale: parsed_signals engine=1568 addon=1560.
Rebuild it with `make website/engine-addon`.
```

This addon is the FFI mirror most likely to go stale, because the `.node` is a
build artifact and nothing used to invalidate it when the header moved. A stale
one is not a small problem: the engine writes its *current* `parsed_signals`
into the worker's *older, shorter* member and straight through the two members
that follow it.

It happened. A `.node` built 2026-07-14, against a header that changed five
times between the 21st and the 30th, aborted the website's dev server on one
fixture (`spam.crypto.en.eml`): the overflow landed on the `std::vector` holding
URL domains, and the next `emplace_back` computed a capacity from smashed
pointers and threw `std::length_error`. Refusing to load is the good outcome,
and it degrades exactly like a missing addon, which consumers already handle.

Classification is also wrapped: an exception escaping `Execute()` would unwind
into a libuv callback and terminate the host process, since
`NAPI_DISABLE_CPP_EXCEPTIONS` means node-addon-api does not wrap it. It is
caught at the boundary and rejects the promise instead.

## Use

```js
import { classifyText, classifyEml } from '@klar/engine';

await classifyText('cheap pills, click now to claim');
// → { class: 'spam', confidence: 0.98, scores: { gibberish, marketing, regular, spam } }

await classifyEml(rawRfc822Buffer); // same shape, via the engine's MIME parse path

// A specific artifact. Swaps the resident model if it is not already loaded.
// DEFAULT_MODEL_PATH is where this host's own model lives, so alternatives can
// be found relative to it without restating KLAR_ENGINE_MODEL.
import path from 'node:path';
import { DEFAULT_MODEL_PATH } from '@klar/engine';

const uuid = '21bcd2ff-beaf-41d4-aa84-8083083d3554'; // installed under engine/models/
const alt = path.resolve(DEFAULT_MODEL_PATH, '..', 'models', uuid);
await classifyText('cheap pills', 'ensemble', false, alt);
```

All resolve to `{ class, confidence, scores, decidedBy, model }`, where `class`
is one of `gibberish | marketing | regular | spam | unknown`, `scores` holds the
per-class probabilities, and `model` names the artifact that produced it.

## Layout

- `addon.cc` — the N-API wrapper (one resident model, worker-thread classify).
- `binding.gyp` — links `libspam_engine_c_api` from the engine build.
- `index.js` / `index.d.ts` — the JS entry point + types.
