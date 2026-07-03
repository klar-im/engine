# @klar/engine

Native Node.js (N-API) addon that embeds the Klar spam-classification engine in
a Node process. It wraps the engine C API (`engine/spam_engine_c_api.h`), loads
the model once, and runs each classification on a libuv worker thread so the
event loop is never blocked. Concurrent calls serialize on the single engine
handle (which the engine already does internally).

## Build

The engine shared library must be built first, then the addon:

```sh
make engine/build              # builds libspam_engine_c_api (+ libspam_engine)
cd engine/node && npm install  # node-gyp builds the addon against it
```

The model directory is resolved from `KLAR_ENGINE_MODEL` (default: `../model`),
loaded lazily on the first classify.

## Use

```js
import { classifyText, classifyEml } from '@klar/engine';

await classifyText('cheap pills, click now to claim');
// → { class: 'spam', confidence: 0.98, scores: { gibberish, marketing, regular, spam } }

await classifyEml(rawRfc822Buffer); // same shape, via the engine's MIME parse path
```

Both resolve to `{ class, confidence, scores }`, where `class` is one of
`gibberish | marketing | regular | spam | unknown` and `scores` holds the
per-class probabilities.

## Layout

- `addon.cc` — the N-API wrapper (load-once, worker-thread classify).
- `binding.gyp` — links `libspam_engine_c_api` from the engine build.
- `index.js` / `index.d.ts` — the JS entry point + types.
