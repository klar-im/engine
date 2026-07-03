// JS loader for the Klar spam-engine N-API addon. Loads the compiled .node via
// createRequire so SvelteKit/Vite never tries to bundle it. The model is loaded
// once inside the addon on the first classify call; the path comes from
// KLAR_ENGINE_MODEL, defaulting to <repo>/engine/model.

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));

// node-gyp emits build/Release/klar_engine.node.
const addon = require(path.join(here, 'build', 'Release', 'klar_engine.node'));

// Model dir: KLAR_ENGINE_MODEL, else <repo>/engine/model (this file lives at
// <repo>/engine/node/index.js). Fixed at startup — the addon loads the model
// once on the first classify and ignores the path thereafter.
const MODEL_PATH = process.env.KLAR_ENGINE_MODEL || path.resolve(here, '..', 'model');

// mode selects the pipeline (ensemble|neural|ftrl); debug=true adds a `debug`
// object with the per-stage internals (decided_by, FTRL P(spam), ensemble spam).

/** Classify free text. Resolves to { class, confidence, scores, decidedBy }. */
export function classifyText(text, mode = 'ensemble', debug = false) {
	return addon.classify(String(text), false, MODEL_PATH, mode, debug);
}

/** Classify a raw RFC822 message (string or Buffer). Resolves to the same shape. */
export function classifyEml(buf, mode = 'ensemble', debug = false) {
	return addon.classify(buf, true, MODEL_PATH, mode, debug);
}
