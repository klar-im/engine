// JS loader for the Klar spam-engine N-API addon. Loads the compiled .node via
// createRequire so SvelteKit/Vite never tries to bundle it. The model directory
// is per call: the addon keeps ONE model resident and swaps it when a different
// directory is asked for, so callers that only ever run one model pay nothing
// and the /demo model selector can run several without holding two at once.

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));

// node-gyp emits build/Release/klar_engine.node.
const addon = require(path.join(here, 'build', 'Release', 'klar_engine.node'));

/**
 * The model a caller gets when it names none: KLAR_ENGINE_MODEL, else
 * <repo>/engine/model (this file lives at <repo>/engine/node/index.js).
 * Exported so a host can offer alternatives relative to it without restating
 * the env var.
 */
export const DEFAULT_MODEL_PATH =
	process.env.KLAR_ENGINE_MODEL || path.resolve(here, '..', 'model');

// mode selects the pipeline (ensemble|neural|ftrl); debug=true adds a `debug`
// object with the per-stage internals (decided_by, FTRL P(spam), ensemble spam).
// Every result carries `model`, the artifact that actually produced it, read
// inside the addon while the load lock is held.

/** Classify free text. Resolves to { class, confidence, scores, decidedBy, model }. */
export function classifyText(text, mode = 'ensemble', debug = false, modelPath = DEFAULT_MODEL_PATH) {
	return addon.classify(String(text), false, modelPath, mode, debug);
}

/** Classify a raw RFC822 message (string or Buffer). Resolves to the same shape. */
export function classifyEml(buf, mode = 'ensemble', debug = false, modelPath = DEFAULT_MODEL_PATH) {
	return addon.classify(buf, true, modelPath, mode, debug);
}

/**
 * Identify a model artifact: { uuid, sourceModel, hiddenSize, numLabels,
 * rawInput, structuralMarkers }, or null if it cannot be loaded.
 *
 * `uuid` is null when the model directory carries no MANIFEST.json, which means
 * "unknown artifact", not "fine". A host that cannot name its own model is how
 * klar.im spent a month serving one that was never released.
 *
 * This LOADS the named model, synchronously, swapping out whatever was resident.
 * To attribute a verdict, read `model` off the classify result instead.
 */
export function modelInfo(modelPath = DEFAULT_MODEL_PATH) {
	return addon.modelInfo(modelPath);
}
