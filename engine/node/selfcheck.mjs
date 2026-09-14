#!/usr/bin/env node
// The addon's decision fold has to agree with the artifact it loaded, and this
// is the check that says so, run right after every build of the addon (make
// website/engine-addon, and deploy-demo-engine.sh on the server).
//
// Why it exists: the addon runs spam_engine_decide itself, and a standalone
// decide caller has to copy the artifact's calibration knot into the decision
// input (spam_engine_classify_full does it for its own callers). Until
// 2026-09-14 it did not, and nothing noticed for as long as the released model
// declared no knot: public-v0's raw spam side already sits above 0.99. gen3-v6
// declares 0.8931 and its raw spam side tops out near 0.90, so the day it was
// deployed every neural spam verdict on klar.im read as ham at 0.897 while the
// C API said 0.990. The demo fixtures are committed and the contract is the
// artifact's own: a raw spam side at or above the declared knot maps to the
// 0.99 gate or above.
//
//   node engine/node/selfcheck.mjs            # model: KLAR_ENGINE_MODEL or engine/model
//   node engine/node/selfcheck.mjs <model-dir>
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_MODEL_PATH, classifyEml, modelInfo } from './index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.resolve(here, '..', 'tests', 'data', 'demo-samples');
const modelPath = process.argv[2] ? path.resolve(process.argv[2]) : DEFAULT_MODEL_PATH;
// No copy of the engine's gate here: the verdict label IS the engine's reading
// of its own gate, so the contract is stated on the label and on the fold
// having moved the score, never on a threshold this file would have to keep
// in step with decision_layer.h.

const fail = (message) => {
	console.error(`[engine/node selfcheck] FAIL: ${message}`);
	process.exit(1);
};

const info = modelInfo(modelPath);
if (!info) fail(`no model at ${modelPath}`);
const knot = info.spamSideCalibrationKnot;
console.log(
	`[engine/node selfcheck] model ${info.uuid ?? 'unmanifested'} at ${modelPath}, knot ${knot || 'undeclared'}`
);

const classify = (name) => classifyEml(readFileSync(path.join(fixtures, name)), 'ensemble', false, modelPath);

// A clear spam and a clear ham, both English, both decided by the head alone
// on every model this repo has shipped (no structural offset fires on either).
const spam = await classify('spam.en.eml');
const ham = await classify('ham.en.eml');
for (const [name, r] of [
	['spam.en.eml', spam],
	['ham.en.eml', ham]
]) {
	console.log(
		`[engine/node selfcheck] ${name}: raw spam ${r.scores.spam.toFixed(4)}, ` +
			`adjusted ${r.decision.adjustedSpamSide.toFixed(4)}, ${r.decision.label}, by ${r.decidedBy}`
	);
}
if (spam.decision.label !== 'spam') fail('spam.en.eml is not decided spam');
if (ham.decision.label !== 'ham') fail('ham.en.eml is not decided ham');
if (knot > 0 && knot < 1) {
	// The contract of a declared knot: a raw spam side at or above it is spam
	// (asserted on the label above, the engine's own reading of its gate), and
	// the fold moved the score, so it cannot have been the identity.
	if (spam.scores.spam < knot) {
		fail(
			`spam.en.eml reads raw ${spam.scores.spam.toFixed(4)} under the declared knot ${knot}: ` +
				'this fixture no longer exercises the calibration and the check needs a new one'
		);
	}
	if (Math.abs(spam.decision.adjustedSpamSide - spam.scores.spam) < 1e-9) {
		fail('a declared knot left the spam side exactly where the raw score was: the knot was not applied');
	}
}
console.log('[engine/node selfcheck] OK: the decision fold applies the loaded artifact\'s calibration');
