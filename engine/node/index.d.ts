export interface ClassifyScores {
	gibberish: number;
	marketing: number;
	regular: number;
	spam: number;
}

export interface ClassifyResult {
	/**
	 * The engine's DELIVERY DECISION — in practice only `spam` or `regular`
	 * (the decision layer folds marketing/gibberish into junk-vs-deliver). This
	 * is NOT the 4-class argmax.
	 */
	class: 'gibberish' | 'marketing' | 'regular' | 'spam' | 'unknown';
	/** Confidence in the decision above — not necessarily `scores[class]`. */
	confidence: number;
	/**
	 * The 4-class scores. In `ensemble` mode `scores.spam` is the escalate-only
	 * spam side `max(neural, w*ftrl+(1-w)*neural)` (NOT a normalized softmax); the
	 * other three stay raw neural. For the predicted *class*, take the argmax.
	 */
	scores: ClassifyScores;
	/** Which scorers produced the verdict: "neural" | "ftrl+neural" | "ftrl". */
	decidedBy: string;
	/**
	 * Present only when `debug` is true — the per-stage internals not already on
	 * the result (the verdict source is `decidedBy`, the spam side is `scores.spam`).
	 */
	debug?: {
		mode: ClassifyMode;
		/** FTRL P(spam), or -1 when FTRL was not consulted/cold. */
		ftrlScore: number;
	};
	/**
	 * The artifact that produced THIS verdict, read inside the addon while it
	 * still holds the load lock. That is the only place the answer is reliable:
	 * one model is resident at a time and the next call can swap it, so anything
	 * asked afterwards names whichever model happens to be loaded by then.
	 * Null only if the engine refused to describe itself.
	 */
	model: ModelInfo | null;
}

/** Pipeline mode: ensemble (default), neural-only, or ftrl-only. */
export type ClassifyMode = 'ensemble' | 'neural' | 'ftrl';

/**
 * The model directory used when a call names none: `KLAR_ENGINE_MODEL`, else
 * `<repo>/engine/model`. Exported so a host can offer alternatives relative to
 * it without restating the env var.
 */
export const DEFAULT_MODEL_PATH: string;

/**
 * Classify free text on a libuv worker thread.
 *
 * `modelPath` names the model directory. ONE model is resident at a time, and
 * asking for a different one swaps it: the resident model is unloaded before the
 * next is read, so peak memory is one encoder rather than two. A swap costs a
 * full load (hundreds of ms), so callers that mix models should serialize them
 * and expect the first call after a switch to be slow.
 */
export function classifyText(
	text: string,
	mode?: ClassifyMode,
	debug?: boolean,
	modelPath?: string
): Promise<ClassifyResult>;

/** Classify a raw RFC822 message (string or Buffer) on a worker thread. */
export function classifyEml(
	buf: string | Buffer,
	mode?: ClassifyMode,
	debug?: boolean,
	modelPath?: string
): Promise<ClassifyResult>;

export interface ModelInfo {
	/** null when the model directory carries no MANIFEST.json. */
	uuid: string | null;
	sourceModel: string | null;
	hiddenSize: number;
	numLabels: number;
	/** false = the public-v0 legacy envelope, true = raw text. */
	rawInput: boolean;
	structuralMarkers: boolean;
}

/**
 * Identify a model artifact. SYNCHRONOUS, and it LOADS the named model, swapping
 * out whatever was resident. To attribute a verdict, read `model` off the
 * classify result instead; this is for a caller naming a model deliberately.
 */
export function modelInfo(modelPath?: string): ModelInfo | null;
