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
}

/** Pipeline mode: ensemble (default), neural-only, or ftrl-only. */
export type ClassifyMode = 'ensemble' | 'neural' | 'ftrl';

/** Classify free text on a libuv worker thread. */
export function classifyText(
	text: string,
	mode?: ClassifyMode,
	debug?: boolean
): Promise<ClassifyResult>;

/** Classify a raw RFC822 message (string or Buffer) on a worker thread. */
export function classifyEml(
	buf: string | Buffer,
	mode?: ClassifyMode,
	debug?: boolean
): Promise<ClassifyResult>;
