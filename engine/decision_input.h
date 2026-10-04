#pragma once

// The structural decision layer's input, and the fold over it (TASK-179).
//
// INTERNAL since TASK-540: this is not part of the C ABI. Every consumer
// (Mail extension, milter, spamd, the demo addon) reaches a verdict through
// spam_engine_classify_full, which assembles this struct from the same parse
// and folds it here. Before that, postfix, the demo addon and classify_full
// each assembled it by hand, and the copies shipped two bugs: the demo folded
// a calibrated model on the raw scale because the knot was not copied, and
// postfix compared model_info's boolean with STATUS_OK and inverted the branch.
// Kept as a header so the engine's tests can drive the fold one offset at a
// time.

#include "spam_engine_c_api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct spam_engine_decision_input {
  spam_engine_scores_t scores;   // stable semantic envelope (from classify)
  const char* ml_label;          // model's spam-side DECISION: "spam" or "regular"
                                 // (not a raw argmax; == the engine's binary label)
  double ml_confidence;          // model confidence, used on the non-spam keep path
  // Engine-derived (from the parsed message):
  int has_in_reply_to;           // 0 or 1
  int references_count;          // 0..N
  const char* dkim_signing_org_domain;  // eTLD+1; NULL/"" if none
  int signer_throwaway;          // 0 or 1
  int display_impersonation;     // 0 or 1 — From display impersonates a brand (TASK-214)
  int raw_ip_url;                // 0 or 1: a body link's host is a bare IP literal (TASK-257)
  int kb_brand_dmarc_pass;       // 0 or 1 — receiver-verified KB-brand sender (TASK-337/334)
  // Caller-OBSERVED transport fact (not derivable from the message); pass 0 if
  // unavailable:
  int connect_ip_blocked;        // 0 or 1 — the IP that CONNECTED to this MTA sits
                                 // in a Spamhaus DROP netblock (TASK-113). Set it
                                 // only from an address the caller observed itself
                                 // (a milter's xxfi_connect argument), never from a
                                 // Received header: below the accepting MTA's own
                                 // line those are attacker-written, and this offset
                                 // is condemn-capable. See ip_blocklist.h.
  // Caller-state (local DBs); pass 0 if unavailable:
  int phase2_match;              // Message-ID DB hit (0 or 1)
  int exact_send_count;          // user's outbound count to this exact address
  int domain_send_count;         // ...to this domain
  int profile;                   // spam_engine_profile_t
  int header_ip_blocked;         // 0 or 1 — the same DROP hit, but on an origin
                                 // recovered from the Received chain behind a
                                 // TRUSTED relay (TASK-387). A SEPARATE field on
                                 // purpose, carrying a weaker magnitude: a caller
                                 // must not be able to launder header evidence
                                 // into the condemn-capable one above.
  int gtube_test;                // 0 or 1 — the GTUBE test string is present, so
                                 // this message is an operator verifying the
                                 // filter is live. Condemn-capable by definition,
                                 // not by measurement: the string exists so that
                                 // "did my filter see this?" has an answer that
                                 // does not depend on the model. See
                                 // decision_layer.h.
  double spam_side_knot;         // 0 (or >= 1) = undeclared, the identity map and
                                 // what public-v0 uses. Otherwise the point on
                                 // THIS artifact's spam side that means the same
                                 // thing the product's Standard gate means, and
                                 // the engine maps it onto that gate. Set from
                                 // classifier_config.json's
                                 // spam_side_calibration_knot by
                                 // spam_engine_classify_full. See
                                 // decision_layer.h calibrate_spam_side.
  int attachment_disguised_executable;  // decoded dangerous bytes presented as harmless
  int archive_disguised_executable;     // same, one bounded archive level down
  int attachment_dangerous_type;        // plainly named or detected executable/script
  int archive_dangerous_type;           // same, within an archive
  int attachment_risk_enabled;          // experiment opt-in; default 0
  int dmarc_pass;                // 0 or 1 - the receiver said dmarc=pass. Read by
                                 // the callback-shape offset, which must not fire
                                 // on mail the receiver could verify.
  int callback_shape;            // 0 or 1 - brand-independent callback phishing
                                 // (TASK-440): billing language, a number to
                                 // call, no link anywhere.
  int no_contact_instruction;    // 0 or 1 - the body tells the recipient NOT to
                                 // check with their bank (TASK-460). Read by the
                                 // no-contact offset, which like the callback
                                 // shape must not fire on mail the receiver
                                 // could verify.
  int replied_to_own_sent;       // 0 or 1 - this message's In-Reply-To or first
                                 // Reference is a Message-ID the USER'S OWN
                                 // OUTBOUND mail carried. A STRICT SUBSET of
                                 // phase2_match, and deliberately its own field
                                 // rather than a reading of it: phase2_match is
                                 // also set by a parent WE classified as ham,
                                 // which an attacker can manufacture by sending
                                 // one benign message and replying to it. Only
                                 // this one is unforgeable, because the ID was
                                 // generated by the user's own client and never
                                 // published, so only this one may veto the
                                 // display-impersonation condemn.
} spam_engine_decision_input_t;

// Fill the engine-derived fields of *din from a classification's scores and
// parsed signals: copies scores, computes ml_label/ml_confidence (the model's
// spam-side decision from the scores, matching the engine and Swift, not a raw
// argmax -- TASK-251 C5), and maps the thread/auth signal fields. Leaves the caller-state
// fields (phase2_match, exact/domain_send_count, profile) untouched; the caller
// owns those. No-op if any pointer is NULL.
//
// din->dkim_signing_org_domain points into *signals, which must outlive the
// subsequent spam_engine_decide() call.
void spam_engine_decision_input_from_signals(
    spam_engine_decision_input_t* din,
    const spam_engine_scores_t* scores,
    const spam_engine_parsed_signals_t* signals);

// Returns SPAM_ENGINE_STATUS_OK and fills *out, or
// SPAM_ENGINE_STATUS_INVALID_ARGUMENT if in/out is NULL.
int spam_engine_decide(const spam_engine_decision_input_t* in,
                       spam_engine_decision_result_t* out);

#ifdef __cplusplus
}
#endif
