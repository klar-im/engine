#pragma once
#include <string>
#include <vector>
#include "config.h"
#include "model_runtime.h"

namespace klar {

enum class Action { TAG, REJECT, BYPASS, TEMPFAIL };

struct PolicyResult {
    Action action = Action::TAG;
    std::string label;           // "spam" or "regular"
    // 3-class argmax over the raw scores: "regular|marketing|spam".
    // Informative companion to the binary label. Sieve files non-spam
    // marketing to a Marketing folder off this (X-Klar-Class header).
    std::string klass = "regular";
    std::string policy_reason;   // "ml", "allowlist_sender", "blocklist_domain", etc.
    double effective_threshold = 0;  // set by evaluate_policy; never a number of its own

    // Scores (may be forced for allowlist/blocklist)
    float score_spam = 0;
    float score_regular = 0;
    float score_marketing = 0;
    // Spam-side after the structural-offset fold (TASK-179). The junk/tag label
    // thresholds on THIS.
    float score_spam_adjusted = 0;
    // Spam-side after the artifact's own calibration and BEFORE any offset
    // (the engine's calibrated_spam_side): the model-independent scale on
    // which reject_threshold is read. Raw `score_spam` is kept for logging
    // and is per-model (a label-smoothed head never reaches 0.99 raw).
    float score_spam_calibrated = 0;

    // Error info
    std::string error_code = "E_NONE";
    std::string status = "ok";
};

std::string action_to_string(Action a);

// The policy in force for one message: the global config, overridden by the
// first recipient-domain policy that matches and merged strictest-wins with
// the rest (mode by severity, thresholds by minimum). Resolved once, BEFORE
// the classify, so the engine folds at the same profile the label is
// thresholded at (TASK-510; the fold used to run at Standard whatever the
// config said, so the `!` flip marks and the label could describe two
// different gates), and handed to both classify_rfc822 and evaluate_policy.
struct EffectivePolicy {
    std::string mode;
    std::string profile;
    spam_engine_profile_t engine_profile = SPAM_ENGINE_PROFILE_STANDARD;  // profile_to_engine(profile)
    double spam_threshold_override = -1.0;
    double reject_threshold = 0;
};

EffectivePolicy resolve_policy(const Config& cfg, const std::vector<std::string>& rcpt_to);

PolicyResult evaluate_policy(
    const Config& cfg,
    const EffectivePolicy& eff,
    const ClassifyResult& cr,
    const std::string& sender_email,
    bool classify_failed,
    bool bypass_due_overload);

} // namespace klar
