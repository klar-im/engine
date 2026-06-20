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
    std::string policy_reason;   // "ml", "allowlist_sender", "blocklist_domain", etc.
    double effective_threshold = 0.5;

    // Scores (may be forced for allowlist/blocklist)
    float score_spam = 0;
    float score_regular = 0;
    float score_marketing = 0;
    float score_gibberish = 0;
    // Spam-side after the structural-offset fold (TASK-179). The junk/tag label
    // thresholds on THIS; `score_spam` (raw) still gates the bounce/reject path.
    float score_spam_adjusted = 0;

    // Error info
    std::string error_code = "E_NONE";
    std::string status = "ok";
};

std::string action_to_string(Action a);

PolicyResult evaluate_policy(
    const Config& cfg,
    const ClassifyResult& cr,
    const std::string& sender_email,
    const std::vector<std::string>& rcpt_to,
    bool classify_failed,
    bool bypass_due_overload);

} // namespace klar
