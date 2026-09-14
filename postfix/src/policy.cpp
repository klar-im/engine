#include "policy.h"

#include <algorithm>
#include <cctype>

namespace klar {

namespace {

std::string to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

std::string extract_domain(const std::string& email) {
    auto pos = email.find('@');
    if (pos == std::string::npos) return {};
    return to_lower(email.substr(pos + 1));
}

// Mode severity: higher is stricter
int mode_severity(const std::string& mode) {
    if (mode == "reject") return 2;
    if (mode == "tag") return 1;
    return 0;
}

bool contains(const std::vector<std::string>& list, const std::string& value) {
    return std::find(list.begin(), list.end(), value) != list.end();
}

} // anonymous namespace

std::string action_to_string(Action a) {
    switch (a) {
        case Action::TAG:        return "tag";
        case Action::REJECT:     return "reject";
        case Action::BYPASS:     return "bypass";
        case Action::TEMPFAIL:   return "tempfail";
    }
    return "tag";
}

PolicyResult evaluate_policy(
    const Config& cfg,
    const ClassifyResult& cr,
    const std::string& sender_email,
    const std::vector<std::string>& rcpt_to,
    bool classify_failed,
    bool bypass_due_overload) {

    PolicyResult pr;

    // 1. Normalize sender
    std::string sender_lower = to_lower(sender_email);
    std::string sender_domain = extract_domain(sender_lower);

    // 2. Effective policy resolution via recipient domains
    // Start with global defaults
    std::string eff_mode = cfg.mode;
    std::string eff_profile = cfg.profile;
    double eff_spam_threshold_override = cfg.spam_threshold_override;
    double eff_reject_threshold = cfg.reject_threshold;

    if (!rcpt_to.empty() && !cfg.domain_policies.empty()) {
        bool first_match = true;

        for (const auto& rcpt : rcpt_to) {
            std::string rcpt_domain = extract_domain(to_lower(rcpt));
            if (rcpt_domain.empty()) continue;

            // Find matching domain policy
            const DomainPolicy* dp = nullptr;
            for (const auto& policy : cfg.domain_policies) {
                if (to_lower(policy.recipient_domain) == rcpt_domain) {
                    dp = &policy;
                    break;
                }
            }

            if (!dp) continue;

            if (first_match) {
                eff_mode = dp->mode;
                eff_profile = dp->profile;
                eff_spam_threshold_override = dp->spam_threshold_override;
                eff_reject_threshold = dp->reject_threshold;
                first_match = false;
            } else {
                // Merge: strictest mode, minimum thresholds
                if (mode_severity(dp->mode) > mode_severity(eff_mode)) {
                    eff_mode = dp->mode;
                }
                eff_reject_threshold = std::min(eff_reject_threshold, dp->reject_threshold);
                if (dp->spam_threshold_override >= 0) {
                    if (eff_spam_threshold_override >= 0) {
                        eff_spam_threshold_override = std::min(eff_spam_threshold_override, dp->spam_threshold_override);
                    } else {
                        eff_spam_threshold_override = dp->spam_threshold_override;
                    }
                }
            }
        }
    }

    // 3. Allowlist/blocklist precedence
    bool is_blocklisted = false;
    bool is_allowlisted = false;

    if (contains(cfg.blocklist_senders, sender_lower)) {
        pr.policy_reason = "blocklist_sender";
        is_blocklisted = true;
    } else if (contains(cfg.blocklist_domains, sender_domain)) {
        pr.policy_reason = "blocklist_domain";
        is_blocklisted = true;
    } else if (contains(cfg.allowlist_senders, sender_lower)) {
        pr.policy_reason = "allowlist_sender";
        is_allowlisted = true;
    } else if (contains(cfg.allowlist_domains, sender_domain)) {
        pr.policy_reason = "allowlist_domain";
        is_allowlisted = true;
    } else if (cr.flipped_by_offset) {
        // A structural offset, not the content model, decided this one. Recorded
        // distinctly so the common "why was my low-scoring mail junked?" case is
        // greppable in the JSON log without opening the event store (TASK-388);
        // fired_offsets on the event says WHICH offset.
        pr.policy_reason = "structural";
    } else {
        pr.policy_reason = "ml";
    }

    // 4. Short-circuit scores for blocklist/allowlist
    if (is_blocklisted) {
        pr.score_spam = 1.0f;
        pr.score_regular = 0.0f;
        pr.score_marketing = 0.0f;
        pr.score_gibberish = 0.0f;
        pr.score_spam_adjusted = 1.0f;
        pr.score_spam_calibrated = 1.0f;
    } else if (is_allowlisted) {
        pr.score_spam = 0.0f;
        pr.score_regular = 1.0f;
        pr.score_marketing = 0.0f;
        pr.score_gibberish = 0.0f;
        pr.score_spam_adjusted = 0.0f;
        pr.score_spam_calibrated = 0.0f;
    } else {
        pr.score_spam = cr.spam;
        pr.score_regular = cr.regular;
        pr.score_marketing = cr.marketing;
        pr.score_gibberish = cr.gibberish;
        pr.score_spam_adjusted = cr.adjusted_spam;
        pr.score_spam_calibrated = cr.calibrated_spam;
    }

    // klass: 4-class argmax over the resolved scores, the X-Klar-Class companion
    // to the binary label. One pass covers every branch: blocklist forces
    // spam=1, allowlist forces regular=1, ML uses the raw scores.
    const struct { const char* name; float score; } classes[] = {
        {"regular", pr.score_regular}, {"marketing", pr.score_marketing},
        {"gibberish", pr.score_gibberish}, {"spam", pr.score_spam}};
    pr.klass = classes[0].name;
    float best = classes[0].score;
    for (const auto& c : classes) {
        if (c.score > best) { best = c.score; pr.klass = c.name; }
    }

    // 5. Threshold resolution
    double threshold;
    if (eff_spam_threshold_override >= 0) {
        threshold = eff_spam_threshold_override;
    } else {
        threshold = profile_to_threshold(eff_profile);
    }
    pr.effective_threshold = threshold;

    // Label — Dovecot Sieve uses this to file spam to Junk. Thresholds on the
    // OFFSET-ADJUSTED spam side (TASK-179) so a free-host/throwaway-signed phish
    // the model leaks as marketing is still junked — and deterministically,
    // independent of the BLAS rounding that makes the raw head flippy near the gate.
    pr.label = (pr.score_spam_adjusted >= threshold) ? "spam" : "regular";

    // 6. Action decision
    // Only two real actions: tag (deliver with headers) or reject (bounce).
    // Dovecot Sieve handles filing to Junk based on X-Klar-Label.
    if (bypass_due_overload) {
        pr.action = Action::BYPASS;
        pr.status = "bypass_overload";
    } else if (is_blocklisted) {
        pr.action = Action::REJECT;
    } else if (is_allowlisted) {
        pr.action = Action::TAG;
    } else if (classify_failed && cfg.fail_open) {
        pr.action = Action::BYPASS;
        pr.error_code = "E_CLASSIFY";
        pr.status = "fail_open";
    } else if (classify_failed && !cfg.fail_open) {
        pr.action = Action::TEMPFAIL;
        pr.error_code = "E_CLASSIFY";
        pr.status = "fail_closed";
    } else if (eff_mode == "reject" && pr.score_spam_calibrated >= eff_reject_threshold
               && cr.structural_condemn) {
        // Reject/bounce is destructive and irreversible, so it requires TWO
        // independent strong signals (TASK-179): the content model highly
        // confident AND a structural condemn (free-host/throwaway DKIM signer,
        // or a DROP-listed connecting IP — TASK-113). No single scorer's blind
        // spot can bounce legitimate mail; high-confidence-but-uncorroborated
        // spam falls through to TAG (junk — recoverable). Blocklist reject
        // (above) is an explicit operator decision, not a scorer, so it stays
        // single-factor.
        //
        // "Highly confident" is read on the CALIBRATED spam side (the artifact's
        // own knot mapped onto the fixed 0.99 gate, before any offset), not the
        // raw probability. The raw scale is per-model: public-v0 emits 0.999 on
        // blatant spam and a label-smoothed head (gen3-v6) tops out near 0.90 by
        // construction, so a raw 0.995 was a rule public-v0 could satisfy and
        // its successor never could (2026-09-14, postfix/test-reject). The
        // offsets are deliberately NOT in this number: the condemn is the
        // second factor and must not also be the first.
        pr.action = Action::REJECT;
    } else {
        pr.action = Action::TAG;
    }

    return pr;
}

} // namespace klar
