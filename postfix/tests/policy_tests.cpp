// The milter's label is the product's gate (TASK-510). evaluate_policy has no
// engine, milter, config-parser or sqlite dependency: this links policy.cpp
// alone, and decision_profiles.h reads the engine's header-only
// decision_layer.h.
//
// The case that motivates every line: a reply to the user's own mail scored
// 0.04 on the model, +0.99 for a brand rule on the sender's surname, -0.25 for
// its thread headers, adjusted 0.78. The Mac app delivers it at 0.99; the
// milter junked it at its own 0.50. Same engine, same calibrated score, a
// table nobody had pinned. The first test here is red on that table.

#include "policy.h"

#include "../../engine/decision_layer.h"

#include <cstdio>
#include <string>
#include <vector>

using klar::ClassifyResult;
using klar::Config;
using klar::DomainPolicy;
using klar::PolicyResult;
using klar::evaluate_policy;
using klar::profile_to_engine;
using klar::profile_to_threshold;

namespace dl = spam_engine::decision;

static int g_failures = 0;

static void check(bool ok, const char* what) {
  std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", what);
  if (!ok) { ++g_failures; }
}

static ClassifyResult scored(float adjusted, float calibrated = 0.0f) {
  ClassifyResult cr;
  cr.ok = true;
  cr.spam = 0.04f;
  cr.regular = 0.84f;
  cr.marketing = 0.12f;
  cr.adjusted_spam = adjusted;
  cr.calibrated_spam = calibrated;
  return cr;
}

static PolicyResult label_for(const Config& cfg, float adjusted) {
  const klar::EffectivePolicy eff = klar::resolve_policy(cfg, {"user@mail.example"});
  return evaluate_policy(cfg, eff, scored(adjusted), "sender@example.org",
                         /*classify_failed=*/false, /*bypass_due_overload=*/false);
}

int main() {
  // 1. The three names are the engine's three profiles and their numbers,
  //    nothing else, through one table.
  check(profile_to_engine("standard") == SPAM_ENGINE_PROFILE_STANDARD, "standard is the engine's Standard");
  check(profile_to_engine("cautious") == SPAM_ENGINE_PROFILE_CAUTIOUS, "cautious is the engine's Cautious");
  check(profile_to_engine("aggressive") == SPAM_ENGINE_PROFILE_AGGRESSIVE, "aggressive is the engine's Aggressive");
  check(profile_to_engine("nonsense") == SPAM_ENGINE_PROFILE_STANDARD, "an unknown name falls back to Standard");
  check(profile_to_threshold(SPAM_ENGINE_PROFILE_STANDARD) == dl::kThresholdStandard, "standard is kThresholdStandard");
  check(profile_to_threshold(SPAM_ENGINE_PROFILE_CAUTIOUS) == dl::kThresholdCautious, "cautious is kThresholdCautious");
  check(profile_to_threshold(SPAM_ENGINE_PROFILE_AGGRESSIVE) == dl::kThresholdAggressive, "aggressive is kThresholdAggressive");
  check(profile_to_threshold(SPAM_ENGINE_PROFILE_LEARNING) == dl::kThresholdCautious, "learning folds at the cautious gate, as in the engine");
  check(klar::is_valid_profile("aggressive") && !klar::is_valid_profile("learning") && !klar::is_valid_profile(""),
        "is_valid_profile is the same three-name table");

  // 2. That reply: adjusted 0.78 under the standard profile is regular.
  //    Red on the old table (0.50).
  Config standard;
  standard.profile = "standard";
  PolicyResult reply = label_for(standard, 0.7842f);
  check(reply.label == "regular", "adjusted 0.78 under standard is regular (was spam at 0.50)");
  check(reply.effective_threshold == dl::kThresholdStandard, "the effective threshold is the product's");

  // 3. Over the gate it is spam at standard and, one notch above, regular at cautious.
  check(label_for(standard, 0.992f).label == "spam", "adjusted 0.992 under standard is spam");
  Config cautious;
  cautious.profile = "cautious";
  check(label_for(cautious, 0.992f).label == "regular", "adjusted 0.992 under cautious is regular");
  Config aggressive;
  aggressive.profile = "aggressive";
  check(label_for(aggressive, 0.96f).label == "spam", "adjusted 0.96 under aggressive is spam");
  check(label_for(standard, 0.96f).label == "regular", "adjusted 0.96 under standard is regular");

  // 4. An explicit override is an operator's number and still applies to the
  //    adjusted side: 0.78 is spam under an override of 0.5.
  Config overridden;
  overridden.profile = "standard";
  overridden.spam_threshold_override = 0.5;
  PolicyResult forced = label_for(overridden, 0.7842f);
  check(forced.label == "spam", "spam_threshold_override 0.5 labels 0.78 spam");
  check(forced.effective_threshold == 0.5, "the override is the effective threshold");

  // 5. A recipient domain policy naming a profile resolves through the same table.
  Config per_domain;
  per_domain.profile = "standard";
  DomainPolicy dp;
  dp.recipient_domain = "mail.example";
  dp.mode = "tag";
  dp.profile = "cautious";
  per_domain.domain_policies.push_back(dp);
  check(label_for(per_domain, 0.992f).label == "regular",
        "a domain policy's cautious profile reads the engine's 0.995");
  // 6. The same resolution is what the milter hands the fold before classifying,
  //    so the label and the flip marks describe one gate; a domain policy that
  //    names no profile inherits the global one rather than resolving to "".
  const klar::EffectivePolicy in_force = klar::resolve_policy(per_domain, {"user@mail.example"});
  check(in_force.profile == "cautious" && in_force.engine_profile == SPAM_ENGINE_PROFILE_CAUTIOUS,
        "resolve_policy: the recipient domain's profile is the one in force, as name and engine value");
  check(klar::resolve_policy(per_domain, {"someone@elsewhere.example"}).profile == "standard",
        "resolve_policy: an unmatched recipient keeps the global profile");
  DomainPolicy unnamed;
  unnamed.recipient_domain = "quiet.example";
  unnamed.mode = "tag";
  Config inherit;
  inherit.profile = "aggressive";
  inherit.domain_policies.push_back(unnamed);
  const klar::EffectivePolicy inherited = klar::resolve_policy(inherit, {"x@quiet.example"});
  check(inherited.profile == "aggressive" && inherited.engine_profile == SPAM_ENGINE_PROFILE_AGGRESSIVE,
        "resolve_policy: a domain policy with no profile inherits the global one");

  std::printf("%d failure(s)\n", g_failures);
  return g_failures == 0 ? 0 : 1;
}
