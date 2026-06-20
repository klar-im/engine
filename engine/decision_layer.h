#pragma once

// Structural decision layer — the C++ source of truth for the soft-offset fold
// + filtering-profile threshold that turns the 4-class model scores into a
// final spam/ham verdict.
//
// WHY THIS EXISTS (TASK-179): the fold + thresholds historically lived ONLY in
// Swift (apple/Klar/KlarCore/Classification/), so every other engine consumer
// — the postfix milter, a future Stalwart plugin, the CLI, a hosted API — would
// have to re-implement them and could silently drift. Moving them here gives
// all consumers the same verdict for free. Signals that need local state
// (Phase-2 Message-ID DB hit, sender-history send-counts) stay caller-provided
// inputs to the fold; everything derivable from the parsed message
// (thread-header presence, free-host / throwaway DKIM signer) is computed here.
//
// CROSS-LANGUAGE SYNC: the constants below MIRROR the canonical Swift
// definitions (ClassificationOffsets.swift, AuthFeatures.freeHostSigningDomains,
// FilteringProfileSetting.spamThreshold). pythonDiscovery/test_decision_layer_sync.py
// already pins the Swift⇄Python pair; this header is the third mirror and is
// kept in sync by engine/tests/decision_layer_tests.cpp (which asserts the same
// values + golden fold cases the Swift unit tests assert).

#include <set>
#include <string>
#include <vector>

namespace spam_engine {
namespace decision {

// ── Offset magnitudes — mirror ClassificationOffsets.swift ──────────────────
// Calibration knobs: change without changing observable behaviour. Any tuning
// must be reflected in the Swift source (and apple/spec/classification.allium).
inline constexpr double kInReplyTo = 0.20;            // thread header presence
inline constexpr double kPerReference = 0.05;
inline constexpr int    kReferencesCapCount = 3;      // cap forged long chains
inline constexpr double kPhase2Match = 0.30;          // Message-ID DB hit
inline constexpr double kSenderHistoryRepeat = 0.40;  // exact send_count >= 2
inline constexpr double kSenderHistorySingle = 0.10;  // exact send_count == 1
inline constexpr double kSenderHistoryDomain = 0.05;  // domain-only prior send
inline constexpr double kSenderAuthFreeHost = 0.90;   // free-host DKIM signer
inline constexpr double kSenderAuthThrowawaySigner = 0.90;  // throwaway-shape signer

// ── Filtering-profile thresholds — mirror FilteringProfileSetting.swift ─────
inline constexpr double kThresholdStandard = 0.90;
inline constexpr double kThresholdCautious = 0.95;  // also forced while "learning"

// Free-hosting / disposable DKIM signing org-domains — mirror
// AuthFeatures.freeHostSigningDomains. All two-label org-domains so they
// compare directly against the engine's eTLD+1 reduction (org_domain()).
inline const std::set<std::string>& free_host_signing_domains() {
  static const std::set<std::string> kDomains = {
      "firebaseapp.com", "web.app", "appspot.com",
      "pages.dev", "workers.dev", "netlify.app", "vercel.app",
  };
  return kDomains;
}

// True when the DKIM signing org-domain is a known free-hosting/disposable host.
inline bool is_free_host_signed(const std::string& dkim_signing_org_domain) {
  if (dkim_signing_org_domain.empty()) return false;
  const auto& set = free_host_signing_domains();
  return set.find(dkim_signing_org_domain) != set.end();
}

// ── Derived offset magnitudes (from the engine's own parse) ─────────────────

// Thread-header ham prior: in-reply-to presence + capped References count.
// Mirrors ThreadFeatures.spamConfidenceOffset.
inline double thread_header_offset(bool has_in_reply_to, int references_count) {
  double offset = 0.0;
  if (has_in_reply_to) offset += kInReplyTo;
  const int capped = references_count < kReferencesCapCount
                         ? references_count : kReferencesCapCount;
  if (capped > 0) offset += static_cast<double>(capped) * kPerReference;
  return offset;
}

// Sender-auth spam-ward push: free-host signer first, else throwaway-shape.
// Mirrors AuthFeatures.spamConfidenceOffset.
inline double sender_auth_offset(const std::string& dkim_signing_org_domain,
                                 bool signer_throwaway) {
  if (is_free_host_signed(dkim_signing_org_domain)) return kSenderAuthFreeHost;
  if (signer_throwaway) return kSenderAuthThrowawaySigner;
  return 0.0;
}

// Graded sender-history ham prior. Caller supplies send counts from its local
// DB (the engine has no contacts store). Mirrors senderHistoryMagnitude().
inline double sender_history_magnitude(int exact_send_count, int domain_send_count) {
  if (exact_send_count >= 2) return kSenderHistoryRepeat;
  if (exact_send_count == 1) return kSenderHistorySingle;
  return domain_send_count >= 1 ? kSenderHistoryDomain : 0.0;
}

// Profile threshold. `learning` forces the cautious threshold (mirror
// SharedSettings.spamThreshold's learning-clause).
enum class Profile { Standard, Cautious, Learning };
inline double threshold_for_profile(Profile p) {
  switch (p) {
    case Profile::Cautious:
    case Profile::Learning:
      return kThresholdCautious;
    case Profile::Standard:
      break;
  }
  return kThresholdStandard;
}

// ── The fold ────────────────────────────────────────────────────────────────

enum class Direction { Ham, Spam };

// One structural offset. Mirrors StructuralOffset.swift.
struct Offset {
  std::string classifier_id;  // "thread_headers" | "thread_history" |
                              // "sender_history" | "sender_auth"
  double magnitude = 0.0;     // unsigned weight (>= 0); 0 == did not fire
  Direction direction = Direction::Ham;

  double signed_value() const {
    return direction == Direction::Spam ? magnitude : -magnitude;
  }
  bool fired() const { return magnitude > 0.0; }
};

// 4-class softmax (mirror ClassScores; doubles so the fold matches Swift's
// Double arithmetic bit-for-bit on the constants).
struct Scores {
  double gibberish = 0.0;
  double marketing = 0.0;
  double regular = 0.0;
  double spam = 0.0;
};

// An offset that fired, with the flip attribution the audit trail records.
struct FiredOffset {
  std::string classifier_id;
  double magnitude = 0.0;
  Direction direction = Direction::Ham;
  // The label this offset is credited with flipping to, or empty if it fired
  // but did not change the decision. Ham-ward → "ham" on a rescue; the
  // spam-ward offset → "spam" on a condemn.
  std::string flipped_label;
};

struct Verdict {
  std::string label;             // "spam" | "gibberish" | "marketing" | "ham"
  double confidence = 0.0;
  double adjusted_spam_side = 0.0;
  bool train_ml = true;          // false on a header-only (offset) condemn
  std::vector<FiredOffset> fired;
};

// Collapse the non-spam side to a first-class label. Mirror refineNonSpamLabel.
inline std::string refine_non_spam_label(const Scores& s) {
  return s.marketing > s.regular ? "marketing" : "ham";
}

// Fold the signed offsets onto the spam side and threshold. `ml_label` is the
// engine's argmax label for the 4-class scores ("spam"/"gibberish" mean the
// model itself said spam-side). Faithful port of ClassificationService steps
// 6–7: same arithmetic, same clamp, same flip attribution, same train_ml rule.
inline Verdict fold(const Scores& scores,
                    const std::vector<Offset>& offsets,
                    double threshold,
                    const std::string& ml_label,
                    double ml_confidence) {
  const double raw_spam_side = scores.spam + scores.gibberish;
  double signed_total = 0.0;
  for (const auto& o : offsets) {
    if (o.fired()) signed_total += o.signed_value();
  }
  double adjusted = raw_spam_side + signed_total;
  if (adjusted < 0.0) adjusted = 0.0;
  if (adjusted > 1.0) adjusted = 1.0;

  const bool ml_said_spam = (ml_label == "spam" || ml_label == "gibberish");

  Verdict v;
  v.adjusted_spam_side = adjusted;
  if (adjusted >= threshold) {
    // Spam side wins: keep the model's spam sub-label when it had one, else a
    // spam-ward offset condemned an otherwise-kept message → "spam".
    v.label = ml_said_spam ? ml_label : "spam";
    v.confidence = adjusted;
  } else if (ml_said_spam) {
    // Model said spam but ham offsets pulled it under the threshold.
    v.label = "ham";
    v.confidence = 1.0 - adjusted;
  } else {
    // Model kept it and nothing pushed it over — recover marketing vs ham.
    // Keeps the model's own confidence, exactly like the Swift non-spam branch.
    v.label = refine_non_spam_label(scores);
    v.confidence = ml_confidence;
  }

  const bool rescued = ml_said_spam && v.label == "ham";
  bool has_spam_ward = false;
  for (const auto& o : offsets) {
    if (o.fired() && o.direction == Direction::Spam) { has_spam_ward = true; break; }
  }
  const bool condemned = has_spam_ward && !ml_said_spam && v.label == "spam";
  v.train_ml = !condemned;  // don't feed a header-only condemn back into ML

  for (const auto& o : offsets) {
    if (!o.fired()) continue;
    FiredOffset f;
    f.classifier_id = o.classifier_id;
    f.magnitude = o.magnitude;
    f.direction = o.direction;
    if (o.direction == Direction::Ham && rescued) f.flipped_label = "ham";
    else if (o.direction == Direction::Spam && condemned) f.flipped_label = "spam";
    v.fired.push_back(f);
  }
  return v;
}

}  // namespace decision
}  // namespace spam_engine
