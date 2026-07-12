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
inline constexpr double kDisplayImpersonation = 0.90;  // spam-ward: From display
                                  // claims a distinctive brand the domain isn't
                                  // (TASK-214) — strong, precision-first (0 ham FP)
inline constexpr double kUrlRawIp = 0.30;  // spam-ward: a body link to a bare IP
                                  // literal (TASK-257). Modest: corroborates, does
                                  // not solo-condemn a clean score. See the URL-
                                  // signals block below for why only this one wired.
inline constexpr double kSenderAuthEstablishedBrand = 0.15;  // ham-ward: Tranco
                                  // brand / clean-ESP DKIM signer (TASK-170)
inline constexpr double kBrandReputationCeiling = 0.97;  // don't rescue a spam-side
                                  // at/above this (a near-certain spam from a
                                  // popular-but-abused domain must not be exonerated)

// ── Structural URL signals (TASK-257): only raw_ip_url wired ────────────────
// Three candidates were built + ablated against this model on the real 739-spam /
// 56-ham corpus, both gates (0.90 standard, 0.95 learning) x both modes (neural,
// ensemble), rule-of-three CIs (pythonDiscovery/scripts/measure_url_structure.py).
// Standalone rates look discriminative (shortener 7.2% spam / 0% ham, raw_ip
// 3.1% / 0%, shared_bare_cdn 25.2% / 7.1%), but on THIS corpus none flips a
// model-wrong verdict: shortener + raw-IP fire only on spam already condemned,
// shared_bare_cdn's only rescues need a magnitude that would also FP legit mail.
//   - raw_ip_url (kUrlRawIp above): WIRED as a modest 0.30 corroborator despite 0
//     measured lift, on a priors argument the corpus can't test: a bare-IP host is
//     ~never legitimate (real senders use domain names), so its 0/56 ham is
//     STRUCTURAL, not sample-luck: it is provably inert on the eval set (fires
//     on 0 ham) while adding cheap insurance against the out-of-sample raw-IP phish
//     the model misses. 0.30 corroborates, never solo-condemns a clean score.
//   - url_shortener: NOT wired. Its 0/56 ham is sample-luck: the set's natural
//     members t.co / lnkd.in carry legit Twitter / LinkedIn mail absent from n=56,
//     so a condemn-capable magnitude would FP on common legit mail. Zero lift too.
//   - shared_bare_cdn: NOT wired. At the 0.95 gate a soft 0.10 push rescues 2-3
//     real phish (googleapis / imgur) with 0 measured FP, but it ALSO fires on
//     legit marketing hosting images on those same stores (a "Mudi 7" launch mail
//     on storage.googleapis.com scores 0.992). 0 FP is luck on n=56; a soft push on
//     such marketing in [0.85, gate) regresses the legit-marketing boundary
//     (TASK-169) this product protects. Revisit only with a larger near-gate ham
//     corpus proving 0 FP holds; the harness sweeps gates/modes/CIs to re-check.
// Also measured non-discriminative, do not re-attempt: free-host-link (0.9% spam /
// 3.6% ham, ham-ward) and many-link-domains (39% ham / 2% spam, a HAM signal).

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

// Shared sender platforms: free webmail + publishing/newsletter hosts. These are
// "established" domains (popular, DMARC-aligned to themselves) yet ANY third party
// can send brand-looking mail from them, so aligning to one is NOT evidence the
// sender owns a brand. Used to exclude them from the impersonation auth-reputation
// exemption ("PayPal" from a gmail.com / blogspot.com account is still a spoof).
inline bool is_shared_sender_platform(const std::string& org_domain) {
  static const std::set<std::string> kShared = {
      "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
      "msn.com", "yahoo.com", "yahoo.fr", "yahoo.co.uk", "ymail.com", "aol.com",
      "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com", "gmx.com",
      "gmx.net", "mail.com", "zoho.com", "yandex.com", "yandex.ru", "qq.com",
      "blogspot.com", "wordpress.com", "medium.com", "substack.com", "beehiiv.com",
      "ghost.io", "tumblr.com",
  };
  return kShared.find(org_domain) != kShared.end();
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

// The model's OWN pre-offset decision from the 4-class scores: the binary label
// ("spam"/"regular") and confidence the fold treats as "what the model said". It
// is NOT a raw argmax: a high gibberish is a spam-side call, and a low-spam
// high-regular carve-out is a deliver. This is the single source of truth that
// SpamEngine::decision_from_scores, the C-ABI decide-input builder, and Swift's
// mlResult.label all reduce to, so ml_said_spam can't drift across the three
// (TASK-251 C5). The old C-ABI builder used argmax, which fired ml_said_spam on
// gibberish-argmax mail the engine and Swift scored as a deliver.
struct NeuralDecision { const char* label; double confidence; };
inline NeuralDecision neural_decision(const Scores& s) {
  // Float literals: the source scores are float, so comparing against 0.7f/0.2f/
  // 0.5f (promoted to double) reproduces the old float comparison exactly, with no
  // boundary drift from a double 0.7 sitting one ULP above 0.7f (TASK-251 C5).
  if (s.gibberish > 0.7f) return {"spam", s.gibberish};
  if (s.spam < 0.2f && s.regular > 0.5f) return {"regular", 1.0 - s.spam};
  if (s.spam > 0.5f) return {"spam", s.spam};
  return {"regular", 1.0 - s.spam};
}

// Fold the signed offsets onto the spam side and threshold. `ml_label` is the
// model's own spam-side DECISION (neural_decision above / Swift mlResult.label):
// "spam" (incl. a "gibberish" sub-label a caller may still pass) means the model
// itself said spam-side; not a raw 4-class argmax (TASK-251 C5). Faithful port of
// ClassificationService steps 6-7: same arithmetic, same clamp, same flip
// attribution, same train_ml rule.
inline Verdict fold(const Scores& scores,
                    const std::vector<Offset>& offsets,
                    double threshold,
                    const std::string& ml_label,
                    double ml_confidence) {
  const double raw_spam_side = scores.spam + scores.gibberish;
  double spam_ward_sum = 0.0, ham_ward_sum = 0.0;
  for (const auto& o : offsets) {
    if (!o.fired()) continue;
    if (o.direction == Direction::Spam) spam_ward_sum += o.signed_value();  // >= 0
    else ham_ward_sum += o.signed_value();                                  // <= 0
  }
  auto clamp01 = [](double x) { return x < 0.0 ? 0.0 : (x > 1.0 ? 1.0 : x); };
  const double adjusted = clamp01(raw_spam_side + spam_ward_sum + ham_ward_sum);
  // Counterfactuals: the spam side with each direction's offsets removed, used to
  // test whether the offsets ACTUALLY flipped the outcome (TASK-251).
  const double without_ham_ward = clamp01(raw_spam_side + spam_ward_sum);
  const double without_spam_ward = clamp01(raw_spam_side + ham_ward_sum);

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

  // Counterfactual flip attribution: credit the offsets only when they ACTUALLY
  // changed the side. A rescue counts only if the ham-ward offsets are what pulled
  // an otherwise-spam score under the threshold (without them it would still
  // condemn); a condemn only if the spam-ward offsets are what pushed an otherwise
  // -delivered score over it (without them it would deliver). Without this check a
  // ham offset that fired but didn't move the side got "ham" credit, and a
  // score-driven condemn (raw already over the threshold) wrongly set train_ml=0
  // and suppressed a correct ML sample (TASK-251).
  const bool rescued = ml_said_spam && v.label == "ham" && without_ham_ward >= threshold;
  const bool condemned = !ml_said_spam && v.label == "spam" && without_spam_ward < threshold;
  v.train_ml = !condemned;  // don't feed a header-only (offset-driven) condemn back into ML

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
