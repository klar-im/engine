// Unit tests for the C++ structural decision layer (TASK-179).
//
// decision_layer.h is dependency-free (no model, no llama, no GMime), so this
// is a fast standalone executable — no engine link, no Metal. It pins:
//   1. the calibration constants match the canonical Swift values (the third
//      mirror alongside test_decision_layer_sync.py),
//   2. the derived-offset helpers, and
//   3. golden fold cases that mirror ClassificationService's behaviour
//      (condemn, rescue, clean-keep, clamp, audit/flip attribution).

#include "../decision_layer.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

namespace dl = spam_engine::decision;

namespace {
int g_failures = 0;
int g_checks = 0;

void check(bool cond, const std::string& what) {
  ++g_checks;
  if (!cond) {
    ++g_failures;
    std::printf("  [FAIL] %s\n", what.c_str());
  }
}

bool near(double a, double b) { return std::fabs(a - b) < 1e-9; }

dl::Offset ham(const std::string& id, double m) {
  return dl::Offset{id, m, dl::Direction::Ham};
}
dl::Offset spamward(const std::string& id, double m) {
  return dl::Offset{id, m, dl::Direction::Spam};
}

// ── Constants mirror Swift ClassificationOffsets / thresholds ───────────────
void test_constants() {
  std::printf("[constants mirror Swift]\n");
  check(near(dl::kInReplyTo, 0.20), "inReplyTo == 0.20");
  check(near(dl::kPerReference, 0.05), "perReference == 0.05");
  check(dl::kReferencesCapCount == 3, "referencesCapCount == 3");
  check(near(dl::kPhase2Match, 0.30), "phase2Match == 0.30");
  check(near(dl::kSenderHistoryRepeat, 0.40), "senderHistoryRepeat == 0.40");
  check(near(dl::kSenderHistorySingle, 0.10), "senderHistorySingle == 0.10");
  check(near(dl::kSenderHistoryDomain, 0.05), "senderHistoryDomain == 0.05");
  check(near(dl::kSoftHamRescueCeiling, 0.999),
        "softHamRescueCeiling == 0.999");
  check(near(dl::kSenderAuthFreeHost, 0.99), "senderAuthFreeHost == 0.99");
  check(near(dl::kSenderAuthThrowawaySigner, 0.99), "senderAuthThrowaway == 0.99");
  check(near(dl::kUrlRawIp, 0.30), "urlRawIp == 0.30");
  check(near(dl::kOriginIpDrop, 0.99), "originIpDrop == 0.99");
  check(near(dl::kOriginIpDropHeader, 0.30), "originIpDropHeader == 0.30");
  check(near(dl::kGtubeTest, 0.99), "gtubeTest == 0.99");
  check(dl::kGtubeTest >= dl::kThresholdStandard,
        "GTUBE must condemn on its own, whatever the model thinks of the text");
  check(dl::kOriginIpDropHeader < dl::kThresholdStandard,
        "the header-derived DROP offset cannot reach the gate on its own");
  // kCallbackShape had no assertion here for its whole life; both content
  // offsets have one now, and they are the pair that shows the tiers apart.
  check(near(dl::kCallbackShape, 0.30), "callbackShape == 0.30");
  check(dl::kCallbackShape < dl::kThresholdStandard,
        "the callback shape corroborates: it cannot reach the gate on its own");
  check(near(dl::kNoContactInstruction, 0.99), "noContactInstruction == 0.99");
  check(dl::kNoContactInstruction >= dl::kThresholdStandard,
        "the no-contact instruction CAN carry a message the model likes over the "
        "gate: the genre's model floor is 0.0268, so a corroborating weight would "
        "change no verdict at all. The 0-of-21,291 bound is what licenses it, and "
        "the bounce allowlist is what still holds it back (TASK-460)");
  check(near(dl::kThresholdStandard, 0.99), "threshold standard == 0.99");
  check(near(dl::kThresholdCautious, 0.995), "threshold cautious == 0.995");
}

// Per-artifact spam-side calibration. The gate never moves; the artifact's
// scale is mapped onto it. See decision_layer.h calibrate_spam_side.
void test_spam_side_calibration() {
  std::printf("[spam-side calibration]\n");

  // Undeclared is the identity, in every form an artifact can fail to declare
  // it. public-v0 depends on this: it has never carried a knot.
  for (double const knot : {0.0, -1.0, 1.0, 2.0}) {
    check(near(dl::calibrate_spam_side(0.0, knot), 0.0), "identity at 0");
    check(near(dl::calibrate_spam_side(0.5, knot), 0.5), "identity at 0.5");
    check(near(dl::calibrate_spam_side(0.99, knot), 0.99), "identity at 0.99");
    check(near(dl::calibrate_spam_side(1.0, knot), 1.0), "identity at 1");
  }

  // The whole contract: the declared point lands exactly on the Standard gate,
  // so the calibrated artifact at 0.99 IS the raw artifact at its own knot.
  const double knot = 0.9998;
  check(near(dl::calibrate_spam_side(knot, knot), dl::kThresholdStandard),
        "the knot maps onto the standard gate");
  check(near(dl::calibrate_spam_side(0.0, knot), 0.0), "0 stays 0");
  check(near(dl::calibrate_spam_side(1.0, knot), 1.0), "1 stays 1");

  // Just under the knot must stay under the gate, just over must clear it.
  // Getting this backwards would invert every verdict near the boundary.
  check(dl::calibrate_spam_side(0.9997, knot) < dl::kThresholdStandard,
        "below the knot stays below the gate");
  check(dl::calibrate_spam_side(0.9999, knot) > dl::kThresholdStandard,
        "above the knot clears the gate");

  // Monotone, therefore ranking-preserving, therefore the ROC is unchanged.
  double previous = -1.0;
  for (int i = 0; i <= 1000; ++i) {
    const double raw = static_cast<double>(i) / 1000.0;
    const double mapped = dl::calibrate_spam_side(raw, knot);
    check(mapped >= previous, "calibration is monotone");
    check(mapped >= 0.0 && mapped <= 1.0, "calibration stays in [0,1]");
    previous = mapped;
  }

  // A knot BELOW the gate is legal and pushes scores up, for a successor whose
  // spam side is compressed rather than saturated.
  check(near(dl::calibrate_spam_side(0.5, 0.5), dl::kThresholdStandard),
        "a low knot also lands on the gate");

  // The reason this mechanism exists rather than a per-artifact threshold:
  // GTUBE is pinned to condemn on its own, and it still does under calibration
  // because the gate never moved. A raised gate breaks exactly this.
  dl::Scores clean_ham;
  clean_ham.spam = 0.0;
  clean_ham.gibberish = 0.0;
  clean_ham.regular = 1.0;
  std::vector<dl::Offset> const gtube{
      {"gtube_test", dl::kGtubeTest, dl::Direction::Spam}};
  const dl::Verdict v = dl::fold(clean_ham, gtube, dl::kThresholdStandard,
                                 "regular", 1.0, knot);
  check(v.label == "spam",
        "GTUBE still condemns a clean-scored message under a calibrated artifact");

  // A consumer that folds a calibrated artifact WITHOUT its knot is running a
  // different classifier from the one release qualification measured, and it
  // fails silently: same API, same offsets, plausible score. This pins the
  // difference so the omission is a test failure rather than a field report.
  //
  // spam_engine_classify_full sets spam_side_knot from the loaded model. Any
  // standalone spam_engine_decide caller must do the same; postfix's
  // ModelRuntime::classify does, and TASK-222 covers the Swift and Node folds.
  dl::Scores just_under_the_knot;
  just_under_the_knot.spam = 0.99979;   // above the 0.99 gate on the RAW scale,
  just_under_the_knot.gibberish = 0.0;  // below it once calibrated at 0.9998
  just_under_the_knot.regular = 0.00021;
  const std::vector<dl::Offset> none;
  const dl::Verdict calibrated =
      dl::fold(just_under_the_knot, none, dl::kThresholdStandard, "spam", 0.99979, knot);
  const dl::Verdict uncalibrated =
      dl::fold(just_under_the_knot, none, dl::kThresholdStandard, "spam", 0.99979, 0.0);
  check(calibrated.label == "ham",
        "a calibrated artifact delivers a message below its own knot");
  check(uncalibrated.label == "spam",
        "the same message folded without the knot is condemned instead");
  check(calibrated.label != uncalibrated.label,
        "dropping the knot changes the verdict, so a consumer cannot omit it "
        "and stay in parity with classify_full");
}

void test_free_host() {
  std::printf("[free-host signer set]\n");
  check(dl::is_free_host_signed("web.app"), "web.app is free-host");
  check(dl::is_free_host_signed("firebaseapp.com"), "firebaseapp.com is free-host");
  check(!dl::is_free_host_signed("stripe.com"), "stripe.com is NOT free-host");
  check(!dl::is_free_host_signed(""), "empty is NOT free-host");
  // Mirror count: 7 entries (AuthFeatures.freeHostSigningDomains).
  check(dl::free_host_signing_domains().size() == 7, "7 free-host domains");
}

void test_thread_offset() {
  std::printf("[thread-header offset]\n");
  check(near(dl::thread_header_offset(false, 0), 0.0), "no headers -> 0");
  check(near(dl::thread_header_offset(true, 0), 0.20), "in-reply-to only -> 0.20");
  check(near(dl::thread_header_offset(false, 2), 0.10), "2 refs -> 0.10");
  // Cap: 5 refs -> capped at 3 -> 0.15; + in-reply-to 0.20 = 0.35.
  check(near(dl::thread_header_offset(true, 5), 0.35), "in-reply-to + 5 refs (capped) -> 0.35");
}

void test_sender_auth_offset() {
  std::printf("[sender-auth offset]\n");
  check(near(dl::sender_auth_offset("web.app", false), 0.99), "free-host -> 0.99");
  check(near(dl::sender_auth_offset("evil.example", true), 0.99), "throwaway -> 0.99");
  check(near(dl::sender_auth_offset("stripe.com", false), 0.0), "legit signer -> 0");
  check(near(dl::sender_auth_offset("web.app", true), 0.99), "free-host wins over throwaway (both 0.99)");
}

void test_sender_history() {
  std::printf("[sender-history magnitude]\n");
  check(near(dl::sender_history_magnitude(2, 0), 0.40), "exact>=2 -> 0.40");
  check(near(dl::sender_history_magnitude(1, 0), 0.10), "exact==1 -> 0.10");
  check(near(dl::sender_history_magnitude(0, 1), 0.05), "domain-only -> 0.05");
  check(near(dl::sender_history_magnitude(0, 0), 0.0), "never -> 0");
}

void test_profile_threshold() {
  std::printf("[profile thresholds]\n");
  check(near(dl::threshold_for_profile(dl::Profile::Standard), 0.99), "standard 0.99");
  check(near(dl::threshold_for_profile(dl::Profile::Cautious), 0.995), "cautious 0.995");
  check(near(dl::threshold_for_profile(dl::Profile::Learning), 0.995), "learning 0.995");
}

void test_refine_non_spam() {
  std::printf("[refine non-spam label]\n");
  check(dl::refine_non_spam_label({0.0, 0.7, 0.3, 0.0}) == "marketing", "marketing>regular -> marketing");
  check(dl::refine_non_spam_label({0.0, 0.2, 0.8, 0.0}) == "ham", "regular>=marketing -> ham");
}

// ── Golden fold cases ───────────────────────────────────────────────────────
void test_fold_clean_keep() {
  std::printf("[fold: clean keep]\n");
  // Model kept it, no offsets fire -> not spam, marketing recovered.
  dl::Scores const s{0.0, 0.7, 0.2, 0.05};  // gib, mkt, reg, spam
  auto const v = dl::fold(s, {}, 0.90, "regular", 0.7);
  check(v.label == "marketing", "label marketing");
  check(v.train_ml, "train_ml true");
  check(v.fired.empty(), "no fired offsets");
}

void test_fold_model_spam_kept() {
  std::printf("[fold: model spam, no offsets]\n");
  dl::Scores const s{0.0, 0.0, 0.05, 0.95};
  auto const v = dl::fold(s, {}, 0.90, "spam", 0.95);
  check(v.label == "spam", "stays spam");
  check(near(v.confidence, 0.95), "confidence == adjusted spam side");
  check(v.train_ml, "train_ml true (content condemn)");
}

void test_fold_free_host_condemn() {
  std::printf("[fold: free-host condemn of a leaked promo]\n");
  // Marketing-leak: spam-side ~0.09, model says marketing (not spam-side).
  dl::Scores const s{0.04, 0.91, 0.0, 0.05};
  std::vector<dl::Offset> const offs = {spamward("sender_auth", 0.90)};
  auto v = dl::fold(s, offs, 0.90, "marketing", 0.91);
  check(near(v.adjusted_spam_side, std::min(1.0, 0.09 + 0.90)), "adjusted clamps toward 0.99");
  check(v.label == "spam", "condemned to spam");
  check(!v.train_ml, "train_ml FALSE on header-only condemn");
  check(v.fired.size() == 1, "one fired offset");
  check(v.fired[0].flipped_label == "spam", "sender_auth credited with the flip");
}

void test_fold_raw_ip_corroborates() {
  std::printf("[fold: raw-IP link corroborates a borderline spam over the gate]\n");
  // Model kept it just under the gate (spam-side 0.65, label "regular"); a bare-IP
  // body link pushes it over. The 0.30 offset is what causes the condemn.
  dl::Scores const s{0.0, 0.10, 0.25, 0.65};
  std::vector<dl::Offset> const offs = {spamward("url_raw_ip", dl::kUrlRawIp)};
  auto v = dl::fold(s, offs, 0.90, "regular", 0.55);
  check(near(v.adjusted_spam_side, 0.95), "0.65 + 0.30 = 0.95");
  check(v.label == "spam", "condemned to spam");
  check(!v.train_ml, "train_ml FALSE on offset-driven condemn");
  check(v.fired.size() == 1 && v.fired[0].flipped_label == "spam", "url_raw_ip credited with the flip");
}

void test_fold_connect_ip_drop_solo_condemns() {
  std::printf("[fold: a DROP-listed connecting IP condemns on its own]\n");
  // The deliberate difference from the raw-IP link above: a message the model
  // read as clean (spam-side 0.02) still gets condemned, because the offset is a
  // fact about the peer, not a claim inside attacker-authored content. Mail from
  // a hijacked netblock is not mail we are grading on its merits.
  dl::Scores const s{0.0, 0.08, 0.90, 0.02};
  std::vector<dl::Offset> const offs = {spamward("connect_ip_drop", dl::kOriginIpDrop)};
  auto v = dl::fold(s, offs, dl::kThresholdStandard, "regular", 0.98);
  check(near(v.adjusted_spam_side, 1.0), "0.02 + 0.99 clamps to 1.0");
  check(v.label == "spam", "condemned to spam");
  check(!v.train_ml, "train_ml FALSE on offset-driven condemn");
  check(v.fired.size() == 1 && v.fired[0].flipped_label == "spam",
        "connect_ip_drop credited with the flip");
}

void test_fold_header_ip_drop_cannot_solo_condemn() {
  std::printf("[fold: a header-derived DROP hit corroborates, never solo-condemns]\n");
  // The deliberate contrast with connect_ip_drop: same evidence, worse
  // provenance (it depends on the operator's trusted-relay list, not on the
  // socket), so a clean-scoring message survives it. 0.02 + 0.30 = 0.32.
  dl::Scores const s{0.0, 0.08, 0.90, 0.02};
  std::vector<dl::Offset> const offs = {spamward("header_ip_drop", dl::kOriginIpDropHeader)};
  auto const v = dl::fold(s, offs, dl::kThresholdStandard, "regular", 0.98);
  check(near(v.adjusted_spam_side, 0.32), "0.02 + 0.30 = 0.32");
  check(v.label != "spam", "not condemned");
  check(v.train_ml, "train_ml true (no offset-driven condemn)");
  // ...but it does carry a message the model already put near the gate.
  dl::Scores const near_gate{0.0, 0.10, 0.20, 0.70};
  auto const v2 = dl::fold(near_gate, offs, dl::kThresholdStandard, "regular", 0.60);
  check(v2.label == "spam", "it does carry a near-gate suspicion over");
}

void test_fold_raw_ip_cannot_solo_condemn_clean() {
  std::printf("[fold: raw-IP alone can't flip a clean score over the gate]\n");
  // A clean-ish message (spam-side 0.30) with a lone bare-IP link stays delivered:
  // 0.30 + 0.30 = 0.60 < 0.90. Proves the modest magnitude corroborates only.
  dl::Scores const s{0.0, 0.20, 0.50, 0.30};
  std::vector<dl::Offset> const offs = {spamward("url_raw_ip", dl::kUrlRawIp)};
  auto v = dl::fold(s, offs, 0.90, "regular", 0.70);
  check(near(v.adjusted_spam_side, 0.60), "0.30 + 0.30 = 0.60");
  check(v.label != "spam", "not condemned");
  check(v.train_ml, "train_ml true (no offset-driven condemn)");
  check(v.fired.size() == 1 && v.fired[0].flipped_label.empty(), "no flip credit (decision unchanged)");
}

void test_fold_ham_rescue() {
  std::printf("[fold: ham rescue by sender history]\n");
  // Model says spam (spam-side 0.95) but the user has emailed this sender a lot.
  dl::Scores const s{0.0, 0.0, 0.05, 0.95};
  std::vector<dl::Offset> const offs = {ham("sender_history", 0.40)};
  auto v = dl::fold(s, offs, 0.90, "spam", 0.95);
  check(near(v.adjusted_spam_side, 0.55), "0.95 - 0.40 = 0.55");
  check(v.label == "ham", "rescued to ham");
  check(near(v.confidence, 1.0 - 0.55), "confidence = 1 - adjusted");
  check(v.train_ml, "train_ml true (user-side rescue still trains)");
  check(v.fired.size() == 1 && v.fired[0].flipped_label == "ham", "sender_history credited with rescue");
}

void test_fold_soft_ham_rescue_ceiling() {
  std::printf("[fold: spoofable ham priors stop at the near-certain ceiling]\n");

  // At the ceiling, neither a forged thread header nor a guessed known sender
  // may exonerate what the calibrated model considers near-certain spam.
  dl::Scores const at_ceiling{0.0, 0.0, 0.001, 0.999};
  std::vector<dl::Offset> const spoofable = {
      ham("thread_headers", dl::kInReplyTo),
      ham("sender_history", dl::kSenderHistoryRepeat),
  };
  auto const blocked = dl::fold(at_ceiling, spoofable, dl::kThresholdStandard,
                          "spam", 0.999);
  check(blocked.label == "spam", "near-certain spam stays spam");
  check(near(blocked.adjusted_spam_side, 0.999),
        "blocked priors do not move the score");
  check(blocked.fired.empty(), "blocked priors emit no misleading audit row");

  // Immediately below the ceiling the same priors retain their product value:
  // they are corroborators for borderline false positives, not disabled.
  dl::Scores const below{0.0, 0.0, 0.0011, 0.9989};
  auto const allowed = dl::fold(below, spoofable, dl::kThresholdStandard,
                          "spam", 0.9989);
  check(allowed.label == "ham", "borderline spam-side can still be rescued");
  check(near(allowed.adjusted_spam_side, 0.3989),
        "both allowed priors are applied below the ceiling");
  check(allowed.fired.size() == 2,
        "allowed priors remain visible in the audit trail");

  // The ceiling is evaluated after per-artifact calibration. A raw 0.99 under
  // this knot maps to exactly 0.999 and must therefore be blocked.
  dl::Scores const candidate_scale{0.0, 0.0, 0.01, 0.99};
  auto const calibrated = dl::fold(candidate_scale,
                             {ham("sender_history", dl::kSenderHistoryRepeat)},
                             dl::kThresholdStandard, "spam", 0.99, 0.90);
  check(calibrated.label == "spam", "calibrated ceiling blocks the rescue");
  check(near(calibrated.adjusted_spam_side, 0.999),
        "ceiling reads the product scale, not the candidate raw scale");
}

void test_fold_spamward_no_condemn_when_model_already_spam() {
  std::printf("[fold: spam-ward fires but model already spam -> not a condemn]\n");
  dl::Scores const s{0.0, 0.0, 0.02, 0.98};
  std::vector<dl::Offset> const offs = {spamward("sender_auth", 0.90)};
  auto v = dl::fold(s, offs, 0.90, "spam", 0.98);
  check(v.label == "spam", "spam");
  check(v.train_ml, "train_ml TRUE — model already said spam, not a header-only condemn");
  check(v.fired.size() == 1 && v.fired[0].flipped_label.empty(), "no flip credit (decision unchanged)");
}

void test_fold_condemn_counterfactual_score_already_over() {
  std::printf("[fold: spam-ward fires but raw score already over -> not an offset condemn]\n");
  // Model kept it (label "regular") but the raw spam side is already >= threshold,
  // AND a spam-ward offset also fires. The offset did NOT cause the condemn, so it
  // gets no flip credit and the sample still trains (TASK-251 counterfactual).
  dl::Scores const s{0.45, 0.0, 0.10, 0.50};  // raw spam side 0.95 >= 0.90
  std::vector<dl::Offset> const offs = {spamward("sender_auth", 0.90)};
  auto v = dl::fold(s, offs, 0.90, "regular", 0.55);
  check(v.label == "spam", "condemned to spam (score carried it)");
  check(v.train_ml, "train_ml TRUE (the score, not the offset, condemned it)");
  check(v.fired.size() == 1 && v.fired[0].flipped_label.empty(),
        "spam-ward offset gets NO flip credit (decision unchanged without it)");
}

void test_fold_rescue_counterfactual_score_already_under() {
  std::printf("[fold: ham fires but raw score already under -> not an offset rescue]\n");
  // Model said spam (spam 0.60) but the raw side is already below the 0.90
  // threshold, so it delivers regardless; a small ham offset that also fires did
  // NOT rescue it and must get no flip credit (TASK-251 counterfactual).
  dl::Scores const s{0.0, 0.0, 0.40, 0.60};  // raw spam side 0.60 < 0.90
  std::vector<dl::Offset> const offs = {ham("sender_history", 0.10)};
  auto v = dl::fold(s, offs, 0.90, "spam", 0.60);
  check(v.label == "ham", "delivered as ham (score already under threshold)");
  check(v.fired.size() == 1 && v.fired[0].flipped_label.empty(),
        "ham offset gets NO rescue credit (decision unchanged without it)");
}

void test_fold_clamp_and_zero_offsets() {
  std::printf("[fold: clamp + zero-magnitude offsets skipped]\n");
  dl::Scores const s{0.0, 0.0, 0.0, 1.0};
  // A zero-magnitude offset (disabled signal) must not appear in fired.
  std::vector<dl::Offset> const offs = {ham("thread_headers", 0.0), spamward("sender_auth", 0.90)};
  auto const v = dl::fold(s, offs, 0.90, "spam", 1.0);
  check(near(v.adjusted_spam_side, 1.0), "1.0 + 0.90 clamps to 1.0");
  check(v.fired.size() == 1, "zero-magnitude offset skipped");
}

}  // namespace

int main() {
  test_constants();
  test_free_host();
  test_thread_offset();
  test_sender_auth_offset();
  test_sender_history();
  test_profile_threshold();
  test_spam_side_calibration();
  test_refine_non_spam();
  test_fold_clean_keep();
  test_fold_model_spam_kept();
  test_fold_free_host_condemn();
  test_fold_raw_ip_corroborates();
  test_fold_connect_ip_drop_solo_condemns();
  test_fold_header_ip_drop_cannot_solo_condemn();
  test_fold_raw_ip_cannot_solo_condemn_clean();
  test_fold_ham_rescue();
  test_fold_soft_ham_rescue_ceiling();
  test_fold_spamward_no_condemn_when_model_already_spam();
  test_fold_condemn_counterfactual_score_already_over();
  test_fold_rescue_counterfactual_score_already_under();
  test_fold_clamp_and_zero_offsets();

  std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
