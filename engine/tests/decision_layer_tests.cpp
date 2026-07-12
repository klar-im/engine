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
  check(near(dl::kSenderAuthFreeHost, 0.90), "senderAuthFreeHost == 0.90");
  check(near(dl::kSenderAuthThrowawaySigner, 0.90), "senderAuthThrowaway == 0.90");
  check(near(dl::kUrlRawIp, 0.30), "urlRawIp == 0.30");
  check(near(dl::kThresholdStandard, 0.90), "threshold standard == 0.90");
  check(near(dl::kThresholdCautious, 0.95), "threshold cautious == 0.95");
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
  check(near(dl::sender_auth_offset("web.app", false), 0.90), "free-host -> 0.90");
  check(near(dl::sender_auth_offset("evil.example", true), 0.90), "throwaway -> 0.90");
  check(near(dl::sender_auth_offset("stripe.com", false), 0.0), "legit signer -> 0");
  check(near(dl::sender_auth_offset("web.app", true), 0.90), "free-host wins over throwaway (both 0.90)");
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
  check(near(dl::threshold_for_profile(dl::Profile::Standard), 0.90), "standard 0.90");
  check(near(dl::threshold_for_profile(dl::Profile::Cautious), 0.95), "cautious 0.95");
  check(near(dl::threshold_for_profile(dl::Profile::Learning), 0.95), "learning 0.95");
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
  dl::Scores s{0.0, 0.7, 0.2, 0.05};  // gib, mkt, reg, spam
  auto v = dl::fold(s, {}, 0.90, "regular", 0.7);
  check(v.label == "marketing", "label marketing");
  check(v.train_ml, "train_ml true");
  check(v.fired.empty(), "no fired offsets");
}

void test_fold_model_spam_kept() {
  std::printf("[fold: model spam, no offsets]\n");
  dl::Scores s{0.0, 0.0, 0.05, 0.95};
  auto v = dl::fold(s, {}, 0.90, "spam", 0.95);
  check(v.label == "spam", "stays spam");
  check(near(v.confidence, 0.95), "confidence == adjusted spam side");
  check(v.train_ml, "train_ml true (content condemn)");
}

void test_fold_free_host_condemn() {
  std::printf("[fold: free-host condemn of a leaked promo]\n");
  // Marketing-leak: spam-side ~0.09, model says marketing (not spam-side).
  dl::Scores s{0.04, 0.91, 0.0, 0.05};
  std::vector<dl::Offset> offs = {spamward("sender_auth", 0.90)};
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
  dl::Scores s{0.0, 0.10, 0.25, 0.65};
  std::vector<dl::Offset> offs = {spamward("url_raw_ip", dl::kUrlRawIp)};
  auto v = dl::fold(s, offs, 0.90, "regular", 0.55);
  check(near(v.adjusted_spam_side, 0.95), "0.65 + 0.30 = 0.95");
  check(v.label == "spam", "condemned to spam");
  check(!v.train_ml, "train_ml FALSE on offset-driven condemn");
  check(v.fired.size() == 1 && v.fired[0].flipped_label == "spam", "url_raw_ip credited with the flip");
}

void test_fold_raw_ip_cannot_solo_condemn_clean() {
  std::printf("[fold: raw-IP alone can't flip a clean score over the gate]\n");
  // A clean-ish message (spam-side 0.30) with a lone bare-IP link stays delivered:
  // 0.30 + 0.30 = 0.60 < 0.90. Proves the modest magnitude corroborates only.
  dl::Scores s{0.0, 0.20, 0.50, 0.30};
  std::vector<dl::Offset> offs = {spamward("url_raw_ip", dl::kUrlRawIp)};
  auto v = dl::fold(s, offs, 0.90, "regular", 0.70);
  check(near(v.adjusted_spam_side, 0.60), "0.30 + 0.30 = 0.60");
  check(v.label != "spam", "not condemned");
  check(v.train_ml, "train_ml true (no offset-driven condemn)");
  check(v.fired.size() == 1 && v.fired[0].flipped_label.empty(), "no flip credit (decision unchanged)");
}

void test_fold_ham_rescue() {
  std::printf("[fold: ham rescue by sender history]\n");
  // Model says spam (spam-side 0.95) but the user has emailed this sender a lot.
  dl::Scores s{0.0, 0.0, 0.05, 0.95};
  std::vector<dl::Offset> offs = {ham("sender_history", 0.40)};
  auto v = dl::fold(s, offs, 0.90, "spam", 0.95);
  check(near(v.adjusted_spam_side, 0.55), "0.95 - 0.40 = 0.55");
  check(v.label == "ham", "rescued to ham");
  check(near(v.confidence, 1.0 - 0.55), "confidence = 1 - adjusted");
  check(v.train_ml, "train_ml true (user-side rescue still trains)");
  check(v.fired.size() == 1 && v.fired[0].flipped_label == "ham", "sender_history credited with rescue");
}

void test_fold_spamward_no_condemn_when_model_already_spam() {
  std::printf("[fold: spam-ward fires but model already spam -> not a condemn]\n");
  dl::Scores s{0.0, 0.0, 0.02, 0.98};
  std::vector<dl::Offset> offs = {spamward("sender_auth", 0.90)};
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
  dl::Scores s{0.45, 0.0, 0.10, 0.50};  // raw spam side 0.95 >= 0.90
  std::vector<dl::Offset> offs = {spamward("sender_auth", 0.90)};
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
  dl::Scores s{0.0, 0.0, 0.40, 0.60};  // raw spam side 0.60 < 0.90
  std::vector<dl::Offset> offs = {ham("sender_history", 0.10)};
  auto v = dl::fold(s, offs, 0.90, "spam", 0.60);
  check(v.label == "ham", "delivered as ham (score already under threshold)");
  check(v.fired.size() == 1 && v.fired[0].flipped_label.empty(),
        "ham offset gets NO rescue credit (decision unchanged without it)");
}

void test_fold_clamp_and_zero_offsets() {
  std::printf("[fold: clamp + zero-magnitude offsets skipped]\n");
  dl::Scores s{0.0, 0.0, 0.0, 1.0};
  // A zero-magnitude offset (disabled signal) must not appear in fired.
  std::vector<dl::Offset> offs = {ham("thread_headers", 0.0), spamward("sender_auth", 0.90)};
  auto v = dl::fold(s, offs, 0.90, "spam", 1.0);
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
  test_refine_non_spam();
  test_fold_clean_keep();
  test_fold_model_spam_kept();
  test_fold_free_host_condemn();
  test_fold_raw_ip_corroborates();
  test_fold_raw_ip_cannot_solo_condemn_clean();
  test_fold_ham_rescue();
  test_fold_spamward_no_condemn_when_model_already_spam();
  test_fold_condemn_counterfactual_score_already_over();
  test_fold_rescue_counterfactual_score_already_under();
  test_fold_clamp_and_zero_offsets();

  std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
