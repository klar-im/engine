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
// FilteringProfileSetting.spamThreshold). model-lab/test_decision_layer_sync.py
// already pins the Swift⇄Python pair; this header is the third mirror and is
// kept in sync by engine/tests/decision_layer_tests.cpp (which asserts the same
// values + golden fold cases the Swift unit tests assert).

#include <cstdint>
#include <set>
#include <string>
#include <vector>


namespace spam_engine::decision {

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
inline constexpr double kSoftHamRescueCeiling = 0.999;  // IRT/references and
                                  // sender history may corroborate a borderline
                                  // score, never exonerate near-certain spam.
                                  // Applied on the artifact-calibrated spam side
                                  // before any structural offset (TASK-358).
inline constexpr double kSenderAuthFreeHost = 0.99;   // free-host DKIM signer
inline constexpr double kSenderAuthThrowawaySigner = 0.99;  // throwaway-shape signer
inline constexpr double kDisplayImpersonation = 0.99;  // spam-ward: From display
                                  // claims a distinctive brand the domain isn't
                                  // (TASK-214) — strong, precision-first (0 ham FP).
                                  // v4 (TASK-283): raised 0.90 -> 0.99 so these
                                  // solo-condemn a ~0-neural phish at the NEW 0.99
                                  // gate (at 0.90 they no longer reached it -> brand
                                  // phish catch fell 78.9%->67.3%). Safe: they fire
                                  // on ~0 ham, so a bigger push only condemns the
                                  // phish they already flagged. Measured recovery +
                                  // 0 new ham FP in eval_brand_gate.py.
inline constexpr double kUrlRawIp = 0.30;  // spam-ward: a body link to a bare IP
                                  // literal (TASK-257). Modest: corroborates, does
                                  // not solo-condemn a clean score. See the URL-
                                  // signals block below for why only this one wired.
inline constexpr double kOriginIpDrop = 0.99;  // spam-ward: the peer that CONNECTED
                                  // sits in a Spamhaus DROP netblock (TASK-113).
                                  // Condemn-capable, and deliberately so: DROP lists
                                  // hijacked and outright rogue networks, and its
                                  // intended use by operators is to null-route them
                                  // entirely — mail from one is not mail we are
                                  // trying to grade. See the block below for the
                                  // measurement and for why only an OBSERVED
                                  // connect IP may set it.
// spam-ward: brand-independent callback phishing (TASK-440). Billing language, a
// callback phone number, no link anywhere, and a sender the receiver could not
// verify. Corroborating, like kUrlRawIp and for the same reason: measured 0 of
// 3,621 real invoices, 0 of 8,000 ordinary messages, and 203 of 7,083
// invoice-shaped trap messages. 0 of 3,621 bounds the false-positive rate at
// roughly 0.08% rather than at zero, so a message must already be near 0.69 from
// the model before this carries it over the gate. The auth condition lives at
// the offset site in spam_engine_c_api.cpp, with the measurement that forced it.
inline constexpr double kCallbackShape = 0.30;

// spam-ward: the bank-advisor scam's second message (TASK-460). An instruction
// NOT to check with your bank, from a sender the receiver could not verify.
//
// THE MAGNITUDE IS DERIVED THE SAME WAY kCallbackShape's IS, and lands somewhere
// else because the evidence is different. Rule of three on a zero count bounds
// the true false-positive rate at 3/N:
//
//   kCallbackShape   0 of  3,621 real invoices     -> bound 0.083%  -> 0.30
//   this             0 of 21,291 real ham messages -> bound 0.0141% -> 0.99
//
// THE DENOMINATOR IS DISTINCT MESSAGES, and getting that wrong was caught in
// review. The first version quoted 25,982, which is the SUM of the census's ham
// rows -- but two of those rows re-scan mailboxes the others already cover, so
// the same messages were counted twice and a repeated observation cannot tighten
// a bound. 21,291 is the distinct ham-labelled population of the four source
// mailboxes (21,325 messages less 34 that carry X-Klar-Label: spam). The census
// now computes and prints that number rather than leaving it to be summed.
//
// A 5.9x tighter bound than the callback shape's, on a predicate that fires ZERO
// times on real mail rather than merely rarely: 0 across the corpus ham panels,
// 0 on the five ham fixtures that are prose ABOUT this scam, and 1 hit in
// 153,806 trap messages, which makes it specific rather than inert. Measured 9/9
// on an authored family that varies bank, language and phrasing.
//
// 0.30 was not an option here, and that is the point of stating the arithmetic.
// The model floor on this genre is 0.0268, so any magnitude below ~0.963 leaves
// the message delivered: a corroborating weight would have shipped a signal that
// changes no verdict at all. The choice was 0.99 or nothing, and the bound is
// what makes 0.99 defensible.
//
// IT STILL MAY NOT AUTHORIZE A BOUNCE. `condemn_offset_fired` is a NAMED
// ALLOWLIST in spam_engine_c_api.cpp and this id is deliberately absent from it:
// a body-text predicate may junk a message but must never authorize a
// destructive REJECT. Asserted by a negative case in
// test_authoritative_condemn_allowlist. The auth condition lives at the offset
// site with the measurement that justified it.
inline constexpr double kNoContactInstruction = 0.99;

inline constexpr double kGtubeTest = 0.99;  // spam-ward: the GTUBE test string.
                                  // Not a heuristic and not measured against a
                                  // corpus, because the string is DEFINED to
                                  // never appear in real mail. See the block
                                  // below.
inline constexpr double kOriginIpDropHeader = 0.30;  // spam-ward: a DROP-listed
                                  // origin recovered from the Received chain
                                  // behind a TRUSTED relay (TASK-387). The weak
                                  // sibling of kOriginIpDrop: same evidence, worse
                                  // provenance, so it corroborates and can never
                                  // solo-condemn. See the block below.
inline constexpr double kAttachmentDisguisedExecutableExperimental = 0.99;
                                  // spam-ward: executable/script bytes presented
                                  // as a harmless file, direct or one archive
                                  // level down. Default-off experiment (TASK-347).
                                  // It may junk but is deliberately NOT an
                                  // authoritative SMTP-reject signal.
inline constexpr double kAttachmentDangerousTypeExperimental = 0.30;
                                  // spam-ward: plainly named executable/script.
                                  // Developer/IT mail can carry one legitimately,
                                  // so this only corroborates the model.
inline constexpr double kSenderAuthEstablishedBrand = 0.15;  // ham-ward: Tranco
                                  // brand / clean-ESP DKIM signer (TASK-170)
inline constexpr double kBrandReputationCeiling = 0.999;  // don't rescue a spam-side
                                  // at/above this (a near-certain spam from a
                                  // popular-but-abused domain must not be exonerated)
inline constexpr double kKbBrandDmarcPass = 0.90;  // ham-ward: receiver-verified
                                  // dmarc=pass From a curated KB brand's own sending
                                  // domain (TASK-337/334). Strong (mirror of the 0.90
                                  // condemns) and deliberately NOT ceiling-gated: the
                                  // transactional FPs it exists to rescue sit at
                                  // 0.97-0.999 where the -0.15 nudge is invisible.
                                  // Forging the precondition means passing DMARC as
                                  // the brand itself. Measured on real AR-stamped
                                  // mail: 203 FP rescued / 0 caught spam lost
                                  // (2,203 ham + 693 junk candidates, 2026-07-23)

// ── Structural URL signals (TASK-257): only raw_ip_url wired ────────────────
// Three candidates were built + ablated against this model on the real 739-spam /
// 56-ham corpus, both gates (0.90 standard, 0.95 learning) x both modes (neural,
// ensemble), rule-of-three CIs (model-lab/scripts/measure_url_structure.py).
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

// ── Origin-IP reputation (TASK-113): Spamhaus DROP, measured 2026-07-30 ────
// The DNSBL-class layer every server-side filter has and we did not: the milter
// ignored the connection entirely and graded only content. Lookup is offline
// against a 14 kB bundled artifact (ip_blocklist.h), so it adds no per-message
// DNS and stays inside the "nothing leaves the device" constraint.
//
// MEASURED on the real corpus (scripts/measure_ip_blocklist.py, today's DROP vs
// every message carrying a Received hop):
//   spam      167,124 msgs with an origin IP -> 5,426 hits = 3.25%
//   marketing   3,893 msgs (real ESP mail to klar.im) -> 0 hits = 0.000%
//   quarantine    101 msgs (real inbound to klar.im)  -> 0 hits = 0.000%
// So: a free 3.25% recall slice on top of the model, at zero measured FP. The
// 3.25% is a FLOOR for live mail — the corpus spans 2018-2026 while DROP lists
// what is hijacked TODAY, so historical spam whose netblocks were since delisted
// cannot be counted. Two honest limits: the ham sample with intact Received
// headers is small (3,994) because our large ham sets (debian archives, enron)
// were shipped header-stripped, and untroubled keeps Received on only ~70% of
// messages.
//
// WHY CONDEMN-CAPABLE (0.99, so it alone crosses the standard gate and sets
// condemn_offset_fired) when the comparable raw-IP-URL tell got 0.30: the raw-IP
// URL is a CLAIM inside attacker-authored content, whereas this is a fact the
// receiving MTA observed about the TCP peer, on a list whose whole purpose is
// "do not route or peer with this network". Rejecting it is milder than what
// DROP is normally used for. The magnitude is only sound while the input is
// sound, hence:
//
// ONLY AN OBSERVED CONNECT IP MAY SET IT. A milter passes its xxfi_connect
// address. An IP parsed out of a Received header must NOT be fed here: every
// hop below the accepting MTA's own line is attacker-written, so a spammer could
// forge a DROP-listed hop and get its own mail condemned — harmless — but the
// same forgery on a REPLY or a mailing-list post is a way to weaponise the
// offset against third-party mail. A header-derived variant needs its own,
// weaker, corroborating magnitude and its own measurement.
//
// NO SWIFT MIRROR, deliberately: this is the one constant here with no
// ClassificationOffsets.swift twin, because the Mail extension reads mail the
// user's provider already accepted and never sees a connecting IP. It is
// therefore absent from test_decision_layer_sync.py's pair list by design, not
// by omission. It becomes a mirror only if a header-derived variant ships, and
// that variant needs its own weaker magnitude (see above).
//
// ── Header-sanity candidates: MEASURED AND REJECTED (TASK-391) ─────────────
// Stalwart's spam filter carries a catalogue of structural header tags
// (analysis/date.rs, messageid.rs, headers.rs). They are offline, cheap, and
// exactly the shape this layer likes, so all of them were measured against our
// corpus before wiring any (scripts/measure_header_structure.py, full run:
// 3,893 marketing + 111 quarantine real inbound, 56,154 debian, 239,647 spam).
// NONE were wired, and the numbers say why:
//
//   signal                 real-ham        spam     verdict
//   NO_SENDER_MID           0.5%   (18)    5.7%     fires on legit mail
//   INVALID_MSGID           0.1%    (4)   13.6%     fires on legit mail
//   MID_BARE_IP             0.7%   (27)    0.2%     INVERTED: more ham than spam
//   MID_RHS_NOT_FQDN       14.7%  (572)    4.8%     INVERTED, and common ham
//   MULTIPLE_UNIQUE_HEADERS 0%      (0)    0.03%    clean but ~no recall
//   DUP_FROM / DUP_SUBJECT  0%      (0)    0%       never occurs at all
//
// Two things this measurement bought, neither of which was obvious in advance:
//
// 1. A CORPUS TRAP. "Missing Message-ID" first measured 0% on ham and looked
//    shippable at 5.7% spam recall. It is wrong: receiving MTAs SYNTHESISE a
//    Message-ID when one is absent, so a delivered corpus cannot see the header
//    the sender omitted. Ours stamps its own hostname, which is how the true
//    rate was recovered — 18 legitimate messages, 0.5%, arrived without one.
//    Same trap applies to MISSING_DATE, which is why it is not listed as clean
//    either. Any future header-absence signal has to be measured at the MTA, not
//    on delivered mail.
// 2. TWO SIGNALS ARE INVERTED FOR OUR MAIL MIX. A bare-IP or non-FQDN
//    Message-ID right-hand side is more common in our legitimate marketing mail
//    (ESP infrastructure) than in our spam. Adopting the catalogue on reputation
//    would have added two ham-ward-firing signals as spam-ward pushes.
//
// The one clean signal (duplicated unique headers) is not wired because in
// 239,647 spam messages it fires 61 times and NEVER on From or Subject — the
// display-inconsistency attack it exists to catch does not occur in our mail. It
// is cheap to revisit if that changes; the harness is committed.

// ── GTUBE (TASK-391) ───────────────────────────────────────────────────────
// The anti-spam equivalent of EICAR: a fixed string every filter agrees to treat
// as spam, so an operator can prove a filter is live end-to-end without crafting
// real spam and without waiting for some to arrive. We had no support for it,
// which meant the only way to test a deployment was to send something that
// happened to score high — a test that silently stops testing the moment the
// model changes its mind.
//
// Condemn-capable (0.99) by DEFINITION rather than by measurement: there is no
// corpus rate to quote because the string's whole purpose is that it never occurs
// naturally. The matching is exact and case-sensitive for the same reason a
// looser match would be wrong: mail DISCUSSING the test (an operator's own setup
// thread, this repository's documentation) must not be junked. The engine's own
// source stores it in two halves so a scanner reading our tree does not trip.
//
// WHY THE FOLD AND NOT A PRE-FILTER, since "why run a 400 MB model on a message
// we already know the answer for?" is the obvious refactor: because the whole
// POINT of GTUBE is proving the pipeline is live end-to-end. A short-circuit
// before scoring would skip preprocess -> embed -> ensemble -> fold and prove
// only that the short-circuit works, which is the one thing nobody needed
// verified. Running the real path and condemning at the fold is what makes the
// liveness claim true. It also keeps the explainability machinery intact
// (fired_offsets, condemn_offset_fired) that every consumer now reads. The
// latency argument is empty: the population is operators running a check, so
// there is nothing to optimise. A pre-filter precedent does exist in the tree
// (spam_engine.cpp's mode=="ftrl" path), and is deliberately not followed here.
//
// ── The header-derived sibling (TASK-387) ──────────────────────────────────
// A milter behind a relay never sees the internet: our own staging MX is exactly
// that shape (Stalwart owns :25 and relays into the Postfix pod, so xxfi_connect
// reports the podman bridge gateway 10.88.0.1) and the offset above is inert
// there. The origin then exists only in the Received chain, so kOriginIpDropHeader
// covers that deployment — and ONLY that deployment: it fires solely when the
// connecting peer is itself a configured trusted relay, walking down while each
// recorded hop is ours and taking the first that is not. That address was written
// by a host the operator trusts, which is what separates it from "some header
// said so".
//
// WHY 0.30 AND NOT 0.99: the evidence is identical, the provenance is not. The
// observed-IP version cannot be wrong about who connected; this one is only as
// good as the operator's trusted_relay_cidrs list, and a misconfiguration turns
// an attacker-written Received line into a condemn. So it corroborates a
// model-side suspicion and never carries a clean message over the gate on its
// own — the same reasoning, and the same magnitude, as the raw-IP-URL tell.
// Everything BELOW the first untrusted hop is attacker-writable and is never
// read, which is what stops a forged hop on a reply or a list post from
// condemning third-party mail.
//
// NOT BUILT — ASN-DROP: checking it needs an IP->ASN map (a full BGP table) we
// neither carry nor will fetch per message. NOT BUILT — ZEN/DBL/URIBL: free only
// for non-commercial low volume under Spamhaus's Fair Use Policy, so they are a
// paid-Datafeed decision, not a code change (see TASK-113).

// ── Filtering-profile thresholds — mirror FilteringProfileSetting.swift ─────
inline constexpr double kThresholdStandard = 0.99;  // successor (TASK-283): the
                                  // XLM-R-base markers model fires at its true
                                  // calibration once fed the training representation
                                  // (see build_normalized_text), so it is high-recall
                                  // AND non-trivial-FP. The FP-first knee is 0.99/0.995:
                                  // gate sweep (scripts/sweep_standard_gate.py) 87.8%
                                  // recall @ 2.3% personal-ham FP vs 90.0% @ 3.1% at
                                  // 0.90 — 0.99 wins every FP panel for -2.2pp recall.
inline constexpr double kThresholdCautious = 0.995;  // also forced while "learning"

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
  if (dkim_signing_org_domain.empty()) { { return false;
}
}
  const auto& set = free_host_signing_domains();
  return set.find(dkim_signing_org_domain) != set.end();
}

// Shared sender platforms: free webmail + publishing/newsletter hosts. These are
// "established" domains (popular, DMARC-aligned to themselves) yet ANY third party
// can send brand-looking mail from them, so aligning to one is NOT evidence the
// sender owns a brand. Used to exclude them from the impersonation auth-reputation
// exemption ("PayPal" from a gmail.com / blogspot.com account is still a spoof).
inline bool is_shared_sender_platform(const std::string& org_domain) {
  // Regional/global consumer webmail + publishing platforms, researched
  // 2026-08-31 (clean.email/sellcell/smtpedia rankings) to widen past the
  // English-market-only original set. Deliberately NOT identical to
  // ClassificationService.swift's `sharedSenderPlatformDomains`: some ISP
  // domains (French: free.fr, orange.fr, laposte.net, sfr.fr; German:
  // t-online.de) are BOTH shared consumer mailboxes AND curated brands that
  // send their own legitimate DMARC-aligned mail from that same domain
  // (TASK-439: adding free.fr here once already stripped the brand exemption
  // from a real "Free Mobile" <noreply@free.fr>, caught only by legit_fp_
  // cases.jsonl's multi-word own-subdomain cases -- see gen_legit_fp_
  // cases.py; t-online.de/"Telekom" reproduced it again, 2026-09-01,
  // caught by brand_impersonation_synth.jsonl's sibling-domain class under
  // KLAR_SYNTH=1, 2/29 false positives). They stay OUT of this predicate but
  // are correctly IN the Swift set, which has no brand-exemption dependency.
  // model-lab/test_decision_layer_sync.py verifies the two sets differ by
  // EXACTLY the documented gap, in either direction.
  static const std::set<std::string> kShared = {
      // Global.
      "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
      "msn.com", "yahoo.com", "yahoo.fr", "yahoo.co.uk", "ymail.com",
      "rocketmail.com", "aol.com", "icloud.com", "me.com", "mac.com",
      "proton.me", "protonmail.com", "pm.me", "tutanota.com", "tuta.com",
      "fastmail.com", "zoho.com",
      // Germany: NOT t-online.de -- see comment above.
      "gmx.com", "gmx.net", "gmx.de", "gmx.at", "mail.com", "web.de",
      "freenet.de",
      // France: NOT free.fr/orange.fr/laposte.net/sfr.fr -- see comment above.
      // Italy.
      "libero.it", "virgilio.it",
      // Brazil.
      "uol.com.br", "terra.com.br", "bol.com.br",
      // Poland.
      "interia.pl", "wp.pl", "o2.pl",
      // Czech Republic.
      "seznam.cz", "centrum.cz",
      // Russia / CIS.
      "yandex.com", "yandex.ru", "yandex.ua", "mail.ru", "inbox.ru", "list.ru",
      "bk.ru", "rambler.ru",
      // China.
      "qq.com", "126.com", "163.com", "sina.com", "sohu.com", "foxmail.com",
      // Korea.
      "naver.com", "daum.net",
      // Publishing / newsletter hosts.
      "blogspot.com", "wordpress.com", "medium.com", "substack.com",
      "beehiiv.com", "ghost.io", "tumblr.com",
  };
  return kShared.find(org_domain) != kShared.end();
}

// ── Derived offset magnitudes (from the engine's own parse) ─────────────────

// Thread-header ham prior: in-reply-to presence + capped References count.
// Mirrors ThreadFeatures.spamConfidenceOffset.
inline double thread_header_offset(bool has_in_reply_to, int references_count) {
  double offset = 0.0;
  if (has_in_reply_to) { { offset += kInReplyTo;
}
}
  const int capped = references_count < kReferencesCapCount
                         ? references_count : kReferencesCapCount;
  if (capped > 0) { { offset += static_cast<double>(capped) * kPerReference;
}
}
  return offset;
}

// Sender-auth spam-ward push: free-host signer first, else throwaway-shape.
// Mirrors AuthFeatures.spamConfidenceOffset.
inline double sender_auth_offset(const std::string& dkim_signing_org_domain,
                                 bool signer_throwaway) {
  if (is_free_host_signed(dkim_signing_org_domain)) { { return kSenderAuthFreeHost;
}
}
  if (signer_throwaway) { { return kSenderAuthThrowawaySigner;
}
}
  return 0.0;
}

// Graded sender-history ham prior. Caller supplies send counts from its local
// DB (the engine has no contacts store). Mirrors senderHistoryMagnitude().
inline double sender_history_magnitude(int exact_send_count, int domain_send_count) {
  if (exact_send_count >= 2) { { return kSenderHistoryRepeat;
}
}
  if (exact_send_count == 1) { { return kSenderHistorySingle;
}
}
  return domain_send_count >= 1 ? kSenderHistoryDomain : 0.0;
}

// Profile threshold. `learning` forces the cautious threshold (mirror
// SharedSettings.spamThreshold's learning-clause).
enum class Profile : std::uint8_t { Standard, Cautious, Learning };
// ── Per-artifact spam-side calibration ──────────────────────────────────────
//
// A successor encoder's scores do not sit where public-v0's sit. Measured on the
// clean e5 candidate: at the shipping 0.99 gate it costs 229/5,122 aggregate ham
// false positives against public-v0's 159, and it needs roughly 0.9998 to reach
// the same false-positive count.
//
// Raising kThresholdStandard to meet it is not available. Five offsets are
// pinned to EXACTLY 0.99 so that each alone crosses the gate: kGtubeTest,
// kSenderAuthFreeHost, kSenderAuthThrowawaySigner, kDisplayImpersonation,
// kOriginIpDrop. Move the gate up and all five stop condemning. Rebuilding
// decision_layer_tests against kThresholdStandard = 0.9998 fails on exactly
// that: "GTUBE must condemn on its own, whatever the model thinks of the text".
// A GTUBE message that is not spam defeats the only purpose GTUBE has.
//
// So the artifact declares where ITS spam side sits and the engine maps that
// point onto the product's fixed gate: two linear segments through (0,0),
// (knot, kThresholdStandard), (1,1). The map is monotone, so ranking and
// therefore the ROC are untouched — the calibrated model at 0.99 IS the raw
// model at `knot`. What it buys is that every offset magnitude, the FTRL blend,
// the Cautious profile, FilteringProfileSetting.swift and the user-facing word
// "Standard" keep meaning what they already mean.
//
// The knot is SELECTED, never guessed: model-lab/scripts/select_operating_point.py
// takes the smallest grid threshold whose false-positive count on a
// training-and-panel-disjoint tuning set matches what the shipping baseline
// already costs. See HOW_TO_TRAIN_A_MODEL.md, "Move the score, not the gate".
//
// knot <= 0 or >= 1 means "not declared" and yields the identity, which is what
// public-v0 has always had and must keep having.
inline double calibrate_spam_side(double raw_spam_side, double knot) {
  if (!(knot > 0.0) || !(knot < 1.0)) { { return raw_spam_side;
}
}
  if (raw_spam_side <= 0.0) { { return 0.0;
}
}
  if (raw_spam_side >= 1.0) { { return 1.0;
}
}
  if (raw_spam_side <= knot) {
    return raw_spam_side * (kThresholdStandard / knot);
  }
  return kThresholdStandard +
         ((raw_spam_side - knot) * ((1.0 - kThresholdStandard) / (1.0 - knot)));
}

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

enum class Direction : std::uint8_t { Ham, Spam };

// One structural offset. Mirrors StructuralOffset.swift.
struct Offset {
  std::string classifier_id;  // "thread_headers" | "thread_history" |
                              // "sender_history" | "sender_auth"
  double magnitude = 0.0;     // unsigned weight (>= 0); 0 == did not fire
  Direction direction = Direction::Ham;

  [[nodiscard]] double signed_value() const {
    return direction == Direction::Spam ? magnitude : -magnitude;
  }
  [[nodiscard]] bool fired() const { return magnitude > 0.0; }
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
  // The spam side after calibrate_spam_side and before any offset: what the
  // fold actually starts from. Reported so a caller can attribute a verdict to
  // a layer without re-deriving the calibration and drifting from it.
  double calibrated_spam_side = 0.0;
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
  if (s.gibberish > 0.7F) { { return {"spam", s.gibberish};
}
}
  if (s.spam < 0.2F && s.regular > 0.5F) { { return {"regular", 1.0 - s.spam};
}
}
  if (s.spam > 0.5F) { { return {"spam", s.spam};
}
}
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
                    double ml_confidence,
                    double spam_side_knot = 0.0) {
  const double raw_spam_side =
      calibrate_spam_side(scores.spam + scores.gibberish, spam_side_knot);
  const auto offset_allowed = [raw_spam_side](const Offset& o) {
    if (o.direction != Direction::Ham || raw_spam_side < kSoftHamRescueCeiling) {
      return true;
    }
    // These two priors are cheap and spoofable: an attacker can forge thread
    // headers or a From address that happens to be in local sender history.
    // The bypass-resistant thread_history lookup and authenticated KB-brand
    // rescue have stronger preconditions and intentionally retain their own
    // policies.
    return o.classifier_id != "thread_headers" &&
           o.classifier_id != "sender_history";
  };
  double spam_ward_sum = 0.0;
  double ham_ward_sum = 0.0;
  for (const auto& o : offsets) {
    if (!o.fired() || !offset_allowed(o)) { { continue;
}
}
    if (o.direction == Direction::Spam) { { spam_ward_sum += o.signed_value();  // >= 0
    } } else { { ham_ward_sum += o.signed_value();                                  // <= 0
}
}
  }
  auto const clamp01 = [](double x) { return x < 0.0 ? 0.0 : (x > 1.0 ? 1.0 : x); };
  const double adjusted = clamp01(raw_spam_side + spam_ward_sum + ham_ward_sum);
  // Counterfactuals: the spam side with each direction's offsets removed, used to
  // test whether the offsets ACTUALLY flipped the outcome (TASK-251).
  const double without_ham_ward = clamp01(raw_spam_side + spam_ward_sum);
  const double without_spam_ward = clamp01(raw_spam_side + ham_ward_sum);

  const bool ml_said_spam = (ml_label == "spam" || ml_label == "gibberish");

  Verdict v;
  v.adjusted_spam_side = adjusted;
  v.calibrated_spam_side = raw_spam_side;
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
    if (!o.fired() || !offset_allowed(o)) { { continue;
}
}
    FiredOffset f;
    f.classifier_id = o.classifier_id;
    f.magnitude = o.magnitude;
    f.direction = o.direction;
    if (o.direction == Direction::Ham && rescued) { { f.flipped_label = "ham";
    } } else if (o.direction == Direction::Spam && condemned) { { f.flipped_label = "spam";
}
}
    v.fired.push_back(f);
  }
  return v;
}

} // namespace spam_engine::decision
