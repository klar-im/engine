#pragma once

// Display-name brand-impersonation detection (TASK-214), the spam-side use of
// the Tranco data. A From DISPLAY NAME that claims a distinctive brand (the stem
// of a popular Tranco domain, e.g. "Scaleway", "PayPal") while the From org-domain
// is NOT that brand is the #1 phishing tell a human uses and the engine otherwise
// ignores. Companion to brand_reputation.h (the ham-side rescue).
//
// The brand set (brand_names_data.h, generated) is split into two tiers (doc-12):
//   Tier-1, distinctive coined stems (NOT dictionary words: Scaleway, PayPal).
//            A match is high-confidence, so it condemns standalone (TASK-214).
//   Tier-2, stems that ARE dictionary words (Decathlon, Orange, Apple). The word
//            has a large legit non-brand population ("Orange County"), so a match
//            is low-confidence: it only counts when the display has the
//            impersonation SHAPE (brand + role words, nothing distinctive left)
//            AND the caller corroborates it with an independent spam signal.
// Membership is exact (FNV-1a + binary search). No Swift copy, Swift reads the
// engine-computed `display_impersonation` boolean over the C ABI.

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "brand_names_data.h"
#include "fnv1a.h"

namespace spam_engine {
namespace brand_names {

// Exact membership of t in a null-free static word list.
inline bool in_word_list(const std::string& t, const char* const* list, std::size_t n);

// Curated SHORT brands (exactly 3 chars): the few high-value brands below the
// len>=4 noise floor that the generated Tranco set drops for precision. DHL is the
// top delivery impersonation target (huge in DE), SFR a major French telecom. The
// stem must NOT appear in a common multi-word English phrase: the shape gate floors
// leftovers at len>=4, so a 3-char companion ("Sit Ups", "Press Ups") would not
// break the shape and the brand would FP. That rules out "ups"; "dhl"/"sfr" have no
// such phrase. Treated as Tier-2: fires only with impersonation shape +
// corroboration, never standalone.
inline bool is_short_brand(const std::string& t) {
  static const char* const kShort[] = {"dhl", "sfr"};
  return in_word_list(t, kShort, sizeof(kShort) / sizeof(kShort[0]));
}

// 0 = not a brand, 1 = Tier-1 (distinctive), 2 = Tier-2 (dictionary word / curated
// short brand). Short brands are Tier-2: a 3-char match is high-ambiguity, so it
// needs the impersonation shape + a corroborating signal downstream.
inline int brand_tier(const std::string& stem) {
  if (stem.size() == 3) return is_short_brand(stem) ? 2 : 0;
  if (stem.size() < 4) return 0;
  const std::uint64_t h = fnv1a_lower(stem);
  if (std::binary_search(kBrandNameHashes, kBrandNameHashes + kBrandNameHashesCount, h)) return 1;
  if (std::binary_search(kBrandNameHashesT2, kBrandNameHashesT2 + kBrandNameHashesT2Count, h)) return 2;
  return 0;
}

// Exact membership of t in a null-free static word list.
inline bool in_word_list(const std::string& t, const char* const* list, std::size_t n) {
  for (std::size_t i = 0; i < n; ++i) {
    if (t == list[i]) return true;
  }
  return false;
}

// Generic mail/account role words. A Tier-2 brand keeps the impersonation SHAPE
// when every other display token is one of these (or short / owned / itself a
// brand), i.e. the display is "just the brand, maybe with roles". A distinctive
// leftover ("Valley", "County", "Wildlife") breaks the shape -> not impersonation.
inline bool is_role_word(const std::string& t) {
  static const char* const kRoles[] = {
      "support", "account", "accounts", "security", "secure", "billing", "team",
      "service", "services", "notification", "notifications", "alert", "alerts",
      "help", "info", "customer", "care", "update", "updates", "login", "signin",
      "verification", "verify", "payment", "payments", "order", "orders", "noreply",
      "official", "online", "store", "shop", "group", "mail", "email", "news",
      // French role words (primary market): compte=account, securite=security,
      // paiement=payment, commande=order, facture=invoice, livraison=delivery,
      // commentaires=reviews, assistance/aide=support, alerte=alert.
      "compte", "comptes", "securite", "paiement", "paiements", "commande",
      "commandes", "facture", "factures", "livraison", "commentaires",
      "assistance", "aide", "alerte", "alertes", "confidentialite", "abonnement",
      // German role words: konto=account, sicherheit=security, zahlung=payment,
      // bestellung=order, rechnung=invoice, lieferung/versand=delivery,
      // kundendienst=support, benachrichtigung=notification, anmeldung=login.
      "konto", "konten", "sicherheit", "zahlung", "zahlungen", "bestellung",
      "bestellungen", "rechnung", "rechnungen", "lieferung", "versand",
      "kundendienst", "kundenservice", "benachrichtigung", "anmeldung", "passwort",
      "bestaetigung", "aktualisierung", "hilfe"};
  return in_word_list(t, kRoles, sizeof(kRoles) / sizeof(kRoles[0]));
}

// Corporate / regional name-parts. A real multi-word brand name ("Fidelity
// International", "Manning Publications", "Austrian Airlines", "Otter Insights")
// keeps the impersonation SHAPE: the continuation is part of the brand's own name,
// not a distinctive qualifier. This is deliberately disjoint from the place-name /
// generic vocabulary the gate must still break on ("County", "Valley", "Lake",
// "Trivia"), a brand + corporate-part is the brand; a brand + place is a namesake.
inline bool is_brand_continuation(const std::string& t) {
  static const char* const kCont[] = {
      "international", "global", "worldwide", "europe", "airlines", "airways",
      "publications", "group", "holdings", "ventures", "partners", "technologies",
      "solutions", "systems", "networks", "communications", "media", "press",
      "insights", "labs", "studio", "studios",
      // German/French corporate forms: GmbH, AG, Deutschland, Gruppe, France.
      "gmbh", "deutschland", "gruppe", "france", "holding",
      // Generic INDUSTRY descriptors that are also Tranco stems but are not brands
      // (a hyphenated legit name like france-telecom / x-bank must not combosquat,
      // and "X Telecom" must hold the display shape). NB: not "telekom" (a brand).
      "telecom", "mobile", "energy", "finance", "digital", "bank", "capital",
      "direct", "express"};
  return in_word_list(t, kCont, sizeof(kCont) / sizeof(kCont[0]));
}

// A generic role / corporate-continuation word. These lists are AUTHORITATIVE: some
// of these words (france, deutschland, partners, labs, signin) are themselves Tranco
// stems and so land in the brand set, but they are far too generic to be an
// impersonation brand. A generic token therefore never counts as a firing brand
// (else "Orange France" would condemn standalone and france-telecom.com would
// false-combosquat). Brands proper (Apple, PayPal, Orange) are not in these lists.
inline bool is_generic_token(const std::string& t) {
  return is_role_word(t) || is_brand_continuation(t);
}

// A token that is a DISTINCTIVE (Tier-1) brand and not a generic word.
inline bool is_distinctive_brand(const std::string& t) {
  return brand_tier(t) == 1 && !is_generic_token(t);
}

// Result of matching a display against the tiered brand set.
struct BrandMatch {
  bool tier1 = false;  // a distinctive brand fired -> condemn standalone
  bool tier2 = false;  // a dictionary-word brand fired WITH impersonation shape
                       // -> the caller must corroborate before condemning
  std::string brand;   // the matched brand token (folded form): the CLAIMED identity,
                       // for the claimed-vs-authenticated check (TASK-232 AC#2, doc-12)
};

// A brand claimed in EITHER source (e.g. the display name or the address local part).
inline BrandMatch operator|(const BrandMatch& a, const BrandMatch& b) {
  return {a.tier1 || b.tier1, a.tier2 || b.tier2, a.brand.empty() ? b.brand : a.brand};
}

// SLD label of an org-domain ("scaleway.fr" -> "scaleway"), lowercased.
inline std::string domain_stem(const std::string& org_domain) {
  std::string out;
  for (char ch : org_domain) {
    if (ch == '.') break;
    unsigned char c = static_cast<unsigned char>(ch);
    out.push_back(static_cast<char>((c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c));
  }
  return out;
}

// Unicode confusables.txt skeleton (TASK-237 AC#4): the whole-script confusable
// letters most used in homoglyph attacks (Cyrillic + Greek), each folded to the
// Latin letter it imitates. A curated, unambiguous subset of Unicode's
// confusables.txt: only the letters whose glyph is a near-exact match for a Latin
// letter, so legit non-Latin text fragments at the unmapped letters instead of
// folding cleanly onto a brand. Sorted by codepoint for binary search.
struct Confusable { std::uint32_t cp; char ascii; };
inline constexpr Confusable kConfusables[] = {
  // Greek capitals identical to Latin
  {0x0391, 'a'}, {0x0392, 'b'}, {0x0395, 'e'}, {0x0397, 'h'}, {0x0399, 'i'},
  {0x039A, 'k'}, {0x039C, 'm'}, {0x039D, 'n'}, {0x039F, 'o'}, {0x03A1, 'p'},
  {0x03A4, 't'}, {0x03A5, 'y'}, {0x03A7, 'x'},
  // Greek lowercase look-alikes
  {0x03B1, 'a'}, {0x03B9, 'i'}, {0x03BA, 'k'}, {0x03BD, 'v'}, {0x03BF, 'o'},
  {0x03C1, 'p'}, {0x03C4, 't'}, {0x03C7, 'x'},
  // Cyrillic capitals
  {0x0405, 's'}, {0x0406, 'i'}, {0x0408, 'j'}, {0x0410, 'a'}, {0x0415, 'e'},
  {0x041A, 'k'}, {0x041E, 'o'}, {0x0420, 'p'}, {0x0421, 'c'}, {0x0423, 'y'},
  {0x0425, 'x'},
  // Cyrillic lowercase (the common homoglyph attack alphabet)
  {0x0430, 'a'}, {0x0435, 'e'}, {0x043A, 'k'}, {0x043E, 'o'}, {0x0440, 'p'},
  {0x0441, 'c'}, {0x0443, 'y'}, {0x0445, 'x'}, {0x0455, 's'}, {0x0456, 'i'},
  {0x0458, 'j'},
};
inline char confusable_skeleton(std::uint32_t cp) {
  std::size_t lo = 0, hi = sizeof(kConfusables) / sizeof(kConfusables[0]);
  while (lo < hi) {
    const std::size_t mid = (lo + hi) / 2;
    if (kConfusables[mid].cp < cp) lo = mid + 1;
    else if (kConfusables[mid].cp > cp) hi = mid;
    else return kConfusables[mid].ascii;
  }
  return 0;
}

// Fold a Unicode codepoint to a single base ASCII [a-z0-9], or 0 if it is not a
// letter/digit (i.e. a token separator). Latin diacritics fold to their base
// letter (é→e, ñ→n) so an accented brand token still matches the ASCII brand set
// AND the accent no longer splits the token mid-brand (TASK-230). Cross-script
// homoglyphs (Cyrillic/Greek) fold via the confusables skeleton so a homoglyph
// display or decoded IDN domain maps onto the brand it imitates (TASK-237). ASCII
// letters lowercase; digits pass through.
inline char brand_fold_base(std::uint32_t cp) {
  if (cp >= 'A' && cp <= 'Z') return static_cast<char>(cp - 'A' + 'a');
  if ((cp >= 'a' && cp <= 'z') || (cp >= '0' && cp <= '9')) return static_cast<char>(cp);
  switch (cp) {  // Latin-1 Supplement + common Latin Extended-A -> base letter.
    case 0xC0: case 0xC1: case 0xC2: case 0xC3: case 0xC4: case 0xC5: case 0xC6:
    case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xE4: case 0xE5: case 0xE6: return 'a';
    case 0xC7: case 0xE7: case 0x0106: case 0x0107: case 0x010C: case 0x010D: return 'c';
    case 0xC8: case 0xC9: case 0xCA: case 0xCB:
    case 0xE8: case 0xE9: case 0xEA: case 0xEB: return 'e';
    case 0xCC: case 0xCD: case 0xCE: case 0xCF:
    case 0xEC: case 0xED: case 0xEE: case 0xEF: return 'i';
    case 0xD0: case 0xF0: return 'd';
    case 0xD1: case 0xF1: return 'n';
    case 0xD2: case 0xD3: case 0xD4: case 0xD5: case 0xD6: case 0xD8:
    case 0xF2: case 0xF3: case 0xF4: case 0xF5: case 0xF6: case 0xF8: return 'o';
    case 0xD9: case 0xDA: case 0xDB: case 0xDC:
    case 0xF9: case 0xFA: case 0xFB: case 0xFC: return 'u';
    case 0xDD: case 0xFD: case 0xFF: return 'y';
    case 0x0141: case 0x0142: return 'l';                          // Ł ł
    case 0x015A: case 0x015B: case 0x0160: case 0x0161: return 's';  // Ś ś Š š
    case 0x0179: case 0x017A: case 0x017D: case 0x017E: return 'z';  // Ź ź Ž ž
    default: return confusable_skeleton(cp);  // Cyrillic/Greek homoglyphs (TASK-237)
  }
}

// One normalized display token. `plain` is UTF-8-lowercased with diacritics folded
// (Nocibé→nocibe, the brand set's own form); `conf` additionally folds the
// capital-'I'→'l' homoglyph (DecathIon→decathlon, LidI→lidl) and is only consulted
// when it diverges from plain, confining the homoglyph path's cost to genuinely
// perturbed tokens (TASK-230).
struct DisplayToken {
  std::string plain;    // brand_fold_base of each char (capital I -> i)
  std::string conf;     // conservative capital-I -> l homoglyph fold
  std::string conf_hg;  // aggressive fold: conf + digit/rn homoglyphs (0->o, 1->l, rn->m, ...)
  bool perturbed = false;  // conf differs from plain (a capital-I homoglyph)
};

inline std::string confusable_fold(const std::string& s);  // defined below

// Tokenize a display name into normalized letter/digit runs. Apostrophes are
// non-breaking within a run (L'Oréal→loreal) so the brand stays one token.
inline std::vector<DisplayToken> tokenize_display(const std::string& display_name) {
  std::vector<DisplayToken> tokens;
  DisplayToken cur;
  auto flush = [&]() {
    if (!cur.plain.empty()) {
      // conf keeps only the conservative capital-I->l fold (matched at any tier).
      // conf_hg adds the aggressive digit/rn homoglyph fold, matched at Tier-1
      // only in match_brand, so PayPa1/G00gle map onto the distinctive brand they
      // imitate without a digit coincidence hitting a dictionary-word (Tier-2)
      // brand (FN2, TASK-251).
      cur.conf_hg = confusable_fold(cur.conf);
      tokens.push_back(cur);
    }
    cur = DisplayToken{};
  };
  // Minimal UTF-8 decode. Truncated/malformed sequences fall to the else branch
  // (one byte, U+FFFD) which folds to a separator, a safe token break, never a
  // crash. ++p every branch guarantees progress.
  const auto* p = reinterpret_cast<const unsigned char*>(display_name.data());
  const auto* end = p + display_name.size();
  while (p < end) {
    std::uint32_t cp;
    if (*p < 0x80) { cp = *p; ++p; }
    else if ((*p >> 5) == 0x6 && p + 1 < end) { cp = ((*p & 0x1F) << 6) | (p[1] & 0x3F); p += 2; }
    else if ((*p >> 4) == 0xE && p + 2 < end) { cp = ((*p & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F); p += 3; }
    else if ((*p >> 3) == 0x1E && p + 3 < end) { cp = ((*p & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F); p += 4; }
    else { cp = 0xFFFD; ++p; }
    if (cp == 0x27 || cp == 0x2019) continue;  // ' ' apostrophe: non-breaking
    if (cp == 0xDF) {  // German ß -> ss (a 1->2 fold the single-char map can't do)
      cur.plain.append("ss");
      cur.conf.append("ss");
      continue;
    }
    const char b = brand_fold_base(cp);
    if (b == 0) { flush(); continue; }
    cur.plain.push_back(b);
    const char c = (cp == 0x49) ? 'l' : b;  // capital 'I' is a homoglyph for 'l'
    cur.conf.push_back(c);
    if (c != b) cur.perturbed = true;
  }
  flush();
  return tokens;
}

// Fold common ASCII homoglyph substitutions toward the canonical letter so a
// look-alike domain stem maps onto the brand stem it imitates (paypa1->paypal,
// g00gle->google, arnazon->amazon). The rn->m digraph is handled first. Only the
// unambiguous swaps are mapped (1->l, 0->o, ...); this is detection-only.
inline std::string confusable_fold(const std::string& s) {
  std::string t;
  t.reserve(s.size());
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] == 'r' && i + 1 < s.size() && s[i + 1] == 'n') { t.push_back('m'); ++i; continue; }
    char c = s[i];
    switch (c) {
      case '0': c = 'o'; break;
      case '1': c = 'l'; break;
      case '3': c = 'e'; break;
      case '4': c = 'a'; break;
      case '5': c = 's'; break;
      case '7': c = 't'; break;
      case '$': c = 's'; break;
      default: break;
    }
    t.push_back(c);
  }
  return t;
}

// Decode an IDNA `xn--` label (RFC 3492 punycode) into Unicode code points. Returns
// false (leaving `out` partial) on malformed input or overflow, so the caller fails
// safe. `in` is the label WITHOUT the "xn--" prefix.
inline bool punycode_decode(const std::string& in, std::vector<std::uint32_t>& out) {
  if (in.empty()) return false;
  constexpr std::uint32_t kBase = 36, kTmin = 1, kTmax = 26, kSkew = 38, kDamp = 700;
  std::size_t pos = 0;
  const std::size_t last_delim = in.find_last_of('-');
  if (last_delim != std::string::npos) {   // literal ASCII prefix before the last '-'
    for (std::size_t i = 0; i < last_delim; ++i) {
      const unsigned char c = static_cast<unsigned char>(in[i]);
      if (c >= 0x80) return false;          // basic section must be ASCII
      out.push_back(c);
    }
    pos = last_delim + 1;
  }
  std::uint32_t n = 128, i = 0, bias = 72;
  auto adapt = [&](std::uint32_t delta, std::uint32_t numpoints, bool first) {
    delta = first ? delta / kDamp : delta / 2;
    delta += delta / numpoints;
    std::uint32_t k = 0;
    while (delta > ((kBase - kTmin) * kTmax) / 2) { delta /= (kBase - kTmin); k += kBase; }
    return k + (((kBase - kTmin + 1) * delta) / (delta + kSkew));
  };
  while (pos < in.size()) {
    const std::uint32_t oldi = i;
    std::uint32_t w = 1, k = kBase;
    for (;;) {
      if (pos >= in.size()) return false;
      const char ch = in[pos++];
      std::uint32_t digit;
      if (ch >= 'a' && ch <= 'z') digit = static_cast<std::uint32_t>(ch - 'a');
      else if (ch >= '0' && ch <= '9') digit = static_cast<std::uint32_t>(ch - '0' + 26);
      else return false;
      if (digit > (0xFFFFFFFFu - i) / w) return false;   // overflow guard
      i += digit * w;
      const std::uint32_t t = k <= bias ? kTmin : (k >= bias + kTmax ? kTmax : k - bias);
      if (digit < t) break;
      if (w > 0xFFFFFFFFu / (kBase - t)) return false;    // overflow guard
      w *= (kBase - t);
      k += kBase;
    }
    const std::uint32_t numpoints = static_cast<std::uint32_t>(out.size()) + 1;
    bias = adapt(i - oldi, numpoints, oldi == 0);
    n += i / numpoints;
    i = i % numpoints;
    if (n > 0x10FFFF) return false;                        // not a valid code point
    out.insert(out.begin() + i, n);
    ++i;
  }
  return true;
}

// Confusable-fold a non-ASCII domain stem onto the brand it imitates (TASK-237 AC#3).
// A homoglyph domain reaches the engine in one of two forms: gmime decodes the From
// header's `xn--` to raw UTF-8 (Cyrillic "ѕcaleway"), while DKIM d= and body-URL
// hosts stay ASCII `xn--`. Both decode to the same code points, then fold through the
// confusables skeleton (brand_fold_base). Returns the folded ASCII stem, or "" if the
// stem is pure ASCII (the caller's ASCII confusable_fold covers digit/rn homoglyphs)
// or the encoding is malformed.
inline std::string confusable_fold_unicode(const std::string& sld) {
  std::vector<std::uint32_t> cps;
  if (sld.rfind("xn--", 0) == 0) {
    if (!punycode_decode(sld.substr(4), cps)) return "";
  } else {
    bool non_ascii = false;
    const auto* p = reinterpret_cast<const unsigned char*>(sld.data());
    const auto* end = p + sld.size();
    while (p < end) {                       // minimal UTF-8 decode (matches tokenize_display)
      std::uint32_t cp;
      if (*p < 0x80) { cp = *p; ++p; }
      else if ((*p >> 5) == 0x6 && p + 1 < end) { cp = ((*p & 0x1F) << 6) | (p[1] & 0x3F); p += 2; non_ascii = true; }
      else if ((*p >> 4) == 0xE && p + 2 < end) { cp = ((*p & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F); p += 3; non_ascii = true; }
      else if ((*p >> 3) == 0x1E && p + 3 < end) { cp = ((*p & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F); p += 4; non_ascii = true; }
      else { cp = 0xFFFD; ++p; non_ascii = true; }
      cps.push_back(cp);
    }
    if (!non_ascii) return "";              // pure ASCII: nothing cross-script to fold
  }
  std::string folded;
  folded.reserve(cps.size());
  for (const std::uint32_t cp : cps) {
    const char b = brand_fold_base(cp);
    if (b) folded.push_back(b);             // unmapped code points drop out
  }
  return folded;
}

// Homoglyph look-alike of a brand: the stem confusable-folds onto a brand it isn't.
// This is the UNAMBIGUOUS-corruption half of the cousin family (a brand never sends
// from a homoglyph of its own name), safe to apply across the From, Reply-To and
// body-URL domains (TASK-237 AC#2). The cross-script fold matches any tier (no legit
// sender Cyrillic-encodes its ASCII brand); the ASCII digit/rn fold stays Tier-1 only.
inline bool is_homoglyph_domain(const std::string& org_domain) {
  const std::string sld = domain_stem(org_domain);
  if (sld.size() < 4) return false;
  const std::string uni = confusable_fold_unicode(sld);
  if (!uni.empty() && brand_tier(uni) != 0 && !is_generic_token(uni)) return true;
  const std::string folded = confusable_fold(sld);
  return folded != sld && is_distinctive_brand(folded);
}

// Cousin / look-alike SENDING DOMAIN detection (TASK-214 AC#3): the From org-domain is
// a homoglyph OR a combosquat of a DISTINCTIVE (Tier-1) brand. Combosquat ("paypal-
// secure", "account-paypal-login") is bundled in here for the FROM only: it is the
// sender's own domain, a far stronger signal than a body link, and is gated downstream
// by reputable_aligned. The multi-field paths use is_homoglyph_domain instead, because
// combosquat over Reply-To / body URLs false-fires on legit ESP and notification infra
// (hubspotemail-na2.net, notif-laposte.info) that legit mail routinely references.
inline bool is_lookalike_domain(const std::string& from_org_domain) {
  if (is_homoglyph_domain(from_org_domain)) return true;
  const std::string sld = domain_stem(from_org_domain);
  // Combosquat: a hyphen-delimited token is a distinctive brand, but the whole stem
  // is not itself a brand. The generic guard keeps a legit hyphenated name
  // (france-telecom, partners-llc) from firing.
  if (sld.size() >= 4 && sld.find('-') != std::string::npos && brand_tier(sld) == 0) {
    std::size_t start = 0;
    while (start <= sld.size()) {
      const std::size_t dash = sld.find('-', start);
      const std::size_t len = (dash == std::string::npos) ? sld.size() - start : dash - start;
      if (len >= 4 && is_distinctive_brand(sld.substr(start, len))) return true;
      if (dash == std::string::npos) break;
      start = dash + 1;
    }
  }
  return false;
}

// Match the From DISPLAY NAME against the tiered brand set. Tier-1 (distinctive)
// fires on any token; Tier-2 (dictionary word) additionally requires the
// impersonation SHAPE: every other token is a role word / short / owned / brand,
// so "Apple <evil>" / "Apple Account Security" match but "Apple Valley News" does
// not. The From org-domain's own brand is exempt: a brand string the sending
// domain stem STARTS WITH ("societe" under societegenerale.fr) is a look-alike
// domain (a different signal), not a display-name spoof (TASK-214, TASK-230, doc-12).
inline BrandMatch display_impersonates_brand(const std::string& display_name,
                                             const std::string& from_org_domain) {
  BrandMatch m;
  if (display_name.empty() || from_org_domain.empty()) return m;
  const std::string fstem = domain_stem(from_org_domain);
  // The sending domain stem STARTS WITH this string (a look-alike domain whose
  // name sits at the front: "societe" under societegenerale.fr).
  auto owns_prefix = [&](const std::string& s) {
    return fstem.size() >= s.size() && fstem.compare(0, s.size(), s) == 0;
  };
  // The brand form a token matches and its tier, homoglyph-aware. The form (plain,
  // or the folded `conf` for a perturbed token) is what ownership must be tested
  // against: "PayPaI" from paypal.com matches via conf="paypal", so the conf form
  // is the one that owns the domain.
  struct Match { int tier; const std::string* form; };
  auto match_brand = [&](const DisplayToken& t) -> Match {
    // A generic word (france, partners, support, ...) never matches as a brand even
    // when it is coincidentally a Tranco stem; the role/continuation lists win.
    // len>=3 admits the curated short brands (DHL/UPS/SFR); brand_tier returns 0 for
    // any other 3-char token, so the noise floor is unchanged.
    if (t.plain.size() >= 3 && !is_generic_token(t.plain)) {
      const int tt = brand_tier(t.plain); if (tt) return {tt, &t.plain};
    }
    if (t.perturbed && t.conf.size() >= 3 && !is_generic_token(t.conf)) {
      // Conservative capital-I->l fold: unambiguous, so admitted at any tier
      // (DecathIon -> decathlon, Tier-2).
      const int tt = brand_tier(t.conf); if (tt) return {tt, &t.conf};
    }
    if (t.conf_hg != t.conf && t.conf_hg.size() >= 3 && !is_generic_token(t.conf_hg)) {
      // Aggressive digit/rn homoglyph fold (PayPa1 -> paypal): admitted only for a
      // DISTINCTIVE (Tier-1) brand, so a digit coincidence can't fold onto a
      // dictionary-word (Tier-2) brand and false-fire (FN2, TASK-251).
      if (brand_tier(t.conf_hg) == 1) return {1, &t.conf_hg};
    }
    return {0, nullptr};
  };
  // A token whose plain OR folded form sits at the front of the sending domain is
  // an owned look-alike, not a spoof of that token (TASK-230 homoglyph-aware).
  auto token_owned = [&](const DisplayToken& t) {
    return owns_prefix(t.plain) || (t.perturbed && owns_prefix(t.conf));
  };

  const std::vector<DisplayToken> tokens = tokenize_display(display_name);
  // Whole-display self-exemption when the sender is genuinely on the brand's own
  // BARE domain, so its display (any co-branded product / sub-brand / place names)
  // is trusted. Two genuine shapes:
  //   (a) a display token's brand form EQUALS the whole sending stem -- the sender
  //       IS that brand on its bare domain ("Amazon" == amazon.fr, homoglyph
  //       "PayPaI" == paypal.com), in ANY token order ("Nike on Amazon",
  //       "Xbox news from Microsoft"); OR
  //   (b) the LEADING tokens spell the stem exactly, for a multi-word brand whose
  //       joined stem is not itself one dictionary entry ("Time Out" -> timeout.com).
  // A brand that only PREFIXES a longer stem the display does not fully spell
  // ("amazon" in "amazon-offers", stem "amazon-offers") is a look-alike, not the
  // owner, so a DIFFERENT brand beside it still condemns: "Amazon PayPal Support"
  // from amazon-offers.xyz impersonates PayPal (FN3, TASK-251). The old check used
  // a bare owns_prefix, which whole-exempted that combosquat. Exoneration of a
  // FORGED brand domain (dmarc=fail on transferwise.com) is the caller's auth job,
  // so a token that only SITS ON but does not equal the stem is reported here, not
  // exempted; the prefix-owned front token is still dropped per-token (token_owned
  // below), leaving only the un-owned brand to fire.
  for (const DisplayToken& t : tokens) {
    const Match mt = match_brand(t);
    if (mt.tier && *mt.form == fstem) return m;  // (a) sender IS this brand's bare domain
  }
  std::string lead_plain, lead_conf;
  for (const DisplayToken& t : tokens) {
    lead_plain += t.plain;
    lead_conf += t.perturbed ? t.conf : t.plain;
    if (lead_plain == fstem || lead_conf == fstem) return m;  // (b) leading tokens spell the stem
    if (lead_plain.size() >= fstem.size()) break;  // == lead_conf.size() (conf fold is 1:1)
  }

  bool tier2_present = false, distinctive_leftover = false;
  std::string tier1_brand, tier2_brand;
  for (const DisplayToken& t : tokens) {
    if (token_owned(t)) continue;              // an owned look-alike token is a different signal
    const Match mt = match_brand(t);
    if (mt.tier == 1) { m.tier1 = true; if (tier1_brand.empty()) tier1_brand = *mt.form; }
    else if (mt.tier == 2) { tier2_present = true; if (tier2_brand.empty()) tier2_brand = *mt.form; }
    else if (t.plain.size() >= 4 && !is_role_word(t.plain) && !is_brand_continuation(t.plain)) {
      distinctive_leftover = true;             // a non-brand, non-role, non-corporate word breaks the shape
    }
  }
  m.tier2 = tier2_present && !distinctive_leftover;
  m.brand = m.tier1 ? tier1_brand : (m.tier2 ? tier2_brand : std::string());
  return m;
}

}  // namespace brand_names
}  // namespace spam_engine
