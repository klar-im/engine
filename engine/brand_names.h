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
//   Tier-2, stems that ARE dictionary words (Decathlon, Orange, Apple) or common
//            FR/DE/EN surnames (Dupont, Mueller, Williams; TASK-266). The word
//            has a large legit non-brand population ("Orange County",
//            "Marie Dupont"), so a match is low-confidence: it only counts when
//            the display has the impersonation SHAPE (brand + role words, nothing
//            distinctive left) AND the caller corroborates it with an independent
//            spam signal.
//   Between the two sit the AMBIGUOUS Tier-1 brands (is_ambiguous_brand,
//   TASK-268): heavily-phished brands that are also common surnames (Boulanger,
//   Norton). Display claims condemn standalone but only with the impersonation
//   shape; a personal-name display passes.
// Membership is exact (FNV-1a + binary search). No Swift copy, Swift reads the
// engine-computed `display_impersonation` boolean over the C ABI.

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "brand_names_data.h"
#include "fnv1a.h"


namespace spam_engine::brand_names {

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

// Ambiguous Tier-1 brands (TASK-268): heavily-phished brands that are ALSO common
// FR surnames (or, for boulanger, a French profession word), kept out of the
// surname demotion (TASK-266) on phish volume: Boulanger gift-card / order scams,
// Norton subscription-renewal invoices. Policy is the middle of the two tiers: a
// display claim condemns STANDALONE (Tier-1 strength, no corroborating signal
// needed) but only WITH the impersonation shape (Tier-2 gate), so "Boulanger
// Support" and bare "Norton" fire while a personal name ("Edmond Boulanger") has
// a distinctive leftover, breaks the shape, and passes. Domain-shaped paths
// (combosquat, homoglyph, subdomain) treat them as plain Tier-1: no person owns
// b0ulanger.com. NB: E.Leclerc, the other Leclerc-class dual, is NOT here
// because "leclerc" is not a Tranco stem at all (the retailer's domain is
// e.leclerc, stem "e"), so no string match exists to gate; its coverage needs
// the brand KB (TASK-267).
inline bool is_ambiguous_brand(const std::string& t) {
  static const char* const kAmbiguous[] = {"boulanger", "norton"};
  return in_word_list(t, kAmbiguous, sizeof(kAmbiguous) / sizeof(kAmbiguous[0]));
}

// 0 = not a brand, 1 = Tier-1 (distinctive), 2 = Tier-2 (dictionary word / curated
// short brand). Short brands are Tier-2: a 3-char match is high-ambiguity, so it
// needs the impersonation shape + a corroborating signal downstream.
inline int brand_tier(const std::string& stem) {
  if (stem.size() == 3) { return is_short_brand(stem) ? 2 : 0;
}
  if (stem.size() < 4) { return 0;
}
  const std::uint64_t h = fnv1a_lower(stem);
  if (std::binary_search(kBrandNameHashes, kBrandNameHashes + kBrandNameHashesCount, h)) { return 1;
}
  if (std::binary_search(kBrandNameHashesT2, kBrandNameHashesT2 + kBrandNameHashesT2Count, h)) { return 2;
}
  return 0;
}

// Exact membership of t in a null-free static word list.
inline bool in_word_list(const std::string& t, const char* const* list, std::size_t n) {
  for (std::size_t i = 0; i < n; ++i) {
    if (t == list[i]) { return true;
}
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
      // Subscription/renewal-scam vocabulary (TASK-268): the Norton-class fake
      // invoice display is "Brand Renewal" / "Brand Invoice"; antivirus is the
      // product noun of that same scam family.
      "invoice", "invoices", "renewal", "renewals", "subscription",
      "subscriptions", "receipt", "receipts", "antivirus",
      // French role words (primary market): compte=account, securite=security,
      // paiement=payment, commande=order, facture=invoice, livraison=delivery,
      // commentaires=reviews, assistance/aide=support, alerte=alert,
      // carte/cadeau=gift-card (the Leclerc/Boulanger scam shape, TASK-268).
      "compte", "comptes", "securite", "paiement", "paiements", "commande",
      "commandes", "facture", "factures", "livraison", "commentaires",
      "assistance", "aide", "alerte", "alertes", "confidentialite", "abonnement",
      "carte", "cartes", "cadeau", "cadeaux", "renouvellement", "abonnements",
      // electromenager: Boulanger's own product tagline, the order-scam shape
      "electromenager",
      // German role words: konto=account, sicherheit=security, zahlung=payment,
      // bestellung=order, rechnung=invoice, lieferung/versand=delivery,
      // kundendienst=support, benachrichtigung=notification, anmeldung=login.
      "konto", "konten", "sicherheit", "zahlung", "zahlungen", "bestellung",
      "bestellungen", "rechnung", "rechnungen", "lieferung", "versand",
      "kundendienst", "kundenservice", "benachrichtigung", "anmeldung", "passwort",
      "bestaetigung", "aktualisierung", "hilfe",
      // Verlaengerung=renewal (both the ASCII spelling and the a-umlaut fold the
      // display tokenizer produces).
      "verlaengerung", "verlangerung"};
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

// PRODUCT LINES, SCOPED TO THE BRAND THAT OWNS THEM (2026-08-29).
//
// The gap this closes ran the guard BACKWARDS for dictionary-word brands:
// "Amazon" alone raised a claim and "Amazon Prime" raised none, because "prime"
// read as a distinctive qualifier and dropped it. Nobody means the river when
// they write "Amazon Prime"; the namesake writes "Amazon River".
//
// THE FIRST ATTEMPT PUT THESE IN kCont, GLOBALLY, AND THAT WAS A REAL FALSE
// POSITIVE. Every product word then followed every brand, so ordinary display
// names fired: "Live Music", "Live Video", "Live Nation" (an actual company),
// "Nothing Fresh", "Booking Assistant", "Visa Business" -- all resolve to a
// Tier-2 brand token plus a word that is only a product line for some OTHER
// company. display_impersonation is a 0.99 offset that CAN authorize a bounce,
// so a global list was the worst possible shape for this.
//
// Scoped, the claim only survives when the leftover is a product line of the
// brand actually matched: "Amazon Prime" yes, "Live Music" no. The namesake
// vocabulary (river, basin, valley, county, watch) is absent from every entry
// and still breaks the shape.
inline bool is_product_line_of(const std::string& brand, const std::string& t) {
  struct Line { const char* brand; const char* word; };
  static const Line kLines[] = {
      {"amazon", "prime"},   {"amazon", "video"},  {"amazon", "music"},
      {"amazon", "fresh"},   {"amazon", "basics"}, {"amazon", "business"},
      {"apple", "pay"},      {"apple", "care"},    {"apple", "music"},
      {"apple", "store"},    {"apple", "watch"},   {"apple", "tv"},
      {"google", "pay"},     {"google", "drive"},  {"google", "cloud"},
      {"google", "play"},    {"google", "photos"},
      {"microsoft", "office"}, {"microsoft", "teams"}, {"microsoft", "azure"},
      {"orange", "money"},   {"orange", "bank"},
      {"free", "mobile"},
      {"paypal", "credit"},
      {"netflix", "kids"},
  };
  return std::any_of(std::begin(kLines), std::end(kLines), [&](const Line& l) {
    return brand == l.brand && t == l.word;
  });
}

// Is this a product-line word for ANY brand? Used ONLY as vocabulary by the
// separator-less token cover in email_preprocessor.cpp, never by the display
// shape guard.
//
// The distinction matters and it is the whole reason these are two functions.
// The DISPLAY guard must be brand-scoped, because "Live Music" is not Live and
// an unscoped list fired on ordinary names. The COVER does not have that
// exposure: it already demands a KB brand AND a strong keyword AND a full
// decomposition of the stem, so `amazonprimeresiliation` needs "prime" only as
// a connecting token, and a cover cannot be built out of product words alone.
inline bool is_product_line_word(const std::string& t) {
  static const char* const kWords[] = {
      "prime", "video", "music", "photos", "drive", "cloud", "wallet", "pay",
      "care", "play", "store", "kids", "fresh", "business", "basics", "teams",
      "azure", "office", "money", "mobile", "credit",
  };
  return in_word_list(t, kWords, sizeof(kWords) / sizeof(kWords[0]));
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
  for (char const ch : org_domain) {
    if (ch == '.') { break;
}
    auto const c = static_cast<unsigned char>(ch);
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
  std::size_t lo = 0;
  std::size_t hi = sizeof(kConfusables) / sizeof(kConfusables[0]);
  while (lo < hi) {
    const std::size_t mid = (lo + hi) / 2;
    if (kConfusables[mid].cp < cp) { lo = mid + 1;
    } else if (kConfusables[mid].cp > cp) { hi = mid;
    } else { return kConfusables[mid].ascii;
}
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
  if (cp >= 'A' && cp <= 'Z') { return static_cast<char>(cp - 'A' + 'a');
}
  if ((cp >= 'a' && cp <= 'z') || (cp >= '0' && cp <= '9')) { return static_cast<char>(cp);
}
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
  // Produced by collapsing a letter-spaced run, so the display's own word
  // boundaries are NOT recoverable from it: "D e u t s c h e B a n k" arrives as
  // one token. Only the multi-word JOIN matcher may treat such a token as a
  // whole brand name; the ordinary tiered paths must not, or a single token
  // would claim a brand without the impersonation shape ever being checked.
  bool spaced_join = false;
};

inline std::string confusable_fold(const std::string& s);  // defined below

// A separator between every letter kills the brand match, and it was the
// cheapest evasion we had (TASK-459): "A m a z o n", "A.m.a.z.o.n" and
// "P a y P a l" all raised no claim while the same names all-caps, with Cyrillic
// homoglyphs, or with a zero-width space all fired. So the fold work was real
// and separators were simply a hole in it.
//
// Fixed by JOINING the run in the tokenizer rather than by adding a synthetic
// candidate beside it, so every guard downstream keeps working on the joined
// form unchanged: ownership (a letter-spaced sender on its own domain is still
// exempt), the Tier-2 impersonation shape, and the leftover/product-line rules.
//
// THE FLOOR IS THE FALSE-POSITIVE LEVER, and it is why this is a run length and
// not a general "collapse single letters" rule. Letter-spacing is a real
// typographic style, and the words marketing sets that way are short and often
// dictionary words that are also Tier-2 brands: "S A L E", "F R E E", "L I V E",
// "N E X T", "A P P L E".
//
// SET AT 5 FIRST, AND THAT WAS TOO LOW. The controls written for it were "SALE",
// "FREE", "LIVE", "NEXT" -- every one of them four letters, which is to say the
// floor was validated exactly at the boundary it had been set to and nowhere
// past it. "A P P L E" is five, is a Tier-2 brand, and is a fruit; it fired.
// Found by probing my own rule after the fact rather than by any gate, which is
// the same lesson as the English call-service mail two commits earlier: a
// control set that only contains cases you expect to pass measures nothing.
//
// 6 keeps every target of TASK-459 ("A m a z o n" and "P a y P a l" are 6,
// "N e t f l i x" is 7) and drops "A P P L E".
//
// KNOWN RESIDUAL, locked in a test rather than left to be rediscovered:
// "O R A N G E" is six letters, a Tier-2 brand, and an ordinary word, so it
// still fires from an unrelated domain. A floor that excluded it would exclude
// "A m a z o n" too, since they are the same length. The sender's own domain is
// exempt either way, so the case that remains is a third party letter-spacing
// the word "orange", which is rare enough to accept and specific enough to name.
//
// Measured: 0/30 on the battery's ham classes, 0/32 on its legit-FP gate, and
// zero additional firings on the 1,479-message transactional panel (35 with the
// join, the same 35 without it, built both ways).
inline constexpr std::size_t kMinSpacedRun = 6;

inline void join_letter_spaced_runs(std::vector<DisplayToken>& tokens) {
  std::vector<DisplayToken> out;
  out.reserve(tokens.size());
  std::size_t i = 0;
  while (i < tokens.size()) {
    std::size_t j = i;
    while (j < tokens.size() && tokens[j].plain.size() == 1) { ++j;
}
    if (j - i >= kMinSpacedRun) {
      DisplayToken joined;
      for (std::size_t k = i; k < j; ++k) {
        joined.plain += tokens[k].plain;
        joined.conf += tokens[k].conf;
        joined.perturbed = joined.perturbed || tokens[k].perturbed;
      }
      joined.conf_hg = confusable_fold(joined.conf);
      joined.spaced_join = true;
      out.push_back(joined);
      i = j;
      continue;
    }
    // A run shorter than the floor is left exactly as it was, one token per
    // letter. Not dropped: "P S 5" beside a brand must still count as tokens.
    for (std::size_t k = i; k < (j > i ? j : i + 1); ++k) { out.push_back(tokens[k]);
}
    i = (j > i ? j : i + 1);
  }
  tokens.swap(out);
}

// Tokenize a display name into normalized letter/digit runs. Apostrophes are
// non-breaking within a run (L'Oréal→loreal) so the brand stays one token.
inline std::vector<DisplayToken> tokenize_display(const std::string& display_name) {
  std::vector<DisplayToken> tokens;
  DisplayToken cur;
  auto const flush = [&] {
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
    std::uint32_t cp = 0;
    if (*p < 0x80) { cp = *p; ++p; }
    else if ((*p >> 5) == 0x6 && p + 1 < end) { cp = ((*p & 0x1F) << 6) | (p[1] & 0x3F); p += 2; }
    else if ((*p >> 4) == 0xE && p + 2 < end) { cp = ((*p & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F); p += 3; }
    else if ((*p >> 3) == 0x1E && p + 3 < end) { cp = ((*p & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F); p += 4; }
    else { cp = 0xFFFD; ++p; }
    if (cp == 0x27 || cp == 0x2019) { continue;  // ' ' apostrophe: non-breaking
}
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
    if (c != b) { cur.perturbed = true;
}
  }
  flush();
  join_letter_spaced_runs(tokens);
  return tokens;
}

// Fold common ASCII homoglyph substitutions toward the canonical letter. The
// leet map lives HERE only; both readings of the ambiguous '1' share it via
// `one_as` ('l' for brand stems: paypa1->paypal; 'i' for role words:
// serv1ce->service, TASK-268). `fold_rn` additionally folds the rn->m digraph
// (arnazon->amazon), wanted for brand stems, not for the role reading. Only
// the unambiguous swaps are mapped; this is detection-only.
inline std::string leet_fold(const std::string& s, char one_as, bool fold_rn) {
  std::string t;
  t.reserve(s.size());
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (fold_rn && s[i] == 'r' && i + 1 < s.size() && s[i + 1] == 'n') { t.push_back('m'); ++i; continue; }
    char c = s[i];
    switch (c) {
      case '0': c = 'o'; break;
      case '1': c = one_as; break;
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

// The brand-stem reading: a look-alike domain stem maps onto the brand it
// imitates (paypa1->paypal, g00gle->google, arnazon->amazon).
inline std::string confusable_fold(const std::string& s) { return leet_fold(s, 'l', true); }

// Decode an IDNA `xn--` label (RFC 3492 punycode) into Unicode code points. Returns
// false (leaving `out` partial) on malformed input or overflow, so the caller fails
// safe. `in` is the label WITHOUT the "xn--" prefix.
inline bool punycode_decode(const std::string& in, std::vector<std::uint32_t>& out) {
  if (in.empty()) { return false;
}
  constexpr std::uint32_t kBase = 36;
  constexpr std::uint32_t kTmin = 1;
  constexpr std::uint32_t kTmax = 26;
  constexpr std::uint32_t kSkew = 38;
  constexpr std::uint32_t kDamp = 700;
  std::size_t pos = 0;
  const std::size_t last_delim = in.find_last_of('-');
  if (last_delim != std::string::npos) {   // literal ASCII prefix before the last '-'
    for (std::size_t i = 0; i < last_delim; ++i) {
      const auto c = static_cast<unsigned char>(in[i]);
      if (c >= 0x80) { return false;          // basic section must be ASCII
}
      out.push_back(c);
    }
    pos = last_delim + 1;
  }
  std::uint32_t n = 128;
  std::uint32_t i = 0;
  std::uint32_t bias = 72;
  auto const adapt = [&](std::uint32_t delta, std::uint32_t numpoints, bool first) {
    delta = first ? delta / kDamp : delta / 2;
    delta += delta / numpoints;
    std::uint32_t k = 0;
    while (delta > ((kBase - kTmin) * kTmax) / 2) { delta /= (kBase - kTmin); k += kBase; }
    return k + (((kBase - kTmin + 1) * delta) / (delta + kSkew));
  };
  while (pos < in.size()) {
    const std::uint32_t oldi = i;
    std::uint32_t w = 1;
    std::uint32_t k = kBase;
    for (;;) {
      if (pos >= in.size()) { return false;
}
      const char ch = in[pos++];
      std::uint32_t digit = 0;
      if (ch >= 'a' && ch <= 'z') { digit = static_cast<std::uint32_t>(ch - 'a');
      } else if (ch >= '0' && ch <= '9') { digit = static_cast<std::uint32_t>(ch - '0' + 26);
      } else { return false;
}
      if (digit > (0xFFFFFFFFU - i) / w) { return false;   // overflow guard
}
      i += digit * w;
      const std::uint32_t t = k <= bias ? kTmin : (k >= bias + kTmax ? kTmax : k - bias);
      if (digit < t) { break;
}
      if (w > 0xFFFFFFFFU / (kBase - t)) { return false;    // overflow guard
}
      w *= (kBase - t);
      k += kBase;
    }
    const std::uint32_t numpoints = static_cast<std::uint32_t>(out.size()) + 1;
    bias = adapt(i - oldi, numpoints, oldi == 0);
    n += i / numpoints;
    i = i % numpoints;
    if (n > 0x10FFFF) { return false;                        // not a valid code point
}
    out.insert(out.begin() + i, n);
    ++i;
  }
  return true;
}

// Decode an `xn--` stem to UTF-8, or "" if it is not one (or is malformed).
//
// Separate from confusable_fold_unicode below, which decodes the SAME label but
// then folds it through the confusables skeleton to catch a homoglyph. That is a
// different question from "what does this domain actually say", and the skeleton
// answers it wrongly for accented Latin: é is not a confusable of e, it is a
// French letter, so the skeleton leaves it alone and the caller sees no keyword.
//
// The two encodings are not interchangeable and that asymmetry is the bug this
// exists for: GMime decodes the From header's `xn--` to raw UTF-8, while BODY
// URL hosts stay ASCII `xn--`. So `amazon-prime-résiliation.com` was caught in
// the From and missed in a link, for the same message.
inline std::string idn_to_utf8(const std::string& sld) {
  if (sld.rfind("xn--", 0) != 0) { return "";
}
  std::vector<std::uint32_t> cps;
  if (!punycode_decode(sld.substr(4), cps)) { return "";
}
  std::string out;
  for (std::uint32_t cp : cps) {
    if (cp < 0x80) {
      out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
      out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
      out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }
  return out;
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
    if (!punycode_decode(sld.substr(4), cps)) { return "";
}
  } else {
    bool non_ascii = false;
    const auto* p = reinterpret_cast<const unsigned char*>(sld.data());
    const auto* end = p + sld.size();
    while (p < end) {                       // minimal UTF-8 decode (matches tokenize_display)
      std::uint32_t cp = 0;
      if (*p < 0x80) { cp = *p; ++p; }
      else if ((*p >> 5) == 0x6 && p + 1 < end) { cp = ((*p & 0x1F) << 6) | (p[1] & 0x3F); p += 2; non_ascii = true; }
      else if ((*p >> 4) == 0xE && p + 2 < end) { cp = ((*p & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F); p += 3; non_ascii = true; }
      else if ((*p >> 3) == 0x1E && p + 3 < end) { cp = ((*p & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F); p += 4; non_ascii = true; }
      else { cp = 0xFFFD; ++p; non_ascii = true; }
      cps.push_back(cp);
    }
    if (!non_ascii) { return "";              // pure ASCII: nothing cross-script to fold
}
  }
  std::string folded;
  folded.reserve(cps.size());
  for (const std::uint32_t cp : cps) {
    const char b = brand_fold_base(cp);
    if (b) { folded.push_back(b);             // unmapped code points drop out
}
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
  if (sld.size() < 4) { return false;
}
  const std::string uni = confusable_fold_unicode(sld);
  if (!uni.empty() && brand_tier(uni) != 0 && !is_generic_token(uni)) { return true;
}
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
  if (is_homoglyph_domain(from_org_domain)) { return true;
}
  const std::string sld = domain_stem(from_org_domain);
  // Combosquat: a hyphen-delimited token is a distinctive brand, but the whole stem
  // is not itself a brand. The generic guard keeps a legit hyphenated name
  // (france-telecom, partners-llc) from firing.
  if (sld.size() >= 4 && sld.find('-') != std::string::npos && brand_tier(sld) == 0) {
    std::size_t start = 0;
    while (start <= sld.size()) {
      const std::size_t dash = sld.find('-', start);
      const std::size_t len = (dash == std::string::npos) ? sld.size() - start : dash - start;
      if (len >= 4 && is_distinctive_brand(sld.substr(start, len))) { return true;
}
      if (dash == std::string::npos) { break;
}
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
  if (display_name.empty() || from_org_domain.empty()) { return m;
}
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
  auto const match_brand = [&](const DisplayToken& t) -> Match {
    // A generic word (france, partners, support, ...) never matches as a brand even
    // when it is coincidentally a Tranco stem; the role/continuation lists win.
    // len>=3 admits the curated short brands (DHL/UPS/SFR); brand_tier returns 0 for
    // any other 3-char token, so the noise floor is unchanged.
    if (t.plain.size() >= 3 && !is_generic_token(t.plain)) {
      const int tt = brand_tier(t.plain); if (tt) { return {tt, &t.plain};
}
    }
    if (t.perturbed && t.conf.size() >= 3 && !is_generic_token(t.conf)) {
      // Conservative capital-I->l fold: unambiguous, so admitted at any tier
      // (DecathIon -> decathlon, Tier-2).
      const int tt = brand_tier(t.conf); if (tt) { return {tt, &t.conf};
}
    }
    if (t.conf_hg != t.conf && t.conf_hg.size() >= 3 && !is_generic_token(t.conf_hg)) {
      // Aggressive digit/rn homoglyph fold (PayPa1 -> paypal, AMAZ0N -> amazon).
      //
      // TIER-1 ONLY UNTIL 2026-08-29 (FN2, TASK-251), on the worry that a digit
      // coincidence would fold onto a dictionary-word brand and false-fire. That
      // left 'AMAZ0N' raising no claim at all while 'PayPa1' did, and the domain
      // fold already covered BOTH tiers (amaz0n.com fires), so the display path
      // was the odd one out rather than the careful one.
      //
      // The worry was reasonable and turned out to be unfounded, and that is a
      // measurement rather than an argument. Admitting Tier-2 here is 0/30 on the
      // brand-impersonation battery's ham classes and 0/32 on its legit-FP gate,
      // and on the 1,479-message transactional ham panel it changes NOTHING:
      // display_impersonation fires on exactly 35 messages with the gate and 35
      // without it, the same 35, measured by building both ways. The reason is
      // structural: this branch only runs when the fold CHANGED the token
      // (conf_hg != conf), so an ordinary all-letter display never reaches it,
      // and the Tier-2 shape guard below still requires every other token to be
      // a role word, owned, or a brand.
      const int tt = brand_tier(t.conf_hg); if (tt) { return {tt, &t.conf_hg};
}
    }
    return {0, nullptr};
  };
  // A token whose plain OR folded form sits at the front of the sending domain is
  // an owned look-alike, not a spoof of that token (TASK-230 homoglyph-aware).
  auto const token_owned = [&](const DisplayToken& t) {
    return owns_prefix(t.plain) || (t.perturbed && owns_prefix(t.conf));
  };
  // A digit-obfuscated role word must not break the impersonation shape
  // (TASK-268): '1' reads as BOTH 'l' and 'i', so try the shared conf_hg fold
  // (1->l, rn->m: "A1ert") and the 1->i leet reading ("Serv1ce", "B1ll1ng").
  // The digit guard skips the second fold for the common all-letter token.
  auto const digit_obfuscated_role = [](const DisplayToken& t) {
    if (t.conf_hg != t.plain && is_role_word(t.conf_hg)) { return true;
}
    if (t.plain.find_first_of("013457") == std::string::npos) { return false;
}
    return is_role_word(leet_fold(t.plain, 'i', /*fold_rn=*/false));
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
    if (mt.tier && *mt.form == fstem) { return m;  // (a) sender IS this brand's bare domain
}
  }
  std::string lead_plain;
  std::string lead_conf;
  for (const DisplayToken& t : tokens) {
    lead_plain += t.plain;
    lead_conf += t.perturbed ? t.conf : t.plain;
    if (lead_plain == fstem || lead_conf == fstem) { return m;  // (b) leading tokens spell the stem
}
    if (lead_plain.size() >= fstem.size()) { break;  // == lead_conf.size() (conf fold is 1:1)
}
  }

  bool tier2_present = false;
  bool ambiguous_present = false;
  bool distinctive_leftover = false;
  std::vector<std::string> leftover_candidates;
  std::string tier1_brand;
  std::string tier2_brand;
  std::string ambiguous_brand;
  for (const DisplayToken& t : tokens) {
    if (token_owned(t)) { continue;              // an owned look-alike token is a different signal
}
    const Match mt = match_brand(t);
    if (mt.tier == 1 && mt.form == &t.plain && is_ambiguous_brand(t.plain)) {
      // Ambiguous Tier-1 (surname-brand, TASK-268): Tier-1 strength but only with
      // the impersonation shape, resolved after the loop. ONLY the unperturbed
      // spelling qualifies: a homoglyph fold ("B0ulanger" -> boulanger) has no
      // personal-name population, so it stays plain Tier-1 below.
      ambiguous_present = true;
      if (ambiguous_brand.empty()) { ambiguous_brand = t.plain;
}
    }
    else if (mt.tier == 1) { m.tier1 = true; if (tier1_brand.empty()) { tier1_brand = *mt.form;
}}
    else if (mt.tier == 2) { tier2_present = true; if (tier2_brand.empty()) { tier2_brand = *mt.form;
}}
    else if (t.plain.size() >= 4 && t.plain.find_first_not_of("0123456789") != std::string::npos &&
             !is_role_word(t.plain) && !is_brand_continuation(t.plain) &&
             !digit_obfuscated_role(t)) {
      // A non-brand, non-role, non-corporate word breaks the shape. An all-digit
      // token (an order number) and a digit-obfuscated role word ("Serv1ce",
      // "A1ert") are attacker-typical filler, not a person's distinctive name,
      // so they do NOT break it (TASK-268).
      //
      // DEFERRED, not decided here: whether the word is a product line depends
      // on WHICH brand was matched, and the matching brand is not known until
      // this loop finishes. Deciding it inline is what produced the global list
      // that fired on "Live Music" and "Live Nation".
      leftover_candidates.push_back(t.plain);
    }
  }
  // A leftover that is a product line OF THE BRAND MATCHED does not break the
  // shape: "Amazon Prime" is Amazon. A product line of some other company does:
  // "Live Music" is not Live, and "music" is only Apple's and Amazon's word.
  for (const std::string& leftover : leftover_candidates) {
    const bool owned =
        (!tier1_brand.empty() && is_product_line_of(tier1_brand, leftover)) ||
        (!tier2_brand.empty() && is_product_line_of(tier2_brand, leftover)) ||
        (!ambiguous_brand.empty() && is_product_line_of(ambiguous_brand, leftover));
    if (!owned) {
      distinctive_leftover = true;
      break;
    }
  }
  // An ambiguous brand with the shape intact condemns standalone ("Boulanger
  // Support", bare "Norton"); a distinctive leftover is a personal name
  // ("Edmond Boulanger") and the claim is dropped entirely, it does not even
  // count as Tier-2 (no corroborated condemn on a person's surname).
  if (ambiguous_present && !distinctive_leftover && !m.tier1) {
    m.tier1 = true;
    tier1_brand = ambiguous_brand;
  }
  m.tier2 = tier2_present && !distinctive_leftover;
  m.brand = m.tier1 ? tier1_brand : (m.tier2 ? tier2_brand : std::string());
  return m;
}

} // namespace spam_engine::brand_names
