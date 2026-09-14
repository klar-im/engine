#pragma once
// "Do not check with your bank": the bank-advisor scam's second message (TASK-460).
//
// THE MESSAGE. A victim published an account of losing 10,000 EUR to the faux
// conseiller bancaire scam. The chain has two emails. The first is a fake
// subscription notice that harvests the card, and the domain path catches it.
// The second arrives DURING the phone call, to make the transfer look official:
// a "compte de securisation" with an IBAN, and an instruction not to telephone
// the bank while the "procedure" runs. The shipping model reads that second
// message as ordinary banking correspondence, 0.0268 spam / 0.9769 regular,
// because it IS written as ordinary banking correspondence. Nothing structural
// touched it either: it claims no brand, so the combosquat and
// claimed-vs-authenticated paths have nothing to fire on.
//
// WHY THIS PREDICATE AND NOT THE OBVIOUS ONES. Measured before anything was
// written (model-lab/scripts/measure_secured_account_shape.py), over the spam
// fixtures, an authored nine-message family, 153,806 trap messages, five ham
// fixtures and 21,291 real ham messages from the founder's mailboxes:
//
//   rule                      recall(9)  ham fixt(5)  corpus ham(21,291)  trap
//   no_contact                 9 (100%)      0             0                1
//   beneficiary + no_contact   8 ( 89%)      0             0                0
//   security_id                8 ( 89%)      4 (80%)    0.03-0.10%        224
//   iban                       7 ( 78%)      0          0.38-0.75%         77
//
// 21,291 is the DISTINCT ham-labelled population of the four source mailboxes.
// An earlier draft said 25,982 by summing the census's ham rows, two of which
// re-scan mailboxes the others already cover; the census now computes the
// distinct figure so a magnitude cannot be derived off a double count again.
//
// Every other candidate keys on something a REAL BANK ALSO DOES. `iban` fires on
// 0.38-0.75% of real mail because every European invoice carries the seller's
// IBAN. `security_id` looked survivable at 0.03-0.10% on corpus and then fired
// on FOUR OF FIVE ham fixtures: a bank's own prevention notice, a press piece
// about the scam, and the victim's testimony all say "service securite".
//
// This one is different in kind. A bank telling you not to contact your bank is
// self-contradictory, so no legitimate sender has a reason to write it. The
// predicate is not a proxy for the genre; it is the genre's DEFINING ACT, which
// is why one predicate suffices where three did not and why adding a second only
// costs recall (beneficiary + no_contact is 8/9 for no false-positive benefit).
//
// WHAT SEPARATES IT FROM PROSE ABOUT THE SCAM, which is the failure mode that
// matters most here: the ham fixtures are a victim's testimony, a bank warning
// and a press piece, all carrying this vocabulary. A victim writes REPORTED
// speech about someone else's instruction and about their OWN bank -- "il m'a
// dit de ne pas contacter MON agence". The lure gives an imperative about YOUR
// bank. So the possessive is load-bearing: `votre`/`l'`/`la` match and `mon`/`ma`
// do not. That is the whole reason the ham fixtures score 0 while sharing every
// other word with the lures, and it is asserted in the tests.
//
// THE POSSESSIVE GUARDS THE CLAUSE PATH AND ONLY THE CLAUSE PATH, which is a
// caveat this block did not carry until a cold review asked for it. There used
// to be a second, unconditional list of literal phrases beside the clause
// matcher, holding "stay on the line", "ne raccrochez pas" and their siblings.
// Those bypassed the possessive entirely, so the separation above was true in
// French and false in English: "the caller told me to stay on the line and not
// to phone my branch" is reported speech and was junked at 0.99, as were a
// conference-bridge invitation, a support-queue hold and an airline booking
// update. The census bound did not see it because 21,291 mostly-French messages
// contain no English call-service mail. **A rule-of-three bound is a bound on
// the population measured, and the population is chosen, not given.** Those
// phrases are now corroborators (see call_management_phrases below) and the
// four measured false positives are pinned as negative cases in the parity
// test, where four of them previously sat pinned as POSITIVE ones.
//
// THE VERB LIST IS MEASURED, NOT GUESSED, and it has already been wrong once.
// The first version covered "contacter" and "raccrocher" only, and missed the
// authored variant saying "ne pas PREVENIR votre agence" -- the same instruction
// with a different verb. A rule pinned to two verbs is pinned to the one message
// we were shown. Nine authored variants caught that in an afternoon; no corpus
// acquisition would have. Widened to the semantic core (do not TELL your bank,
// however the language says "tell") it is 9/9 with the ham panels unmoved.
//
// NOT A REGEX, deliberately: the Python census regex is the SPECIFICATION and
// this scanner is the implementation, and `make model-lab/verify-no-contact`
// runs both over the same corpus because the two have disagreed twice before on
// the callback shape while agreeing on a table of strings.
//
// KNOWN BLIND SPOT, stated because it is real and it bounds what this can do:
// the instruction is load-bearing for the SCAM but not mandatory in this
// MESSAGE. A scammer who says it on the call instead of writing it leaves a mail
// that is back to 0.0268 with nothing structural to fire on. That variant needs
// the model, not this.
//
// The auth condition (no dmarc=pass) lives at the OFFSET site in
// spam_engine_c_api.cpp, not here: this header answers "is the message shaped
// like the lure", a fact about content, and the decision layer decides what that
// is worth given who sent it. It also means the shape is still reported for a
// message that authenticates, so a reader can see it.

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <string>
#include <vector>

#include "callback_shape.h"  // normalize(): lowercase, collapse, fold accents

namespace no_contact_shape {

// Start from the callback shape's normaliser (lowercase, whitespace collapsed,
// the UTF-8 0xC3 block folded) and then finish the job it does not do. Measured
// misses on the borrowed version alone, every one of them a form a French sender
// actually produces:
//
//   NE PAS PRÉVENIR VOTRE AGENCE   uppercase accents: 0xC3 0x89 is not in the
//                                  lowercase fold range, so É survived
//   pre<U+0301>venir               decomposed (NFD), which is what a Mac types
//   l'agence with U+2019           the smart apostrophe every mail client
//                                  substitutes for '
//   don't with U+2019              same, in English
//
// A phrase matcher that misses the apostrophe its own senders type is not a
// matcher.
//
// THIS CANNOT BE A POST-PASS OVER callback_shape::normalize, which was the first
// attempt. That normaliser lower-cases with locale std::tolower, which on this
// platform folds the Latin-1 range: the 0xC3 lead byte of É becomes 0xE3 before
// any later stage sees it, so the uppercase and decomposed forms arrive as
// mojibake that no table can recover. It is the same locale bug that corrupted
// IDN domains until to_lower_ascii was fixed, still live on the body path. So this
// is standalone: fold FIRST, lower-case ASCII only, never touch a byte >= 0x80.
inline std::string normalize(const std::string& in) {
  std::string out;
  out.reserve(in.size());
  bool in_space = false;
  for (std::size_t i = 0; i < in.size();) {
    const auto c = static_cast<unsigned char>(in[i]);
    if (i + 1 < in.size()) {
      const auto n = static_cast<unsigned char>(in[i + 1]);
      // Combining diacritics U+0300..U+036F: drop, leaving the base letter, so
      // the decomposed spelling a Mac produces folds onto the precomposed one.
      if (c == 0xCC || (c == 0xCD && n <= 0xAF)) { i += 2; continue; }
      if (c == 0xC3) {
        char folded = 0;
        // Lower-case Latin-1 Supplement.
        if (n >= 0xA0 && n <= 0xA5) { folded = 'a';
        } else if (n >= 0xA8 && n <= 0xAB) { folded = 'e';
        } else if (n >= 0xAC && n <= 0xAF) { folded = 'i';
        } else if (n >= 0xB2 && n <= 0xB6) { folded = 'o';
        } else if (n >= 0xB9 && n <= 0xBC) { folded = 'u';
        } else if (n == 0xA7) { folded = 'c';
        } else if (n == 0xB1) { folded = 'n';
        // Upper-case, which the borrowed normaliser never handled.
        } else if (n >= 0x80 && n <= 0x85) { folded = 'a';
        } else if (n >= 0x88 && n <= 0x8B) { folded = 'e';
        } else if (n >= 0x8C && n <= 0x8F) { folded = 'i';
        } else if (n >= 0x92 && n <= 0x96) { folded = 'o';
        } else if (n >= 0x99 && n <= 0x9C) { folded = 'u';
        } else if (n == 0x87) { folded = 'c';
        } else if (n == 0x91) { folded = 'n';
}
        if (folded != 0) { out.push_back(folded); i += 2; in_space = false; continue; }
      }
    }
    // U+2018/U+2019 curly quotes -> the ASCII apostrophe the patterns use.
    if (c == 0xE2 && i + 2 < in.size() &&
        static_cast<unsigned char>(in[i + 1]) == 0x80 &&
        (static_cast<unsigned char>(in[i + 2]) == 0x99 ||
         static_cast<unsigned char>(in[i + 2]) == 0x98)) {
      out.push_back('\'');
      i += 3;
      in_space = false;
      continue;
    }
    if (c < 0x80 && std::isspace(c)) {
      if (!in_space && !out.empty()) { out.push_back(' ');
}
      in_space = true;
      ++i;
      continue;
    }
    in_space = false;
    // ASCII ONLY. A byte >= 0x80 passes through untouched; locale case-folding
    // above 0x7F is what produced the mojibake this function exists to avoid.
    out.push_back((in[i] >= 'A' && in[i] <= 'Z')
                      ? static_cast<char>(in[i] - 'A' + 'a')
                      : in[i]);
    ++i;
  }
  return out;
}

// Phrases that need no structure because they are unambiguous on their own. A
// legitimate sender has no reason to tell you to stay on a call.
// SUFFICIENT ON THEIR OWN, because each one NAMES THE BANK and says not to
// contact it. That is the defining act spelled out, not a proxy for it. German
// only: French and English express the same thing through the clause matcher
// below, which is why there is no "ne contactez pas votre banque" literal here.
// Full clauses, never fragments: "ihre bank nicht" alone would fire on "wenn
// ihre bank nicht erreichbar ist" (if your bank is not reachable).
inline const std::vector<std::string>& instruction_phrases() {
  static const std::vector<std::string> p = {
      "kontaktieren sie ihre bank nicht", "informieren sie ihre bank nicht",
      "benachrichtigen sie ihre bank nicht",
  };
  return p;
}

// NOT SUFFICIENT ON THEIR OWN, and this cost a real bug. These say "stay on the
// call", which is what the scammer needs and ALSO what every conference bridge,
// support queue and airline hold message says. Until 2026-08-29 they were in
// the list above, unconditional, at a 0.99 condemn-level weight, and all four of
// these fired:
//
//   "Please stay on the line while we connect your conference call"   junked
//   "An agent will be with you shortly. Please stay on the line."     junked
//   "Do not hang up; your booking is being updated."                  junked
//   "The caller told me to stay on the line and not to phone my       junked
//    branch."                                            (REPORTED SPEECH)
//
// The last one is the tell. The possessive discriminator documented in the
// header block is real but guards the CLAUSE path only, so this list was a hole
// straight through it: an English victim recounting the scam was junked while
// the French one was not. The 0-of-21,291 census bound did not catch it because
// that population is overwhelmingly French and holds no English call-service
// mail. A rule-of-three bound is only ever a bound ON THE POPULATION MEASURED.
//
// So they now require corroboration: a second-person prohibition somewhere in
// the message (see below). That keeps the one authored variant that depends on
// them, spam-fr-no-iban-hangup, whose instruction is "n'appelez pas le numero
// ... au dos de VOTRE carte" -- a real prohibition whose object is a card rather
// than a bank, so the clause matcher alone does not see it.
inline const std::vector<std::string>& call_management_phrases() {
  static const std::vector<std::string> p = {
      // fr
      "restez en ligne", "ne raccrochez pas", "ne quittez pas la ligne",
      // en
      "stay on the line", "do not hang up", "dont hang up", "don't hang up",
      // de
      "bleiben sie in der leitung", "legen sie nicht auf",
  };
  return p;
}

namespace detail {

// The verbs for "tell", in the forms an imperative or an infinitive takes. Both
// French conjugations are listed because "ne CONTACTEZ pas" and "ne pas
// CONTACTER" are both natural and the scam uses both.
inline const std::vector<std::string>& fr_verbs() {
  static const std::vector<std::string> v = {
      "contactez", "contacter", "prevenez", "prevenir", "signalez", "signaler",
      "alertez", "alerter", "appelez", "appeler", "joignez", "joindre",
      "informez", "informer",
  };
  return v;
}

inline const std::vector<std::string>& en_verbs() {
  static const std::vector<std::string> v = {
      "contact", "call", "notify", "inform", "alert", "tell", "phone",
  };
  return v;
}

// The thing you are told not to tell. YOUR bank, never MY bank: see the
// reported-speech note in the header block. "mon"/"ma"/"mes" are absent on
// purpose and adding them would fire on every victim's account of the scam.
inline const std::vector<std::string>& fr_objects() {
  static const std::vector<std::string> o = {
      "agence", "banque", "conseiller", "service client", "etablissement",
      "banquier",
  };
  return o;
}

// The second-person possessives, and the ONLY forms accepted before the object.
//
// A list rather than two literals because the Python census has to mirror it,
// and it was a hardcoded copy in the generator until this rule tightened: the
// C++ started requiring "votre"/"vos" while the regex still accepted "l'", "la",
// "le" and no possessive at all, which the parity fuzz reported as 1,942
// disagreements. The verb and object lists were already read from here for
// exactly this reason; the possessives were the one part still written twice.
inline const std::vector<std::string>& fr_second_person() {
  static const std::vector<std::string> p = {" votre ", " vos "};
  return p;
}

inline const std::vector<std::string>& en_objects() {
  static const std::vector<std::string> o = {
      "bank", "branch", "advisor", "adviser", "banker",
  };
  return o;
}

// A CHANNEL QUALIFIER TURNS THE INSTRUCTION INTO ADVICE, and missing this was
// the third and worst instance of the same mistake in this rule's short life.
//
// The header block below claims a bank telling you not to contact your bank is
// self-contradictory, so no legitimate sender writes it. That is FALSE, and
// consumer security advice is the counter-example: "ne contactez pas votre
// banque EN CLIQUANT SUR UN LIEN", "kontaktieren Sie Ihre Bank nicht ÜBER LINKS
// in E-Mails", "do not contact your bank BY CLICKING a link". All three were
// junked at 0.99. This is mail banks and consumer bodies send on purpose, and
// the one ham fixture in that register scored 0 only because it happens to
// phrase its advice positively ("contactez votre agence si vous avez un doute").
//
// The 0-of-21,291 bound did not see it for the same reason it did not see the
// English call-service mail: the corpus is thin in that genre. THAT IS THREE
// TIMES the population bound has been quoted for coverage it does not have.
//
// The discriminator is what the instruction is qualified BY. The lure qualifies
// by TIME, because it needs the victim not to check until the transfer clears:
// "pendant la procedure", "while this is in progress", "solange der Vorgang
// laeuft". Advice qualifies by MEANS: not through this channel, use a safe one.
// So a means qualifier within a short window after the object disqualifies.
inline const std::vector<std::string>& channel_qualifiers() {
  static const std::vector<std::string> q = {
      // fr
      "par e-mail", "par email", "par mail", "par sms", "par telephone",
      "en cliquant", "sur un lien", "via un lien", "par retour", "par ce lien",
      "depuis ce message", "par messagerie",
      // "sur un numero indique dans un message". The English twin of this
      // ("on a number given") was in the list from the start and the French one
      // was not, in a rule measured on a French corpus -- the same language
      // asymmetry that produced the first two false-positive rounds. It was
      // caught by the ham fixture written for this very fix, not by a probe.
      "sur un numero", "au numero indique", "a un numero", "sur le numero",
      // en
      "by clicking", "by email", "by e-mail", "by replying", "by phone",
      "by sms", "by text", "via a link", "via this link", "through a link",
      "on a number given", "from this message", "in this email",
      // de. normalize() folds the umlaut, so "ueber" and "uber" both occur.
      "ueber links", "uber links", "ueber einen link", "uber einen link",
      "per e-mail", "per email", "per sms", "telefonisch", "ueber diesen",
      "uber diesen", "unter einer nummer", "ueber eine nummer",
      "uber eine nummer",
  };
  return q;
}

// How far after the instruction a means qualifier still governs it. Sized to
// carry "votre banque EN CLIQUANT sur un lien" and the German equivalent, and
// short enough that an unrelated later sentence cannot exonerate the lure.
constexpr std::size_t kQualifierWindow = 48;

inline bool channel_qualified(const std::string& s, std::size_t i) {
  const std::size_t end = std::min(s.size(), i + kQualifierWindow);
  const std::string window = s.substr(i, end - i);
  return std::any_of(channel_qualifiers().begin(), channel_qualifiers().end(),
                      [&](const std::string& q) {
                        return window.find(q) != std::string::npos;
                      });
}

// Is position i the end of a word? End of string, or a non-letter. The matcher
// runs on normalized text, so "letter" is ASCII a-z here.
inline bool at_word_end(const std::string& s, std::size_t i) {
  return i >= s.size() || s[i] < 'a' || s[i] > 'z';
}

// Consume `lit` at position i, advancing i on success.
inline bool consume(const std::string& s, std::size_t& i, const char* lit) {
  const std::size_t n = std::char_traits<char>::length(lit);
  if (s.compare(i, n, lit) != 0) { return false;
}
  i += n;
  return true;
}

// Consume any one of `opts` at position i, longest first so "contacter" is not
// shadowed by a shorter prefix.
inline bool consume_any(const std::string& s, std::size_t& i,
                        const std::vector<std::string>& opts) {
  std::size_t best = 0;
  for (const std::string& o : opts) {
    if (o.size() > best && s.compare(i, o.size(), o) == 0) { best = o.size();
}
  }
  if (best == 0) { return false;
}
  i += best;
  return true;
}

// "ne [pas] <verb> [pas] [votre|l'|la] <object>", anchored at a "ne " already
// found by the caller. Mirrors the census regex's shape rather than a loose
// window, because a window admits two unrelated clauses and the Python is the
// specification this has to agree with.
inline bool fr_clause_at(const std::string& s, std::size_t i) {
  // "ne contactez" and "n'appelez" are both natural and the scam writes both.
  // The elided form was missing until 2026-08-29, which made "n'appelez pas
  // votre banque" a false negative on the clause path.
  if (!consume(s, i, "ne ") && !consume(s, i, "n'")) { return false;
}
  consume(s, i, "pas ");                       // "ne pas contacter ..."
  if (!consume_any(s, i, fr_verbs())) { return false;
}
  consume(s, i, " pas");                       // "ne contactez pas ..."
  // THE SECOND PERSON IS REQUIRED, and the definite article is not enough.
  //
  // `l'`, `la`, `le` and the bare no-possessive form were all accepted until a
  // cold review pointed at "le fraudeur m'a dit de ne pas contacter LA banque",
  // which is a fraud warning written by a victim and was being junked at 0.99 --
  // precisely the ham class the possessive discriminator exists to protect. The
  // article carries no person, so it cannot tell an instruction to the reader
  // from a report of one given to someone else.
  //
  // MEASURED before removing them: not one of the ten authored lures uses an
  // article on this clause. All ten say "votre". So the cost is zero recall for
  // a whole class of false positive, which is the same trade the possessive made
  // in the first place.
  if (!consume_any(s, i, fr_second_person())) { return false;
}
  if (!consume_any(s, i, fr_objects())) { return false;
}
  if (channel_qualified(s, i)) { return false;   // advice, not the instruction
}
  // The object must END here. Without this, "banque" matches inside "banque
  // alimentaire" (a food bank) and "agence" inside "agencement".
  return at_word_end(s, i);
}

// "do not|dont|don't <verb> your <object>"
inline bool en_clause_at(const std::string& s, std::size_t i) {
  if (!consume(s, i, "do not ") && !consume(s, i, "dont ") &&
      !consume(s, i, "don't ")) {
    return false;
  }
  if (!consume_any(s, i, en_verbs())) { return false;
}
  if (!consume(s, i, " your ")) { return false;
}
  if (!consume_any(s, i, en_objects())) { return false;
}
  if (channel_qualified(s, i)) { return false;   // advice, not the instruction
}
  return at_word_end(s, i);   // "bank" must not match inside "bank holiday"
}

// A second-person prohibition with ANY object: negation, a tell-verb, then a
// second-person possessive close behind. Weaker than the clause matchers above
// on purpose, and NEVER sufficient on its own -- it exists only to license a
// call-management phrase, because "do not call the number on YOUR card" is the
// same speech act as "do not call your bank" with an object no list will ever
// hold. Widening the object list instead would have bought the same recall at a
// real false-positive cost ("do not contact your account manager").
//
// The window is bounded so an unrelated "votre" three sentences later cannot
// license a phrase it has nothing to do with. 60 bytes covers the authored
// variant's "pas le numero figurant au dos de votre carte" with room, and is
// well short of a sentence boundary's worth of unrelated text.
constexpr std::size_t kPossessiveWindow = 60;

inline bool possessive_within(const std::string& s, std::size_t i,
                              const char* poss) {
  const std::size_t end = std::min(s.size(), i + kPossessiveWindow);
  const std::size_t at = s.find(poss, i);
  return at != std::string::npos && at < end;
}

// A QUALIFIED CLAUSE IS EXCLUDED HERE TOO, and forgetting that left the advice
// hole open through the side door. The qualifier guard was added to the clause
// matchers only, so "Do not contact your bank by clicking a link" was correctly
// rejected as sufficient and then accepted here as a corroborator, which is all
// tier 3 needs beside a "stay on the line". A bank's advice page that says both,
// which is a normal thing for a bank's advice page to say, was still junked at
// 0.99. Same guard, same window, same anchor.
inline bool fr_prohibition_at(const std::string& s, std::size_t i) {
  if (!consume(s, i, "ne ") && !consume(s, i, "n'")) { return false;
}
  consume(s, i, "pas ");
  if (!consume_any(s, i, fr_verbs())) { return false;
}
  consume(s, i, " pas");
  if (channel_qualified(s, i)) { return false;
}
  return possessive_within(s, i, "votre") || possessive_within(s, i, "vos ");
}

inline bool en_prohibition_at(const std::string& s, std::size_t i) {
  if (!consume(s, i, "do not ") && !consume(s, i, "dont ") &&
      !consume(s, i, "don't ")) {
    return false;
  }
  if (!consume_any(s, i, en_verbs())) { return false;
}
  if (channel_qualified(s, i)) { return false;
}
  return possessive_within(s, i, "your");
}

}  // namespace detail

// The instruction, in any of the forms above. Scans every candidate anchor
// rather than the first: a reference number or an unrelated "ne " earlier in the
// body must not hide the clause that follows it (the callback shape lost a whole
// class of matches to exactly that bug).
inline bool has_no_contact_instruction(const std::string& normalized) {
  // 1. A clause that names the bank and says not to contact it. Sufficient,
  //    UNLESS a means qualifier follows, which makes it security advice: these
  //    three German phrases were matched unconditionally and junked "Kontaktieren
  //    Sie Ihre Bank nicht ueber Links in E-Mails" at 0.99.
  //    EVERY occurrence, not the first. A single `find` meant that when the same
  //    German literal appeared once as qualified advice and again as the lure
  //    ("... nicht ueber Links ..." then "... nicht, solange der Vorgang
  //    laeuft"), the first one's qualifier suppressed the phrase and the second
  //    was never looked at. German has no fallback clause scanner, so the whole
  //    message scored 0 while the Python mirror, which uses finditer, scored 1:
  //    a false negative AND a parity divergence from one missing loop. The
  //    Python docstring states this rule; the C++ did not follow it.
  for (const std::string& p : instruction_phrases()) {
    for (std::size_t at = normalized.find(p); at != std::string::npos;
         at = normalized.find(p, at + 1)) {
      if (!detail::channel_qualified(normalized, at + p.size())) { return true;
}
    }
  }
  // 2. The clause matchers, also sufficient. A second-person prohibition with an
  //    unlisted object is collected on the same pass but only corroborates.
  bool prohibition = false;
  for (std::size_t i = 0; i + 3 <= normalized.size(); ++i) {
    if (normalized[i] == 'n') {
      if (detail::fr_clause_at(normalized, i)) { return true;
}
      if (!prohibition) { prohibition = detail::fr_prohibition_at(normalized, i);
}
    }
    if (normalized[i] == 'd') {
      if (detail::en_clause_at(normalized, i)) { return true;
}
      if (!prohibition) { prohibition = detail::en_prohibition_at(normalized, i);
}
    }
  }
  // 3. "Stay on the line" and friends, which every support queue also writes, so
  //    they count ONLY beside a prohibition. See call_management_phrases().
  if (!prohibition) { return false;
}
  return std::any_of(call_management_phrases().begin(), call_management_phrases().end(),
                      [&](const std::string& p) {
                        return normalized.find(p) != std::string::npos;
                      });
}

// The whole body, joined by the caller, plus the subject. Deliberately unbounded
// for the same reason callback_shape is: capping the scan would let a lure push
// the instruction past the cap, and this predicate is false-negative-safe rather
// than false-positive-safe.
inline bool matches(const std::string& subject, const std::string& body) {
  return has_no_contact_instruction(normalize(subject)) ||
         has_no_contact_instruction(normalize(body));
}

}  // namespace no_contact_shape
