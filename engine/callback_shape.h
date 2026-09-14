#pragma once
// Brand-independent callback phishing: the shape, without a brand (TASK-440, C).
//
// The family is a fake renewal invoice that carries NO LINK and a PHONE NUMBER.
// You are meant to call, and the payload arrives during the call, in a "support
// session" the caller talks you into starting. TASK-440 shipped the brand half
// (key Geek Squad, Norton, McAfee and the carriers in brand_kb), which covers
// only the lures that name a brand somebody has already listed. The reported
// scam that started this reads "Billing Department" and names nothing, and the
// brand path can never reach it.
//
// WHY THESE PREDICATES. Measured with model-lab/scripts/measure_callback_shape.py
// over 3,621 invoice-ish messages from the founder's four real mailboxes (the
// ham panel that decides this), 8,000 messages of their ordinary mail, and 7,083
// invoice-ish messages from the trap corpus:
//
//   rule                                    trap hits   FP on real invoices
//   billing + phone                              256          123  (3.4%)
//   billing + phone + no_link                    203           15  (0.4%)
//   billing + phone + no_link + no dmarc=pass    203            0
//   ... + a call-to-cancel phrase                  1            0
//
// The asymmetry that makes it work: a real invoice wants you in a portal, so it
// links. This lure removes links deliberately, because a link is what URL
// reputation reads. `no_link` does most of the separating; `billing` and `phone`
// describe the genre; and requiring an unverifiable sender removes the last 15.
//
// TWO THINGS THIS GOT WRONG FIRST, both worth keeping:
//
// 1. The phone matcher was North-American-shaped, because the census regex it
//    was copied from was. That version had 0 false positives and 56 trap hits,
//    and it would have been dead weight on French mail, which is most of what we
//    filter. Widening it to international and French national forms tripled the
//    catch (56 -> 203) and introduced 15 false positives.
// 2. The auth condition was left out on the argument that it "buys nothing",
//    which was measured on the narrow matcher and stopped being true the moment
//    the matcher widened. On the shipped matcher it removes every false positive
//    at no measured cost. Required, not preferred.
//
// The auth condition is applied at the OFFSET (spam_engine_c_api.cpp), not here:
// this header answers "is this message shaped like the lure", which is a fact
// about the content, and the decision layer decides what that is worth given who
// sent it. It also means the shape is still reported for a message that
// authenticates, so a reader can see it.
//
// VERIFIED AGAINST THE SHIPPED CODE, not only against the Python that chose the
// rule (`make model-lab/verify-callback-shape`, which drives classify_full over
// the same panel). On 3,620 invoice-ish messages from the six real mailboxes the
// shape fires 15 times and 0 of those survive the auth condition, which is what
// the Python reported to the message. On the fixtures, 7 of 8 fire and the one
// that does not is the legitimate control.
//
// Worth running after any edit here. The two implementations have disagreed
// twice on a corpus while agreeing on a table of strings: once on digit grouping
// (this accepted any ten digits with two separators, so "12 3456 7890" matched)
// and once on whether a run is retried from every position (a reference number
// next to a phone number hid it, because Python's re.search tries every position
// and this did not).
//
// KNOWN BLIND SPOT: a lure from a COMPROMISED domain that authenticates is not
// reached. The TASK-439 family does exactly that, and it needs the model.
//
// STRENGTH: corroborating, never a solo condemn. kCallbackShape is 0.30, so a
// message needs to be at 0.69 from the model already before this can carry it
// over the gate. 0 of 3,621 bounds the true false-positive rate at about 0.08%,
// not at zero, and an invoice is the single most damaging message to junk.
//
// NOT REGEX, and not by preference: the equivalent std::regex scan costs more
// than the rest of preprocessing on a message this size. The three matchers
// below mirror the measured Python patterns exactly, and
// test_callback_shape_matcher_parity pins them against the same strings.
#include <algorithm>
#include <cctype>
#include <initializer_list>
#include <string>
#include <vector>

namespace callback_shape {

// en/fr/de. The lure has to say what it is billing you for, in the recipient's
// language, which is the one thing it cannot obfuscate away.
inline const std::vector<std::string>& billing_terms() {
  static const std::vector<std::string> terms = {
      "invoice", "receipt", "billing", "subscription", "renewal", "renewed",
      "auto-renew", "autorenew", "order confirmation",
      "facture", "abonnement", "renouvellement", "renouvele", "prelevement",
      "rechnung", "abrechnung", "verlangerung", "quittung",
  };
  return terms;
}

// Lowercased, whitespace collapsed to single spaces, accents folded to ASCII for
// the handful of letters the lexicon needs. Mail is hard-wrapped at ~76 columns,
// so a term or a number can straddle a newline: matching the raw part is how the
// first draft of the measurement scored 0% on its own fixtures.
inline std::string normalize(const std::string& in) {
  std::string out;
  out.reserve(in.size());
  bool in_space = false;
  for (size_t i = 0; i < in.size(); ++i) {
    auto const c = static_cast<unsigned char>(in[i]);
    // The UTF-8 two-byte block that carries é/è/ê/ü/ä/ö: fold to the base letter
    // so "prélèvement" and "prelevement" are the same term.
    if (c == 0xC3 && i + 1 < in.size()) {
      auto const n = static_cast<unsigned char>(in[i + 1]);
      char folded = 0;
      if (n >= 0xA0 && n <= 0xA5) { folded = 'a';
      } else if (n >= 0xA8 && n <= 0xAB) { folded = 'e';
      } else if (n >= 0xAC && n <= 0xAF) { folded = 'i';
      } else if (n >= 0xB2 && n <= 0xB6) { folded = 'o';
      } else if (n >= 0xB9 && n <= 0xBC) { folded = 'u';
      } else if (n == 0xA7) { folded = 'c';
}
      if (folded != 0) { out += folded; ++i; in_space = false; continue; }
    }
    if (std::isspace(c)) {
      if (!in_space && !out.empty()) { out += ' ';
}
      in_space = true;
      continue;
    }
    in_space = false;
    out += static_cast<char>(std::tolower(c));
  }
  return out;
}

inline bool has_billing_language(const std::string& normalized) {
  return std::any_of(billing_terms().begin(), billing_terms().end(),
                      [&](const std::string& t) {
                        return normalized.find(t) != std::string::npos;
                      });
}

inline bool has_link(const std::string& normalized) {
  return normalized.find("http://") != std::string::npos ||
         normalized.find("https://") != std::string::npos;
}

namespace detail {

inline bool is_sep(char c) {
  return c == ' ' || c == '.' || c == '-' || c == '(' || c == ')';
}

// A run of phone-ish characters starting at `start`: where it ends, how many
// digits it holds, and the SIZE OF EACH DIGIT GROUP. The groups are the part
// that matters, and counting digits and separators instead was this matcher's
// third bug: "12 3456 7890" is ten digits with two separators and is not a phone
// number in any format, while the Python pattern the false-positive rate was
// measured with requires 3-3-4 exactly. A matcher looser than the pattern that
// was measured has an unmeasured false-positive rate, which is the same as not
// having measured it.
struct Run {
  size_t end;
  int digits;
  std::vector<int> groups;
};

// A phone number is at most an international prefix plus 15 digits plus their
// separators, so nothing longer than this can be one. The bound is not cosmetic:
// every candidate start is tried (see has_callback_number), and without a cap a
// body of "1 1 1 1 ..." would be one enormous run scanned from every position,
// which is quadratic work an attacker chooses. With it the scan is O(64n).
inline constexpr size_t kMaxPhoneRun = 64;

inline Run scan_run(const std::string& s, size_t start) {
  Run r{start, 0, {}};
  int current = 0;
  const size_t limit = std::min(s.size(), start + kMaxPhoneRun);
  for (size_t i = start; i < limit; ++i) {
    char const c = s[i];
    if (std::isdigit(static_cast<unsigned char>(c))) {
      ++r.digits;
      ++current;
      r.end = i + 1;
      continue;
    }
    if ((is_sep(c) || c == '+') && (i + 1 < s.size() &&
          (std::isdigit(static_cast<unsigned char>(s[i + 1])) || is_sep(s[i + 1]) ||
           s[i + 1] == '+')))
      // A separator only continues a run if a digit follows it, so a number at
      // the end of a sentence does not swallow the following words.
      {
        if (current > 0) { r.groups.push_back(current); current = 0; }
        continue;
      }

    break;
  }
  if (current > 0) { r.groups.push_back(current);
}
  return r;
}

inline bool groups_are(const std::vector<int>& g, std::initializer_list<int> want) {
  return g.size() == want.size() && std::equal(g.begin(), g.end(), want.begin());
}

// NNN NNN NNNN, optionally behind a country digit: the North American shape the
// census regex matched, group for group.
inline bool na_shape(const std::vector<int>& g) {
  return groups_are(g, {3, 3, 4}) || groups_are(g, {1, 3, 3, 4});
}

// An international number: a leading '+', a country code, and 9 to 15 digits in
// total, however they are grouped. This is the one that reaches French and
// Belgian mail, which is most of what we filter. The '+' is what makes loose
// grouping safe here: nothing else in an invoice starts that way.
inline bool intl_shape(bool leading_plus, int digits) {
  return leading_plus && digits >= 9 && digits <= 15;
}

// The French national form, 0X XX XX XX XX. The grouping is the whole check: it
// is what keeps this off the long digit runs an invoice is full of, an order id
// or a customer reference.
inline bool fr_shape(bool leading_zero, const std::vector<int>& g) {
  return leading_zero && groups_are(g, {2, 2, 2, 2, 2});
}

}  // namespace detail

// A callback number: something a human is meant to dial. Deliberately narrower
// than "a long number", because an invoice is FULL of long numbers: an invoice
// id, an order reference, a VAT number, an amount. Every accepted shape needs
// either an international prefix or explicit grouping.
inline bool has_callback_number(const std::string& normalized) {
  for (size_t i = 0; i < normalized.size(); ++i) {
    const char c = normalized[i];
    const bool starts = std::isdigit(static_cast<unsigned char>(c)) || c == '+' || c == '(';
    if (!starts) { continue;
}
    // Not mid-token: "abc123" and "1.2.3.4" are not phone numbers.
    if (i > 0) {
      const auto prev = static_cast<unsigned char>(normalized[i - 1]);
      if (std::isalnum(prev) || prev == '.' || prev == '/' || prev == '-') { continue;
}
    }
    const bool leading_plus = (c == '+');
    const detail::Run r = detail::scan_run(normalized, i);
    if (r.digits == 0) { continue;
}
    const bool leading_zero = std::isdigit(static_cast<unsigned char>(c)) && c == '0';
    // A trailing alphanumeric means the run was part of something longer.
    if (r.end < normalized.size() &&
        std::isalnum(static_cast<unsigned char>(normalized[r.end]))) {
      continue;
    }
    if (detail::intl_shape(leading_plus, r.digits) ||
        detail::na_shape(r.groups) ||
        detail::fr_shape(leading_zero, r.groups)) {
      return true;
    }
    // Do NOT skip to the end of the run. A reference number immediately followed
    // by a phone number ("1234567890 +33 1 42 68 53 00") is ONE run under the
    // rule above, and the run as a whole matches no shape, so skipping it missed
    // the number entirely. Every position that could start a number is tried
    // instead; the guard at the top of the loop rejects the ones that are mid-
    // token, and kMaxPhoneRun bounds the work.
  }
  return false;
}

// The shape itself. `subject` and `body` are the decoded text the preprocessor
// already holds; nothing here re-parses the message.
// DO NOT bound the body scanned here. It is tempting (a milter sees arbitrary
// mail) and it is unsafe in one direction: `no_link` has to be true of the WHOLE
// body, so a cap that hid a link past its end would make this fire on a message
// that has one, which is the false-positive direction the whole rule is built to
// avoid. The scan is already linear (kMaxPhoneRun bounds the only quadratic
// part), so there is nothing to buy.
inline bool matches(const std::string& subject, const std::string& body) {
  const std::string nbody = normalize(body);
  if (has_link(nbody)) { return false;
}
  if (!has_callback_number(nbody)) { return false;
}
  return has_billing_language(normalize(subject)) || has_billing_language(nbody);
}

}  // namespace callback_shape
