#include "pii_scrub.h"

#include <cctype>
#include <regex>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace spam_engine {
namespace {

// Strip table: recipient identity + routing
// headers whose value, when it appears quoted in a body, must not leak.
const std::set<std::string>& recipient_headers() {
  static const std::set<std::string> s = {"to", "cc", "bcc"};
  return s;
}
const std::set<std::string>& dropped_headers() {
  static const std::set<std::string> s = {
      "delivered-to", "envelope-to", "x-original-to", "received",
      "authentication-results", "x-mailer", "user-agent", "x-originating-ip"};
  return s;
}

const std::string kPlaceholder = "<redacted>";

std::string to_lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

std::string trim(const std::string& s) {
  const size_t a = s.find_first_not_of(" \t");
  if (a == std::string::npos) return "";
  const size_t b = s.find_last_not_of(" \t");
  return s.substr(a, b - a + 1);
}

// A strip-table header name (lower-cased): the explicit set or the ARC-* family.
bool is_sensitive_name(const std::string& lower) {
  if (recipient_headers().count(lower) || dropped_headers().count(lower)) return true;
  return lower.rfind("arc-", 0) == 0;
}

std::vector<std::string> split_lines(const std::string& text) {
  std::vector<std::string> lines;
  std::string cur;
  for (const char c : text) {
    if (c == '\n') {
      lines.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  lines.push_back(cur);
  return lines;
}

// Strip leading quote markers ('>') and whitespace off a body line.
std::pair<std::string, std::string> de_quote(const std::string& line) {
  size_t i = 0;
  while (i < line.size() && (line[i] == '>' || line[i] == ' ' || line[i] == '\t')) i++;
  return {line.substr(0, i), line.substr(i)};
}

std::string value_after_colon(const std::string& s) {
  const size_t colon = s.find(':');
  if (colon == std::string::npos) return "";
  return trim(s.substr(colon + 1));
}

// If the de-quoted line starts a strip-table header (`name:` with a
// whitespace-free name), set prefix + original-case name and return true.
bool sensitive_header_start(const std::string& line, std::string& prefix, std::string& name) {
  const auto dq = de_quote(line);
  const std::string& rest = dq.second;
  const size_t colon = rest.find(':');
  if (colon == std::string::npos) return false;
  name = rest.substr(0, colon);
  if (name.empty()) return false;
  if (name.find(' ') != std::string::npos || name.find('\t') != std::string::npos) return false;
  if (!is_sensitive_name(to_lower(name))) return false;
  prefix = dq.first;
  return true;
}

// True for an RFC 5322 folded continuation line. Strips quote markers first
// (a quote marker is "> "; a fold adds extra leading whitespace beyond it).
bool is_fold_continuation(const std::string& line) {
  size_t i = 0;
  while (i < line.size() && line[i] == '>') {
    i++;
    if (i < line.size() && line[i] == ' ') i++;
  }
  return i < line.size() && (line[i] == ' ' || line[i] == '\t');
}

// True for an IPv6-looking token. Requires a `::` or a hex letter so pure-digit,
// colon-separated values (timestamps like 10:30:45, MACs) are NOT matched.
bool looks_like_ipv6(const std::string& s) {
  bool has_hex = false, has_colons = false;
  int colons = 0;
  for (char c : s) {
    if (c == ':') { colons++; has_colons = true; }
    else if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) has_hex = true;
    else if (!(c >= '0' && c <= '9')) return false;  // only hex digits + colons
  }
  if (colons < 2) return false;
  return s.find("::") != std::string::npos || has_hex;
}

// True if the text carries contact PII we must not leak: an email address or an
// IP literal (the routing IPs in `Received:` lines).
bool contains_contact_pii(const std::string& text) {
  if (text.find('@') != std::string::npos) return true;
  static const std::regex ipv4(R"(\b\d{1,3}(\.\d{1,3}){3}\b)");
  if (std::regex_search(text, ipv4)) return true;
  static const std::regex ipv6_candidate(R"([0-9A-Fa-f:]{2,45}:[0-9A-Fa-f:]{1,45})");
  std::smatch m;
  std::string s = text;
  auto begin = std::sregex_iterator(s.begin(), s.end(), ipv6_candidate);
  for (auto it = begin; it != std::sregex_iterator(); ++it)
    if (looks_like_ipv6(it->str())) return true;
  return false;
}

// Apply a regex over `body`, calling `accept` on each match's captured token;
// accepted matches are replaced with `placeholder`, the rest kept verbatim.
// (std::regex_replace can't make a per-match decision, hence the manual scan.)
std::string redact_where(const std::string& body, const std::regex& re,
                         const std::string& placeholder,
                         bool (*accept)(const std::string&)) {
  std::string out;
  auto last = body.cbegin();
  for (auto it = std::sregex_iterator(body.begin(), body.end(), re);
       it != std::sregex_iterator(); ++it) {
    const auto& m = *it;
    out.append(last, body.cbegin() + m.position());
    out += accept(m.str()) ? placeholder : m.str();
    last = body.cbegin() + m.position() + m.length();
  }
  out.append(last, body.cend());
  return out;
}

// Redact bare email addresses in body text, KEEPING the domain as spam signal
// (the local-part is the identifier): john.doe@evil.ru -> <email>@evil.ru.
std::string redact_emails(const std::string& body) {
  // Bounded quantifiers: libstdc++ std::regex recurses per matched char, so an
  // unbounded run of matching bytes from an attacker body stack-overflows. RFC
  // limits keep the bounds well above any real address (local<=64, domain<=255).
  static const std::regex re(R"(([A-Za-z0-9._%+\-]{1,64})@([A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}))");
  return std::regex_replace(body, re, "<email>@$2");
}

// Redact recipient identifiers hidden in URLs: percent-encoded addresses
// (victim%40x.com) and the values of common per-recipient tracking params.
std::string redact_url_identifiers(const std::string& body) {
  static const std::regex enc_email(R"([A-Za-z0-9._.+\-]{1,64}%(?:25)?40[A-Za-z0-9._%+\-]{1,255}\.[A-Za-z]{2,24})",
                                     std::regex::icase);
  std::string s = std::regex_replace(body, enc_email, "<email>");
  static const std::regex track(
      R"(([?&](?:email|e|u|eid|uid|rcpt|recipient|subscriber|mailto|toaddr)=)[^&\s"'<>]{1,512})",
      std::regex::icase);
  return std::regex_replace(s, track, "$1<redacted>");
}

// Redact phone-number-shaped runs: a candidate with 7–15 digits. Digit-count is
// checked in code (regex can't), so order numbers / prices (too few digits) and
// long IDs (too many) are left alone.
std::string redact_phones(const std::string& body) {
  static const std::regex re(R"(\+?\d[\d\s().\-]{5,30}\d)");
  return redact_where(body, re, "<phone>", [](const std::string& tok) {
    int digits = 0;
    for (char c : tok) if (c >= '0' && c <= '9') digits++;
    return digits >= 7 && digits <= 15;
  });
}

// Redact body IPv6 literals (the gate above only covers quoted header lines).
std::string redact_ipv6(const std::string& body) {
  static const std::regex re(R"([0-9A-Fa-f:]{2,45}:[0-9A-Fa-f:]{1,45})");
  return redact_where(body, re, "<ip>", looks_like_ipv6);
}

// Redact card-number-shaped runs that pass the Luhn checksum (13–19 digits with
// optional space/dash grouping). Luhn keeps false positives near zero.
std::string redact_credit_cards(const std::string& body) {
  static const std::regex re(R"(\b(?:\d[ \-]?){13,19}\b)");
  return redact_where(body, re, "<redacted-number>", [](const std::string& tok) {
    std::string d;
    for (char c : tok) if (c >= '0' && c <= '9') d += c;
    if (d.size() < 13 || d.size() > 19) return false;
    int sum = 0; bool dbl = false;
    for (auto it = d.rbegin(); it != d.rend(); ++it) {
      int v = *it - '0';
      if (dbl) { v *= 2; if (v > 9) v -= 9; }
      sum += v; dbl = !dbl;
    }
    return sum % 10 == 0;
  });
}

// Redact recipient/routing headers that appear *in the body* (a quoted or
// forwarded message). Gathers folded continuation lines, and only redacts when
// the folded value actually carries contact PII — so prose like "To: buy milk"
// is left intact.
std::string redact_quoted_headers(const std::vector<std::string>& lines) {
  std::vector<std::string> out;
  size_t i = 0;
  while (i < lines.size()) {
    std::string prefix, name;
    if (!sensitive_header_start(lines[i], prefix, name)) {
      out.push_back(lines[i]);
      i++;
      continue;
    }
    std::string value = value_after_colon(de_quote(lines[i]).second);
    size_t j = i + 1;
    while (j < lines.size() && is_fold_continuation(lines[j])) {
      value += " " + trim(lines[j]);
      j++;
    }
    if (contains_contact_pii(value)) {
      out.push_back(prefix + name + ": " + kPlaceholder);  // drops the folds too
    } else {
      for (size_t k = i; k < j; k++) out.push_back(lines[k]);  // keep prose verbatim
    }
    i = j;
  }
  std::string joined;
  for (size_t k = 0; k < out.size(); k++) {
    if (k) joined += "\n";
    joined += out[k];
  }
  return joined;
}

// Escape regex metacharacters so a literal token can be used in a pattern.
std::string regex_escape(const std::string& s) {
  static const std::string special = R"(\^$.|?*+()[]{})";
  std::string out;
  for (char c : s) {
    if (special.find(c) != std::string::npos) out += '\\';
    out += c;
  }
  return out;
}

// Case-insensitive substring replace of `needle` with `replacement` in `s`.
std::string replace_ci(const std::string& s, const std::string& needle,
                       const std::string& replacement) {
  if (needle.empty()) return s;
  const std::string low_s = to_lower(s), low_n = to_lower(needle);
  std::string out;
  size_t pos = 0, f;
  while ((f = low_s.find(low_n, pos)) != std::string::npos) {
    out.append(s, pos, f - pos);
    out += replacement;
    pos = f + low_n.size();
  }
  out.append(s, pos, std::string::npos);
  return out;
}

// Redact this message's recipient identifiers wherever they appear in the body.
// Email-shaped tokens (with '@') are matched as substrings (plus their %40
// URL-encoded form); name / local-part tokens are matched on word boundaries so
// "Park" doesn't nuke "Parking".
std::string redact_recipient_tokens(std::string s, const std::vector<std::string>& tokens) {
  for (const std::string& tok : tokens) {
    if (tok.empty()) continue;
    if (tok.find('@') != std::string::npos) {
      s = replace_ci(s, tok, "<email>");
      std::string at = tok;
      const size_t a = at.find('@');
      if (a != std::string::npos) {
        at.replace(a, 1, "%40");
        s = replace_ci(s, at, "<email>");
      }
    } else {
      const std::regex re("\\b" + regex_escape(tok) + "\\b", std::regex::icase);
      s = std::regex_replace(s, re, "<redacted>");
    }
  }
  return s;
}

// Replace inline `data:` URI payloads (base64 images embedded in HTML/CSS) with
// a `data:<stripped>` token so structure survives but the bytes are gone.
std::string strip_data_uris(const std::string& body) {
  // Linear scan, NOT std::regex: a data: URI payload is attacker-controlled and
  // unbounded, and libstdc++ std::regex recurses per matched byte on the `*`, so
  // a huge payload would stack-overflow. This strips a payload of any length.
  static const auto is_delim = [](char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
           c == '"' || c == '\'' || c == '<' || c == '>' || c == ')';
  };
  static const auto is_marker = [](const std::string& s, size_t j) {
    return j + 5 <= s.size() && (s[j] == 'd' || s[j] == 'D') &&
           (s[j + 1] == 'a' || s[j + 1] == 'A') &&
           (s[j + 2] == 't' || s[j + 2] == 'T') &&
           (s[j + 3] == 'a' || s[j + 3] == 'A') && s[j + 4] == ':';
  };
  std::string out;
  out.reserve(body.size());
  size_t i = 0;
  while (i < body.size()) {
    if (is_marker(body, i)) {
      out += "data:<stripped>";
      i += 5;
      while (i < body.size() && !is_delim(body[i])) ++i;  // skip the payload
    } else {
      out += body[i++];
    }
  }
  return out;
}

}  // namespace

std::string scrub_body_text(const std::string& body,
                            const std::vector<std::string>& recipient_tokens) {
  // Cap the body fed to the regex passes as defense-in-depth (the quantifiers
  // are all bounded, but this also bounds total scan time). An attacker controls
  // the full email body; the discriminative signal for a contribution sits at
  // the head, so truncating here loses nothing (the C ABI also clamps the output
  // to the caller capacity). Only materialise a copy on the rare overflow path —
  // the common case passes `body` straight through by reference.
  static constexpr size_t kMaxScrubBytes = 256 * 1024;
  std::string truncated;
  const std::string& capped = body.size() > kMaxScrubBytes
                                  ? (truncated = body.substr(0, kMaxScrubBytes))
                                  : body;

  // Order matters: strip data: URIs first (so base64 blobs can't trip the
  // number/email scans), redact the known recipient identity, then quoted
  // headers (line-structured), then the free-text identifier scans.
  std::string s = strip_data_uris(capped);
  s = redact_recipient_tokens(std::move(s), recipient_tokens);
  s = redact_quoted_headers(split_lines(s));
  s = redact_emails(s);
  s = redact_url_identifiers(s);
  s = redact_credit_cards(s);  // before phones: 16-digit cards aren't phones
  s = redact_phones(s);
  s = redact_ipv6(s);
  return s;
}

}  // namespace spam_engine
