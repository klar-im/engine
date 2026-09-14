#include "email_preprocessor.h"

#include "callback_shape.h"
#include "no_contact_shape.h"

#include "attachment_features.h"
#include "brand_kb.h"  // curated canonical-domain exemption + cousin detection (TASK-232)
#include "brand_names.h"
#include "brand_reputation.h"  // is_established_brand (auth-reputation exemption, doc-12)
#include "decision_layer.h"  // is_free_host_signed (Tier-2 corroboration, doc-12)
#include "ip_blocklist.h"  // strict IPv6 literal parser (TASK-389)

#include <algorithm>
#include <cstdlib>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include <gmime/gmime.h>

namespace spam_engine {

namespace {

// Defined further down; forward-declared so preprocess_rfc822 can compute the
// structural features from its own GMime parse (TASK-173) before the public
// standalone extractors, which re-parse, appear in the file.
ExtractedThreadFeatures extract_thread_features_from_message(GMimeMessage* message);
ExtractedAuthFeatures extract_auth_features_from_message(GMimeMessage* message);
ExtractedUrlFeatures extract_url_features_from_message(GMimeMessage* message);
ExtractedBodyFeatures extract_body_features_from_message(GMimeMessage* message);
ExtractedBodyFeatures body_features_from_parts(
    const char* subject,
    const std::vector<std::string>& plain_parts,
    const std::vector<std::string>& html_parts);

void ensure_gmime_initialized() {
  static std::once_flag once;
  std::call_once(once, [] { g_mime_init(); });
}

// RAII for a GMime GObject: unref on scope exit so a throw between construct and
// the manual unref (decode_header_text, extract_*, collect_body_parts all throw)
// no longer leaks the parsed message (TASK-251).
struct GObjectDeleter {
  void operator()(void* p) const { if (p != nullptr) { g_object_unref(p);
}}
};
template <typename T>
using GObjectPtr = std::unique_ptr<T, GObjectDeleter>;

GMimeParserOptions* parser_options() {
  return g_mime_parser_options_get_default();
}

std::string trim(const std::string& value) {
  const auto start = std::find_if_not(value.begin(), value.end(), [](unsigned char c) {
    return std::isspace(c) != 0;
  });
  if (start == value.end()) {
    return "";
  }

  const auto end = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char c) {
    return std::isspace(c) != 0;
  }).base();
  return {start, end};
}

std::string join_with_blank_lines(const std::vector<std::string>& parts) {
  std::string joined;
  bool first = true;
  for (const auto& part : parts) {
    const std::string trimmed = trim(part);
    if (trimmed.empty()) {
      continue;
    }
    if (!first) {
      joined += "\n\n";
    }
    joined += trimmed;
    first = false;
  }
  return joined;
}

// Zero-width / invisible Unicode "format" code points that carry no linguistic
// content. Email marketers stuff these into preheaders as invisible spacers,
// and spammers wedge them between letters to break tokenization ("v​i​agra").
// Left in, a long run dominates the encoder's first 512 tokens and the message
// reads as gibberish (TASK-167). Not exhaustive — the high-frequency offenders.
bool is_invisible_format_cp(std::uint32_t cp) {
  switch (cp) {
    case 0x00AD:  // soft hyphen
    case 0x034F:  // combining grapheme joiner
    case 0x061C:  // arabic letter mark
    case 0x115F: case 0x1160:  // hangul choseong/jungseong fillers
    case 0x17B4: case 0x17B5:  // khmer inherent vowels
    case 0x180E:  // mongolian vowel separator
    case 0x200B: case 0x200C: case 0x200D: case 0x200E: case 0x200F:  // ZWSP/ZWNJ/ZWJ/LRM/RLM
    case 0x202A: case 0x202B: case 0x202C: case 0x202D: case 0x202E:  // bidi embeds/overrides
    case 0x2060: case 0x2061: case 0x2062: case 0x2063: case 0x2064:  // word joiner, invisible ops
    case 0x2066: case 0x2067: case 0x2068: case 0x2069:  // bidi isolates
    case 0xFEFF:  // zero-width no-break space / BOM
    case 0xFFF9: case 0xFFFA: case 0xFFFB:  // interlinear annotation
      return true;
    default:
      return (cp >= 0xFE00 && cp <= 0xFE0F)    // variation selectors
          || (cp >= 0xE0000 && cp <= 0xE007F); // tag characters
  }
}

// Drop invisible-format code points (UTF-8 aware) and collapse the ASCII-space
// runs their removal leaves behind, so the visible text survives at full token
// weight. Newlines and other content are preserved.
std::string strip_invisible_chars(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  const std::size_t n = s.size();
  std::size_t i = 0;
  while (i < n) {
    const auto c = static_cast<unsigned char>(s[i]);
    std::uint32_t cp = c;
    std::size_t len = 1;
    if (c >= 0xF0 && i + 3 < n) {
      cp = (c & 0x07U) << 18 | (s[i + 1] & 0x3FU) << 12 | (s[i + 2] & 0x3FU) << 6 | (s[i + 3] & 0x3FU);
      len = 4;
    } else if (c >= 0xE0 && i + 2 < n) {
      cp = (c & 0x0FU) << 12 | (s[i + 1] & 0x3FU) << 6 | (s[i + 2] & 0x3FU);
      len = 3;
    } else if (c >= 0xC0 && i + 1 < n) {
      cp = (c & 0x1FU) << 6 | (s[i + 1] & 0x3FU);
      len = 2;
    }
    if (is_invisible_format_cp(cp)) {
      i += len;
      continue;
    }
    if (len == 1 && cp == ' ' && !out.empty() && out.back() == ' ') {
      i += len;  // collapse the space runs that stripping leaves behind
      continue;
    }
    out.append(s, i, len);
    i += len;
  }
  return out;
}

// NUL carries no linguistic content but hides the rest of the body from the
// classifier: a spammer plants a NUL early in a text/plain part and everything
// after it is truncated by any C-string boundary downstream (C6, TASK-251).
std::string strip_nul_bytes(std::string s) {
  s.erase(std::remove(s.begin(), s.end(), '\0'), s.end());  // no realloc if none
  return s;
}

std::string build_normalized_text(
    const std::string& subject,
    const std::string& from,
    const std::string& body_text) {
  // EXPERIMENT (representation parity): the successor was trained on
  // build_gmail_4class.body_text = "<subject>\n<body>" — no "subject:"/"from:"
  // labels and no From line. Match it exactly so the engine feeds the model the
  // shape it trained on. `from` is intentionally unused here (it reaches the
  // decision layer via auth features, not the neural text).
  (void)from;
  const std::string clean_subject = strip_invisible_chars(subject);
  const std::string clean_body = strip_invisible_chars(body_text);
  std::string normalized = clean_subject;
  if (!normalized.empty() && !clean_body.empty()) {
    normalized += '\n';
  }
  normalized += clean_body;
  return trim(normalized);
}

void replace_all(std::string& value, const std::string& from, const std::string& to) {
  if (from.empty()) {
    return;
  }

  std::size_t pos = 0;
  while ((pos = value.find(from, pos)) != std::string::npos) {
    value.replace(pos, from.size(), to);
    pos += to.size();
  }
}

// Append one Unicode codepoint as UTF-8.
void append_utf8(std::string& out, unsigned long cp) {
  if (cp < 0x80) {
    out.push_back(static_cast<char>(cp));
  } else if (cp < 0x800) {
    out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  } else if (cp < 0x10000) {
    out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  } else if (cp <= 0x10FFFF) {
    out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  }
}

// HTML character references, decoded generally rather than from a list of seven.
//
// WHY THIS IS NOT COSMETIC. This function produces the VISIBLE TEXT that body
// predicates match on, so anything it fails to decode is a bypass that costs an
// attacker one search-and-replace. It used to handle `&nbsp; &amp; &lt; &gt;
// &quot; &#39; &apos;` and nothing else, which meant `N&rsquo;appelez pas votre
// banque` and `ne pas pr&eacute;venir votre agence` reached no_contact_shape as
// literal `&rsquo;` and `&eacute;` and scored 0, while the same sentences in raw
// UTF-8 or with `&#39;` scored 1. Found by a cold review; both forms are now
// regression cases.
//
// Numeric references (decimal and hex) are decoded in full. Named ones come from
// the table below, which is deliberately narrow: the Latin-1 letters and the
// typographic quotes, because those are what appears in French and German lure
// text and what the matchers' own normalizers then fold. It is not a complete
// HTML5 entity table and does not need to be; an unknown reference is left
// verbatim, exactly as before.
void decode_html_entities(std::string& value) {
  static const struct { const char* name; unsigned long cp; } kNamed[] = {
      {"nbsp", 0x20}, {"amp", '&'}, {"lt", '<'}, {"gt", '>'}, {"quot", '"'},
      {"apos", '\''},
      // Typographic quotes: the apostrophe in "n'appelez" is routinely curly.
      {"rsquo", 0x2019}, {"lsquo", 0x2018}, {"ldquo", 0x201C}, {"rdquo", 0x201D},
      {"laquo", 0xAB}, {"raquo", 0xBB},
      // Latin-1 letters, lower and upper.
      {"agrave", 0xE0}, {"aacute", 0xE1}, {"acirc", 0xE2}, {"auml", 0xE4},
      {"ccedil", 0xE7}, {"egrave", 0xE8}, {"eacute", 0xE9}, {"ecirc", 0xEA},
      {"euml", 0xEB}, {"igrave", 0xEC}, {"iacute", 0xED}, {"icirc", 0xEE},
      {"iuml", 0xEF}, {"ntilde", 0xF1}, {"ograve", 0xF2}, {"oacute", 0xF3},
      {"ocirc", 0xF4}, {"ouml", 0xF6}, {"ugrave", 0xF9}, {"uacute", 0xFA},
      {"ucirc", 0xFB}, {"uuml", 0xFC}, {"szlig", 0xDF},
      {"Agrave", 0xC0}, {"Aacute", 0xC1}, {"Acirc", 0xC2}, {"Auml", 0xC4},
      {"Ccedil", 0xC7}, {"Egrave", 0xC8}, {"Eacute", 0xC9}, {"Ecirc", 0xCA},
      {"Euml", 0xCB}, {"Iacute", 0xCD}, {"Icirc", 0xCE}, {"Iuml", 0xCF},
      {"Ntilde", 0xD1}, {"Oacute", 0xD3}, {"Ocirc", 0xD4}, {"Ouml", 0xD6},
      {"Ugrave", 0xD9}, {"Uacute", 0xDA}, {"Ucirc", 0xDB}, {"Uuml", 0xDC},
  };
  // A reference is at most "&" + 8 name chars + ";" here, or "&#x10FFFF;".
  constexpr std::size_t kMaxRef = 10;

  std::string out;
  out.reserve(value.size());
  for (std::size_t i = 0; i < value.size();) {
    if (value[i] != '&') {
      out.push_back(value[i++]);
      continue;
    }
    const std::size_t stop = std::min(value.size(), i + 1 + kMaxRef);
    std::size_t semi = std::string::npos;
    for (std::size_t j = i + 1; j < stop; ++j) {
      if (value[j] == ';') { semi = j; break; }
      if (value[j] == '&') { break;          // a bare '&' then another reference
}
    }
    if (semi == std::string::npos) {       // not a reference, keep the '&'
      out.push_back(value[i++]);
      continue;
    }
    const std::string body = value.substr(i + 1, semi - i - 1);
    bool decoded = false;
    if (!body.empty() && body[0] == '#') {
      const bool hex = body.size() > 1 && (body[1] == 'x' || body[1] == 'X');
      const std::string digits = body.substr(hex ? 2 : 1);
      if (!digits.empty() &&
          digits.find_first_not_of(hex ? "0123456789abcdefABCDEF"
                                       : "0123456789") == std::string::npos) {
        const unsigned long cp = std::strtoul(digits.c_str(), nullptr, hex ? 16 : 10);
        if (cp > 0 && cp <= 0x10FFFF) { append_utf8(out, cp); decoded = true; }
      }
    } else {
      for (const auto& e : kNamed) {
        if (body == e.name) { append_utf8(out, e.cp); decoded = true; break; }
      }
    }
    if (decoded) {
      i = semi + 1;
    } else {
      out.push_back(value[i++]);           // unknown reference, left verbatim
    }
  }
  value.swap(out);
}

std::string collapse_whitespace(const std::string& input) {
  std::string output;
  output.reserve(input.size());

  bool in_space = false;
  bool last_was_newline = false;
  for (unsigned char const uc : input) {
    const char c = static_cast<char>(uc);
    if (c == '\r') {
      continue;
    }
    if (c == '\n') {
      if (!last_was_newline && !output.empty()) {
        output.push_back('\n');
      }
      in_space = false;
      last_was_newline = true;
      continue;
    }
    if (std::isspace(uc) != 0) {
      if (!in_space && !last_was_newline) {
        output.push_back(' ');
      }
      in_space = true;
      continue;
    }

    output.push_back(c);
    in_space = false;
    last_was_newline = false;
  }

  return trim(output);
}

}  // namespace

std::string html_to_text(const std::string& html) {
  std::string text;
  text.reserve(html.size());

  bool in_tag = false;
  bool in_script_or_style = false;
  std::string tag_name;
  bool tag_name_done = false;
  bool self_closing = false;

  for (char const c : html) {
    if (c == '<') {
      in_tag = true;
      tag_name.clear();
      tag_name_done = false;
      self_closing = false;
      text.push_back(' ');
      continue;
    }

    if (in_tag) {
      if (c == '>') {
        in_tag = false;
        // tag_name holds the element NAME only (attributes were skipped once
        // the name ended), so "<style type=\"text/css\">" still matches "style".
        std::string lower_tag;
        for (char const tc : tag_name) {
          lower_tag.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(tc))));
        }
        // A self-closing tag (<style/>, <script src=... />) opens no element,
        // so it must not toggle strip mode: its content-close never arrives
        // and the rest of the body would be swallowed.
        if (!self_closing) {
          if (lower_tag == "script" || lower_tag == "style") {
            in_script_or_style = true;
          } else if (lower_tag == "/script" || lower_tag == "/style") {
            in_script_or_style = false;
          }
        }
      } else {
        const bool ws = std::isspace(static_cast<unsigned char>(c)) != 0;
        // The name runs to the first whitespace or a '/' that isn't the leading
        // slash of a closing tag; everything after (attributes, self-closing
        // slash) is ignored for name matching.
        if (!tag_name_done) {
          if (ws || (c == '/' && !tag_name.empty())) {
            tag_name_done = true;
          } else {
            tag_name.push_back(c);
          }
        }
        // Track whether the last non-space tag char was '/', so the '>' handler
        // can tell a self-closing tag from a real open. Whitespace doesn't reset
        // it, so "<br / >" still reads as self-closing.
        if (!ws) {
          self_closing = (c == '/');
        }
      }
      continue;
    }

    if (!in_script_or_style) {
      text.push_back(c);
    }
  }

  decode_html_entities(text);

  return collapse_whitespace(text);
}

namespace {

std::string decode_header_text(const char* text) {
  if (text == nullptr || text[0] == '\0') {
    return "";
  }

  char* decoded = g_mime_utils_header_decode_text(parser_options(), text);
  if (decoded == nullptr) {
    return collapse_whitespace(text);
  }

  std::string const out(decoded);
  g_free(decoded);
  return collapse_whitespace(out);
}

// Lower-case a string in place, ASCII ONLY.
//
// It says ASCII and now does ASCII. `std::tolower` is locale-sensitive above
// 0x7F, and on this platform it lower-cases the Latin-1 range: 0xC3 becomes
// 0xE3. 0xC3 is the LEAD BYTE of every two-byte UTF-8 sequence in the Latin-1
// Supplement, so an IDN domain came out of here as mojibake --
// `amazon-prime-résiliation.com` was stored as the bytes
// `...72 e3 a9 73...`, which is neither UTF-8 nor Latin-1 and matches nothing
// anywhere downstream. Found while checking whether the combosquat keyword set
// could be bypassed by registering the accented spelling of a French keyword.
// It could, and this was why: the fold was correct, the bytes it was folding
// were already corrupt.
//
// Bytes >= 0x80 are left exactly as they arrived. Nothing here has ever wanted
// Latin-1 case folding, and a multi-byte encoding cannot be case-folded a byte
// at a time in any case.
//
// There used to be a second, byte-identical copy of this named `ascii_lower`,
// lower in the file, serving the DOMAIN path (org_domain -> split_labels) while
// this one served headers. Both carried the same `std::tolower` bug and both
// had to be found and fixed separately. One definition, so the next fix cannot
// land on half the callers. It is length-preserving, which several callers rely
// on to index the original string with offsets found in the lower-cased copy.
std::string to_lower_ascii(std::string s) {
  for (auto& c : s) {
    if (c >= 'A' && c <= 'Z') { c = static_cast<char>(c - 'A' + 'a');
}
  }
  return s;
}

// Add `raw` (trimmed, lower-cased) to `out` if it's at least `min_len` chars.
void add_recipient_token(std::set<std::string>& out, const std::string& raw, size_t min_len) {
  const std::string t = to_lower_ascii(trim(raw));
  if (t.size() >= min_len) { out.insert(t);
}
}

// Mine one address + display name into recipient identifier tokens: the full
// address, its local-part, the full display name, and each name word.
void add_address_tokens(std::set<std::string>& out, const char* email, const char* name) {
  if (email != nullptr && email[0] != '\0') {
    const std::string addr = email;
    add_recipient_token(out, addr, 5);                 // full address
    const size_t at = addr.find('@');
    if (at != std::string::npos) { add_recipient_token(out, addr.substr(0, at), 4);  // local-part
}
  }
  if (name != nullptr && name[0] != '\0') {
    const std::string nm = decode_header_text(name);
    add_recipient_token(out, nm, 4);                   // full display name
    size_t i = 0;
    while (i < nm.size()) {                            // each word
      while (i < nm.size() && std::isspace(static_cast<unsigned char>(nm[i]))) { i++;
}
      size_t j = i;
      while (j < nm.size() && !std::isspace(static_cast<unsigned char>(nm[j]))) { j++;
}
      if (j > i) { add_recipient_token(out, nm.substr(i, j - i), 4);
}
      i = j;
    }
  }
}

// Walk an InternetAddressList (recursing into groups) collecting recipient tokens.
// Walk an address list (recursing into groups) and invoke `on_mailbox` for each
// leaf mailbox. The shared skeleton for the two collectors below.
// on_mailbox is invoked once per leaf mailbox (loop + recursion), so it is
// deliberately never forwarded/moved-from — it must stay valid across every
// call.
template <typename Fn>
// NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward)
void walk_mailboxes(InternetAddressList* list, Fn&& on_mailbox) {
  if (list == nullptr) { return;
}
  const int n = internet_address_list_length(list);
  for (int i = 0; i < n; i++) {
    InternetAddress* addr = internet_address_list_get_address(list, i);
    if (addr == nullptr) { continue;
}
    if (INTERNET_ADDRESS_IS_GROUP(addr)) {
      walk_mailboxes(internet_address_group_get_members(INTERNET_ADDRESS_GROUP(addr)), on_mailbox);
    } else if (INTERNET_ADDRESS_IS_MAILBOX(addr)) {
      on_mailbox(addr);
    }
  }
}

void collect_address_list(InternetAddressList* list, std::set<std::string>& out) {
  walk_mailboxes(list, [&](InternetAddress* addr) {
    add_address_tokens(out,
        internet_address_mailbox_get_addr(INTERNET_ADDRESS_MAILBOX(addr)),
        internet_address_get_name(addr));
  });
}

// The mailbox addresses only (email, lowercased), display names dropped. Used to
// compare Reply-To against From so a differing display name on the SAME address
// is not read as a redirect (TASK-251).
void collect_mailbox_addrs(InternetAddressList* list, std::set<std::string>& out) {
  walk_mailboxes(list, [&](InternetAddress* addr) {
    const char* a = internet_address_mailbox_get_addr(INTERNET_ADDRESS_MAILBOX(addr));
    if (a != nullptr && a[0] != '\0') {
      std::string s(a);
      std::transform(s.begin(), s.end(), s.begin(),
                     [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
      out.insert(std::move(s));
    }
  });
}

std::string decode_to_utf8(const std::string& decoded_body, const char* charset) {
  if (decoded_body.empty()) {
    return "";
  }

  if (charset != nullptr && charset[0] != '\0') {
    gsize bytes_read = 0;
    gsize bytes_written = 0;
    GError* error = nullptr;

    char* converted = g_convert(
        decoded_body.data(),
        static_cast<gssize>(decoded_body.size()),
        "UTF-8",
        charset,
        &bytes_read,
        &bytes_written,
        &error);

    if (converted != nullptr) {
      // g_convert is length-safe (bytes_written), so a source NUL survives into
      // the UTF-8 output as a 0x00 byte; strip it so it can't truncate the body
      // downstream. Strip here (post-conversion), NOT from the raw input, so a
      // legitimately NUL-bearing charset (UTF-16) is not corrupted before decode.
      std::string out(converted, static_cast<std::size_t>(bytes_written));
      g_free(converted);
      return strip_nul_bytes(std::move(out));  // moves in; strips only if a NUL exists
    }

    if (error != nullptr) {
      g_error_free(error);
    }
  }

  // Fallback: no charset, or conversion failed. The bytes are treated as 8-bit
  // text, so a NUL is a control byte that would truncate the NUL-terminated
  // g_mime_utils_decode_8bit result and hide the tail of the body. Strip it
  // first, but only copy when a NUL is actually present (the common case decodes
  // the body in place with no allocation).
  std::string cleaned;
  const std::string* body = &decoded_body;
  if (decoded_body.find('\0') != std::string::npos) {
    cleaned = strip_nul_bytes(decoded_body);
    body = &cleaned;
  }
  char* guessed = g_mime_utils_decode_8bit(
      parser_options(), body->data(), body->size());
  if (guessed == nullptr) {
    return *body;
  }

  std::string out(guessed);
  g_free(guessed);
  return out;
}

bool is_attachment(GMimeObject* object) {
  const char* disposition = g_mime_object_get_disposition(object);
  return disposition != nullptr
      && g_ascii_strcasecmp(disposition, GMIME_DISPOSITION_ATTACHMENT) == 0;
}

std::string decode_part_bytes(GMimePart* part) {
  GMimeDataWrapper* content = g_mime_part_get_content(part);
  if (content == nullptr) {
    return "";
  }

  GMimeStream* stream = g_mime_stream_mem_new();
  if (stream == nullptr) {
    return "";
  }

  const ssize_t written = g_mime_data_wrapper_write_to_stream(content, stream);
  std::string decoded;

  if (written >= 0) {
    GByteArray const* bytes = g_mime_stream_mem_get_byte_array(GMIME_STREAM_MEM(stream));
    if (bytes != nullptr && bytes->data != nullptr && bytes->len > 0) {
      decoded.assign(
          reinterpret_cast<const char*>(bytes->data),
          static_cast<std::size_t>(bytes->len));
    }
  }

  g_object_unref(stream);

  return decoded;
}

struct BoundedDecodedPart {
  std::string bytes;
  bool truncated = false;
};

std::size_t encoded_budget_for(
    GMimeContentEncoding encoding, std::size_t decoded_budget) {
  if (encoding == GMIME_CONTENT_ENCODING_BASE64) {
    return (((decoded_budget + 2) / 3) * 4) + 8;
  }
  if (encoding == GMIME_CONTENT_ENCODING_QUOTEDPRINTABLE) {
    // Escaped bytes can use three source bytes, but ordinary quoted-printable
    // is one-to-one. Cap the source at the decoded budget so an attacker cannot
    // make GMime materialize 3x the promised per-file limit before we truncate
    // the destination. This may conservatively truncate escape-heavy legacy
    // payloads; the attachment context records that fact.
    return decoded_budget;
  }
  // 7bit, 8bit and binary are one input byte per output byte. Uuencode is
  // larger than its decoded form, so this conservative cap remains bounded and
  // may merely mark an unusually large legacy attachment truncated.
  return decoded_budget;
}

BoundedDecodedPart decode_part_bytes_bounded(
    GMimePart* part, std::size_t decoded_budget) {
  BoundedDecodedPart out;
  if (decoded_budget == 0) {
    out.truncated = true;
    return out;
  }
  GMimeDataWrapper* content = g_mime_part_get_content(part);
  if (content == nullptr) { return out;
}
  GMimeStream* source = g_mime_data_wrapper_get_stream(content);
  if (source == nullptr) { return out;
}
  if (g_mime_stream_reset(source) != 0) {
    out.truncated = true;
    return out;
  }
  const gint64 source_start = g_mime_stream_tell(source);
  if (source_start < 0) {
    out.truncated = true;
    return out;
  }

  const GMimeContentEncoding encoding = g_mime_data_wrapper_get_encoding(content);
  const std::size_t encoded_budget = encoded_budget_for(encoding, decoded_budget);
  const gint64 source_length = g_mime_stream_length(source);
  const gint64 bounded_length = source_length < 0
      ? static_cast<gint64>(encoded_budget)
      : std::min<gint64>(source_length, static_cast<gint64>(encoded_budget));
  out.truncated = source_length < 0 || source_length > bounded_length;

  GMimeStream* bounded_source = g_mime_stream_substream(
      source, source_start, source_start + bounded_length);
  if (bounded_source == nullptr) {
    out.truncated = true;
    return out;
  }
  GMimeDataWrapper* bounded = g_mime_data_wrapper_new_with_stream(
      bounded_source, encoding);
  g_object_unref(bounded_source);
  if (bounded == nullptr) {
    out.truncated = true;
    return out;
  }
  GMimeStream* destination = g_mime_stream_mem_new();
  if (destination == nullptr) {
    g_object_unref(bounded);
    out.truncated = true;
    return out;
  }

  const ssize_t written = g_mime_data_wrapper_write_to_stream(bounded, destination);
  if (written >= 0) {
    GByteArray const* bytes = g_mime_stream_mem_get_byte_array(GMIME_STREAM_MEM(destination));
    if (bytes != nullptr && bytes->data != nullptr && bytes->len > 0) {
      const std::size_t kept = std::min<std::size_t>(bytes->len, decoded_budget);
      out.bytes.assign(reinterpret_cast<const char*>(bytes->data), kept);
      out.truncated = out.truncated || bytes->len > kept;
    }
  } else {
    out.truncated = true;
  }
  g_object_unref(destination);
  g_object_unref(bounded);
  return out;
}

std::string decode_part_content(GMimePart* part, GMimeContentType* content_type) {
  const std::string decoded = decode_part_bytes(part);

  const char* charset = content_type == nullptr
      ? nullptr
      : g_mime_content_type_get_parameter(content_type, "charset");
  return decode_to_utf8(decoded, charset);
}

bool is_feature_attachment(GMimeObject* object) {
  if (is_attachment(object)) { return true;
}
  if (GMIME_IS_PART(object)) {
    const char* filename = g_mime_part_get_filename(GMIME_PART(object));
    if (filename != nullptr && *filename != '\0') { return true;
}
  }
  GMimeContentType* content_type = g_mime_object_get_content_type(object);
  return content_type != nullptr &&
      g_mime_content_type_get_parameter(content_type, "name") != nullptr;
}

std::string declared_mime(GMimeObject* object) {
  GMimeContentType* type = g_mime_object_get_content_type(object);
  if (type == nullptr) { return "";
}
  const char* media = g_mime_content_type_get_media_type(type);
  const char* subtype = g_mime_content_type_get_media_subtype(type);
  if (media == nullptr || subtype == nullptr) { return "";
}
  return std::string(media) + "/" + subtype;
}

bool is_inline_declared_image(GMimeObject* object) {
  const char* disposition = g_mime_object_get_disposition(object);
  GMimeContentType* type = g_mime_object_get_content_type(object);
  const char* media = type == nullptr
      ? nullptr : g_mime_content_type_get_media_type(type);
  // A named image body commonly omits Content-Disposition entirely. Count it
  // with attachments only when the sender explicitly calls it an attachment;
  // the byte analyzer still sees every named image and promotes a MIME-disguised
  // executable/archive when its magic does not match image/*.
  return media != nullptr && g_ascii_strcasecmp(media, "image") == 0 &&
      (disposition == nullptr ||
       g_ascii_strcasecmp(disposition, GMIME_DISPOSITION_ATTACHMENT) != 0);
}

void collect_attachment_inputs(
    GMimeObject* object,
    std::vector<AttachmentInput>& attachments,
    int& observed_count,
    std::size_t& remaining_decoded_bytes,
    bool& collection_truncated,
    int& visited_parts,
    int depth = 0) {
  if (object == nullptr) { return;
}
  if (visited_parts >= kAttachmentMimeMaxParts) {
    collection_truncated = true;
    return;
  }
  ++visited_parts;
  if (depth > kAttachmentMimeMaxDepth) {
    collection_truncated = true;
    return;
  }
  if (GMIME_IS_MULTIPART(object)) {
    GMimeMultipart* multipart = GMIME_MULTIPART(object);
    const int count = g_mime_multipart_get_count(multipart);
    for (int i = 0; i < count; ++i) {
      if (visited_parts >= kAttachmentMimeMaxParts) {
        collection_truncated = true;
        break;
      }
      collect_attachment_inputs(
          g_mime_multipart_get_part(multipart, i), attachments,
          observed_count, remaining_decoded_bytes, collection_truncated,
          visited_parts, depth + 1);
    }
    return;
  }
  if (GMIME_IS_MESSAGE_PART(object)) {
    if (is_feature_attachment(object)) {
      ++observed_count;
      if (attachments.size() < static_cast<std::size_t>(kAttachmentMaxFiles)) {
        attachments.push_back({"attached-message.eml", declared_mime(object), ""});
      } else {
        collection_truncated = true;
      }
    }
    GMimeMessage* nested = g_mime_message_part_get_message(GMIME_MESSAGE_PART(object));
    if (nested != nullptr) {
      collect_attachment_inputs(
          g_mime_message_get_mime_part(nested), attachments,
          observed_count, remaining_decoded_bytes, collection_truncated,
          visited_parts, depth + 1);
    }
    return;
  }
  if (!GMIME_IS_PART(object) || !is_feature_attachment(object)) { return;
}

  const bool counted_as_attachment = !is_inline_declared_image(object);
  if (counted_as_attachment) { ++observed_count;
}
  if (attachments.size() >= static_cast<std::size_t>(kAttachmentMaxFiles)) {
    collection_truncated = true;
    return;
  }

  GMimePart* part = GMIME_PART(object);
  const char* filename = g_mime_part_get_filename(part);
  std::string name = filename == nullptr ? "" : decode_header_text(filename);
  if (name.empty()) {
    GMimeContentType* type = g_mime_object_get_content_type(object);
    const char* parameter = type == nullptr
        ? nullptr : g_mime_content_type_get_parameter(type, "name");
    if (parameter != nullptr) { name = decode_header_text(parameter);
}
  }
  if (name.empty()) { name = "unnamed";
}
  const std::size_t file_budget = std::min(
      kAttachmentDecodedFileMaxBytes, remaining_decoded_bytes);
  BoundedDecodedPart decoded = decode_part_bytes_bounded(part, file_budget);
  remaining_decoded_bytes -= decoded.bytes.size();
  collection_truncated = collection_truncated || decoded.truncated;
  attachments.push_back({
      name, declared_mime(object), std::move(decoded.bytes), decoded.truncated,
      counted_as_attachment});
}

void collect_body_parts(
    GMimeObject* object,
    std::vector<std::string>& plain_parts,
    std::vector<std::string>& html_parts) {
  if (object == nullptr) {
    return;
  }

  if (GMIME_IS_MULTIPART(object)) {
    GMimeMultipart* multipart = GMIME_MULTIPART(object);
    const int count = g_mime_multipart_get_count(multipart);
    for (int i = 0; i < count; ++i) {
      collect_body_parts(g_mime_multipart_get_part(multipart, i), plain_parts, html_parts);
    }
    return;
  }

  if (GMIME_IS_MESSAGE_PART(object)) {
    GMimeMessagePart* message_part = GMIME_MESSAGE_PART(object);
    GMimeMessage* nested = g_mime_message_part_get_message(message_part);
    if (nested != nullptr) {
      collect_body_parts(g_mime_message_get_mime_part(nested), plain_parts, html_parts);
    }
    return;
  }

  if (!GMIME_IS_PART(object) || is_attachment(object)) {
    return;
  }

  GMimeContentType* content_type = g_mime_object_get_content_type(object);
  if (content_type == nullptr) {
    return;
  }

  GMimePart* part = GMIME_PART(object);
  const std::string decoded = decode_part_content(part, content_type);
  if (decoded.empty()) {
    return;
  }

  if (g_mime_content_type_is_type(content_type, "text", "plain")) {
    plain_parts.push_back(collapse_whitespace(decoded));
    return;
  }

  if (g_mime_content_type_is_type(content_type, "text", "html")) {
    html_parts.push_back(html_to_text(decoded));
  }
}

// Collect raw body parts without text conversion (for display purposes).
void collect_raw_body_parts(
    GMimeObject* object,
    std::vector<std::string>& plain_parts,
    std::vector<std::string>& html_parts) {
  if (object == nullptr) {
    return;
  }

  if (GMIME_IS_MULTIPART(object)) {
    GMimeMultipart* multipart = GMIME_MULTIPART(object);
    const int count = g_mime_multipart_get_count(multipart);
    for (int i = 0; i < count; ++i) {
      collect_raw_body_parts(g_mime_multipart_get_part(multipart, i), plain_parts, html_parts);
    }
    return;
  }

  if (GMIME_IS_MESSAGE_PART(object)) {
    GMimeMessagePart* message_part = GMIME_MESSAGE_PART(object);
    GMimeMessage* nested = g_mime_message_part_get_message(message_part);
    if (nested != nullptr) {
      collect_raw_body_parts(g_mime_message_get_mime_part(nested), plain_parts, html_parts);
    }
    return;
  }

  if (!GMIME_IS_PART(object) || is_attachment(object)) {
    return;
  }

  GMimeContentType* content_type = g_mime_object_get_content_type(object);
  if (content_type == nullptr) {
    return;
  }

  GMimePart* part = GMIME_PART(object);
  const std::string decoded = decode_part_content(part, content_type);
  if (decoded.empty()) {
    return;
  }

  if (g_mime_content_type_is_type(content_type, "text", "plain")) {
    plain_parts.push_back(decoded);  // Raw, no whitespace collapse
    return;
  }

  if (g_mime_content_type_is_type(content_type, "text", "html")) {
    html_parts.push_back(decoded);  // Raw HTML, no conversion
  }
}

}  // namespace

PreprocessedEmail preprocess_rfc822(
    const std::string& raw_rfc822,
    bool extract_attachments) {
  if (raw_rfc822.empty()) {
    throw std::invalid_argument("raw_rfc822 cannot be empty");
  }

  ensure_gmime_initialized();

  GMimeStream* stream = g_mime_stream_mem_new_with_buffer(raw_rfc822.data(), raw_rfc822.size());
  if (stream == nullptr) {
    throw std::runtime_error("Failed to create GMime stream for RFC822 input");
  }

  GMimeParser* parser = g_mime_parser_new_with_stream(stream);
  g_object_unref(stream);
  if (parser == nullptr) {
    throw std::runtime_error("Failed to create GMime parser");
  }

  GMimeMessage* message = g_mime_parser_construct_message(parser, nullptr);
  g_object_unref(parser);
  if (message == nullptr) {
    throw std::runtime_error("Failed to parse RFC822 message");
  }
  GObjectPtr<GMimeMessage> message_guard(message);

  PreprocessedEmail out;

  out.subject = decode_header_text(g_mime_message_get_subject(message));

  InternetAddressList* from_list = g_mime_message_get_from(message);
  if (from_list != nullptr) {
    char* rendered = internet_address_list_to_string(from_list, nullptr, false);
    if (rendered != nullptr) {
      out.from = decode_header_text(rendered);
      g_free(rendered);
    }
  }

  // Reply-To parity check: legitimate senders rarely need a Reply-To that
  // differs from From; spammers do it to redirect responses to a throwaway
  // address. Surfaced through CustomerInfo (see engine/PARITY_PLAN.md).
  // Compared by the MAILBOX ADDRESSES only (not the rendered string, which
  // carries the display name): a "Acme Support <billing@acme.com>" Reply-To on a
  // "Acme <billing@acme.com>" From is the same address and must not flag.
  InternetAddressList* reply_to_list = g_mime_message_get_reply_to(message);
  if (reply_to_list != nullptr && from_list != nullptr) {
    std::set<std::string> reply_to_addrs;
    std::set<std::string> from_addrs;
    collect_mailbox_addrs(reply_to_list, reply_to_addrs);
    collect_mailbox_addrs(from_list, from_addrs);
    if (!reply_to_addrs.empty() && reply_to_addrs != from_addrs) {
      out.replyto_differs = true;
    }
  }

  // Structural thread + sender-auth features from this same parse (TASK-173):
  // the Swift decision layer used to trigger two more GMime parses for these.
  out.thread_features = extract_thread_features_from_message(message);
  out.auth_features = extract_auth_features_from_message(message);
  out.url_features = extract_url_features_from_message(message);

  // Recipient identifiers, for PII-scrubbing the contribution body (TASK-135):
  // the recipient's own address/name must not leak even when it appears IN the
  // body (greetings, footers, tracking links). From/Reply-To are NOT collected —
  // the sender is kept as spam signal.
  {
    std::set<std::string> rcpt;
    collect_address_list(g_mime_message_get_addresses(message, GMIME_ADDRESS_TYPE_TO), rcpt);
    collect_address_list(g_mime_message_get_addresses(message, GMIME_ADDRESS_TYPE_CC), rcpt);
    collect_address_list(g_mime_message_get_addresses(message, GMIME_ADDRESS_TYPE_BCC), rcpt);
    for (const char* header : {"Delivered-To", "Envelope-To", "X-Original-To"}) {
      const char* v = g_mime_object_get_header(GMIME_OBJECT(message), header);
      if (v != nullptr) { add_address_tokens(rcpt, v, nullptr);
}
    }
    out.recipient_tokens.assign(rcpt.begin(), rcpt.end());
  }

  std::vector<std::string> plain_parts;
  std::vector<std::string> html_parts;
  collect_body_parts(g_mime_message_get_mime_part(message), plain_parts, html_parts);
  // Raw (untransformed) HTML for the structural markers, which need <img tags and
  // href attributes that html_to_text() strips. Collected from the SAME parse,
  // before the message is freed. Python concatenates the parts with no separator.
  std::vector<std::string> raw_plain_parts;
  std::vector<std::string> raw_html_parts;
  collect_raw_body_parts(g_mime_message_get_mime_part(message), raw_plain_parts, raw_html_parts);
  if (extract_attachments) {
    std::vector<AttachmentInput> attachment_inputs;
    int attachment_count = 0;
    std::size_t attachment_bytes_remaining = kAttachmentDecodedTotalMaxBytes;
    bool attachment_collection_truncated = false;
    int attachment_parts_visited = 0;
    collect_attachment_inputs(
        g_mime_message_get_mime_part(message), attachment_inputs,
        attachment_count, attachment_bytes_remaining,
        attachment_collection_truncated, attachment_parts_visited);
    out.attachment_features = analyze_attachments(
        attachment_inputs, attachment_count, attachment_collection_truncated);
  }
  // Reuses the parts collected just above rather than adding a traversal of its
  // own (TASK-394): re-collecting would re-decode every text part.
  out.body_features = body_features_from_parts(
      g_mime_message_get_subject(message), raw_plain_parts, raw_html_parts);
  message_guard.reset();

  out.plain_body_text = join_with_blank_lines(plain_parts);
  out.html_body_text = join_with_blank_lines(html_parts);
  out.normalized_plain_text = build_normalized_text(out.subject, out.from, out.plain_body_text);
  out.normalized_html_text = build_normalized_text(out.subject, out.from, out.html_body_text);

  out.body_text = !out.plain_body_text.empty() ? out.plain_body_text : out.html_body_text;
  out.normalized_text = build_normalized_text(out.subject, out.from, out.body_text);

  if (out.normalized_text.empty() &&
      out.attachment_features.total_count == 0) {
    throw std::runtime_error("No extractable text/plain or text/html content in RFC822 message");
  }

  // Compute the structural-marker summary the successor model was trained on
  // (TASK-283/344), but do not mutate normalized_*. Whether the neural path
  // prepends it is an artifact property; the public model and the independently
  // trained FTRL baseline must keep their original input distribution. The
  // image-only gate keys on the plain base (subject + preferred body), mirroring
  // Python body_text.
  std::string raw_html_joined;
  for (const auto& part : raw_html_parts) { raw_html_joined += part;
}
  out.structural_marker_prefix = structural_marker_prefix(
      raw_html_joined, trim(out.subject + "\n" + out.body_text));

  return out;
}

namespace {

// Whether a decoded `text/plain` part is actually HTML markup dumped
// verbatim rather than genuine plain text. Real ESP bug, not a parsing bug on
// our side: some mailers (myphotobook.de's newsletter is a confirmed case,
// 2026-09-04) generate a `multipart/alternative`'s plain half by writing out
// the HTML template unconverted, tags and all, so `<meta
// http-equiv="Content-Type" ...>` and similar end up as this part's literal
// decoded content. `decode_part_content` correctly decodes exactly the bytes
// that part actually contains; there is nothing to fix upstream of this —
// the fix is treating that content as HTML once it is recognisably HTML,
// same as the genuine `text/html` alternative would be.
//
// Checked on a prefix only, matching `html_to_text`'s own scope and cost: a
// false negative here (a tag buried mid-body, past the prefix) leaves that
// one tag visible, which is the safe direction — a false positive would
// instead run `html_to_text` over a genuine plain-text email that happens to
// quote HTML-looking text early on, corrupting content that was already
// correct.
bool looks_like_html_markup(const std::string& text) {
  std::string lower;
  const size_t prefix_len = std::min<size_t>(text.size(), 500);
  lower.reserve(prefix_len);
  for (size_t i = 0; i < prefix_len; ++i) {
    lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(text[i]))));
  }
  // `<div `/`<span ` etc. deliberately excluded (found by /codex:review):
  // unlike the document-level markers below, a single attribute-bearing tag
  // like that is exactly what a genuine plain-text support/developer email
  // can quote on its own ("the button renders as <div class=\"btn\">...")
  // without being a raw-HTML-dump ESP bug — the false-positive direction
  // this function's own comment above warns is unsafe. Every marker kept
  // here is a whole-document marker a human essentially never types by hand.
  static const std::array<const char*, 5> kMarkers = {
      "<!doctype html", "<html", "<head>", "<meta ", "<body"};
  return std::any_of(kMarkers.begin(), kMarkers.end(), [&lower](const char* marker) {
    return lower.find(marker) != std::string::npos;
  });
}

// A `text/plain` part's content, cleaned if it turns out to actually be raw
// HTML (see `looks_like_html_markup`) — the single place both call sites in
// `extract_preferred_body` below assign into `plain_out`, so the check
// cannot be added to one and missed on the other.
std::string cleaned_plain_text(const std::string& decoded) {
  return looks_like_html_markup(decoded) ? html_to_text(decoded) : decoded;
}

// Extract body from the "preferred" part only (handles multipart/alternative correctly).
// Does NOT recurse into nested messages.
void extract_preferred_body(
    GMimeObject* object,
    std::string& plain_out,
    std::string& html_out) {
  if (object == nullptr) {
    return;
  }

  // For multipart/alternative, GMime can give us the "preferred" part directly
  if (GMIME_IS_MULTIPART(object)) {
    GMimeMultipart* multipart = GMIME_MULTIPART(object);
    GMimeContentType* ct = g_mime_object_get_content_type(object);

    // multipart/alternative: extract BOTH plain and HTML parts
    // We need both: plain for text_preview, HTML for display
    if (ct != nullptr && g_mime_content_type_is_type(ct, "multipart", "alternative")) {
      const int count = g_mime_multipart_get_count(multipart);
      for (int i = 0; i < count; ++i) {
        GMimeObject* part = g_mime_multipart_get_part(multipart, i);
        if (!GMIME_IS_PART(part) || is_attachment(part)) {
          continue;
        }
        GMimeContentType* part_ct = g_mime_object_get_content_type(part);
        if (part_ct != nullptr && g_mime_content_type_is_type(part_ct, "text", "plain") && plain_out.empty()) {
          plain_out = cleaned_plain_text(decode_part_content(GMIME_PART(part), part_ct));
        }
        if (part_ct != nullptr && g_mime_content_type_is_type(part_ct, "text", "html") && html_out.empty()) {
          html_out = decode_part_content(GMIME_PART(part), part_ct);
        }
      }
      return;
    }

    // Other multipart types: recurse into each part (but not nested messages)
    const int count = g_mime_multipart_get_count(multipart);
    for (int i = 0; i < count; ++i) {
      GMimeObject* part = g_mime_multipart_get_part(multipart, i);
      // Skip nested messages (forwards, etc.) - we only want the primary body
      if (GMIME_IS_MESSAGE_PART(part)) {
        continue;
      }
      extract_preferred_body(part, plain_out, html_out);
      // If we found HTML, stop searching
      if (!html_out.empty()) {
        return;
      }
    }
    return;
  }

  // Single part
  if (!GMIME_IS_PART(object) || is_attachment(object)) {
    return;
  }

  GMimeContentType* content_type = g_mime_object_get_content_type(object);
  if (content_type == nullptr) {
    return;
  }

  GMimePart* part = GMIME_PART(object);
  const std::string decoded = decode_part_content(part, content_type);
  if (decoded.empty()) {
    return;
  }

  if (g_mime_content_type_is_type(content_type, "text", "html")) {
    html_out = decoded;
  } else if (g_mime_content_type_is_type(content_type, "text", "plain") && plain_out.empty()) {
    plain_out = cleaned_plain_text(decoded);
  }
}

}  // namespace

ExtractedEmailBody extract_email_body(const std::string& raw_rfc822) {
  ExtractedEmailBody out;

  if (raw_rfc822.empty()) {
    return out;
  }

  ensure_gmime_initialized();

  GMimeStream* stream = g_mime_stream_mem_new_with_buffer(raw_rfc822.data(), raw_rfc822.size());
  if (stream == nullptr) {
    return out;
  }

  GMimeParser* parser = g_mime_parser_new_with_stream(stream);
  g_object_unref(stream);
  if (parser == nullptr) {
    return out;
  }

  GMimeMessage* message = g_mime_parser_construct_message(parser, nullptr);
  g_object_unref(parser);
  if (message == nullptr) {
    return out;
  }
  GObjectPtr<GMimeMessage> message_guard(message);

  out.subject = decode_header_text(g_mime_message_get_subject(message));

  InternetAddressList* from_list = g_mime_message_get_from(message);
  if (from_list != nullptr) {
    char* rendered = internet_address_list_to_string(from_list, nullptr, false);
    if (rendered != nullptr) {
      out.from = decode_header_text(rendered);
      g_free(rendered);
    }
  }

  // Extract date header
  GDateTime* date_time = g_mime_message_get_date(message);
  if (date_time != nullptr) {
    char* date_str = g_date_time_format_iso8601(date_time);
    if (date_str != nullptr) {
      out.date = date_str;
      g_free(date_str);
    }
  }

  // Extract preferred body (HTML if available, else plain text)
  // Does not recurse into nested/forwarded messages
  extract_preferred_body(g_mime_message_get_mime_part(message), out.plain_body, out.html_body);
  message_guard.reset();

  // Generate text preview: prefer plain text, fall back to HTML-to-text
  if (!out.plain_body.empty()) {
    out.text_preview = collapse_whitespace(out.plain_body);
  } else if (!out.html_body.empty()) {
    out.text_preview = html_to_text(out.html_body);
  }

  return out;
}

namespace {

// Strip surrounding `<...>` from a Message-ID header value and trim whitespace.
// GMime returns header values verbatim; the angle brackets and any leading
// whitespace are part of that string and need to come off.
std::string strip_message_id(const char* raw) {
  if (raw == nullptr) {
    return {};
  }
  std::string s(raw);
  // Trim ASCII whitespace.
  auto const not_ws = [](unsigned char c) {
    return c != ' ' && c != '\t' && c != '\r' && c != '\n';
  };
  while (!s.empty() && !not_ws(s.front())) {
    s.erase(s.begin());
  }
  while (!s.empty() && !not_ws(s.back())) {
    s.pop_back();
  }
  if (s.size() >= 2 && s.front() == '<' && s.back() == '>') {
    s = s.substr(1, s.size() - 2);
  }
  return s;
}

// Extract every `<id>` token from a header value in order. The References
// header is a space-separated list; In-Reply-To technically holds a single
// msg-id but in the wild often has free text plus the ID, so the same
// scanner works for both.
std::vector<std::string> extract_message_id_list(const char* raw) {
  std::vector<std::string> out;
  if (raw == nullptr) {
    return out;
  }
  const char* p = raw;
  while (*p != '\0') {
    if (*p == '<') {
      const char* end = std::strchr(p + 1, '>');
      if (end == nullptr) {
        break;
      }
      const std::string id(p + 1, end);
      // Reject IDs containing whitespace or nested brackets (malformed).
      if (id.find_first_of(" \t\r\n<>") == std::string::npos && !id.empty()) {
        out.push_back(id);
      }
      p = end + 1;
    } else {
      ++p;
    }
  }
  return out;
}

// Parse raw RFC822 into a GMimeMessage. The caller owns the returned ref and
// must g_object_unref it. Returns nullptr on empty input or any parser failure.
GMimeMessage* parse_rfc822_message(const std::string& raw_rfc822) {
  if (raw_rfc822.empty()) {
    return nullptr;
  }
  ensure_gmime_initialized();
  GMimeStream* stream = g_mime_stream_mem_new_with_buffer(raw_rfc822.data(), raw_rfc822.size());
  if (stream == nullptr) {
    return nullptr;
  }
  GMimeParser* parser = g_mime_parser_new_with_stream(stream);
  g_object_unref(stream);
  if (parser == nullptr) {
    return nullptr;
  }
  GMimeMessage* message = g_mime_parser_construct_message(parser, nullptr);
  g_object_unref(parser);
  return message;  // may be nullptr on malformed input
}

void strip_attachment_payloads(GMimeObject* object) {
  if (object == nullptr) {
    return;
  }
  if (GMIME_IS_MULTIPART(object)) {
    auto* multipart = GMIME_MULTIPART(object);
    const int count = g_mime_multipart_get_count(multipart);
    for (int i = 0; i < count; ++i) {
      strip_attachment_payloads(g_mime_multipart_get_part(multipart, i));
    }
    return;
  }
  if (GMIME_IS_MESSAGE_PART(object)) {
    // An attached message is itself an attachment payload. Keep the outer
    // Content-Type/Disposition/filename metadata, but not the nested original.
    GMimeMessage* empty = g_mime_message_new(false);
    if (empty == nullptr) {
      throw std::runtime_error("failed to allocate empty message/rfc822 payload");
    }
    g_mime_message_part_set_message(GMIME_MESSAGE_PART(object), empty);
    g_object_unref(empty);
    return;
  }
  if (!GMIME_IS_PART(object)) {
    return;
  }

  auto* part = GMIME_PART(object);
  GMimeContentType* content_type = g_mime_object_get_content_type(object);
  const bool inline_body = !g_mime_part_is_attachment(part)
      && content_type != nullptr
      && (g_mime_content_type_is_type(content_type, "text", "plain")
          || g_mime_content_type_is_type(content_type, "text", "html"));
  if (inline_body) {
    return;
  }

  GMimeStream* empty_stream = g_mime_stream_mem_new();
  if (empty_stream == nullptr) {
    throw std::runtime_error("failed to allocate empty attachment payload");
  }
  GMimeDataWrapper* empty_content = g_mime_data_wrapper_new_with_stream(
      empty_stream, g_mime_part_get_content_encoding(part));
  g_object_unref(empty_stream);
  if (empty_content == nullptr) {
    throw std::runtime_error("failed to wrap empty attachment payload");
  }
  g_mime_part_set_content(part, empty_content);
  g_object_unref(empty_content);
}

}  // namespace

std::string make_replay_rfc822(const std::string& raw_rfc822) {
  GObjectPtr<GMimeMessage> const message(parse_rfc822_message(raw_rfc822));
  if (message == nullptr) {
    throw std::runtime_error("failed to parse RFC822 source for replay");
  }
  strip_attachment_payloads(g_mime_message_get_mime_part(message.get()));

  GObjectPtr<GMimeStream> const stream(g_mime_stream_mem_new());
  if (stream == nullptr ||
      g_mime_object_write_to_stream(
          GMIME_OBJECT(message.get()), nullptr, stream.get()) < 0) {
    throw std::runtime_error("failed to serialize RFC822 replay source");
  }
  GByteArray const* bytes = g_mime_stream_mem_get_byte_array(GMIME_STREAM_MEM(stream.get()));
  if (bytes == nullptr) {
    throw std::runtime_error("missing serialized RFC822 replay source");
  }
  return {reinterpret_cast<const char*>(bytes->data), bytes->len};
}

namespace {

// Core thread-feature extraction from an already-parsed message. Shared by the
// standalone extract_thread_features (which parses) and preprocess_rfc822
// (which reuses its own parse). Does NOT unref the message — the caller owns it.
ExtractedThreadFeatures extract_thread_features_from_message(GMimeMessage* message) {
  ExtractedThreadFeatures out;

  if (message == nullptr) {
    return out;
  }

  // GMime handles RFC 5322 line folding internally — `g_mime_object_get_header`
  // returns the unfolded value.
  const char* irt = g_mime_object_get_header(GMIME_OBJECT(message), "In-Reply-To");
  if (irt != nullptr) {
    const auto ids = extract_message_id_list(irt);
    if (!ids.empty()) {
      out.has_in_reply_to = true;
      out.in_reply_to = ids.front();
    } else {
      // Malformed but present — record presence with the trimmed value.
      const auto fallback = strip_message_id(irt);
      if (!fallback.empty()) {
        out.has_in_reply_to = true;
        out.in_reply_to = fallback;
      }
    }
  }

  const char* refs = g_mime_object_get_header(GMIME_OBJECT(message), "References");
  if (refs != nullptr) {
    const auto ids = extract_message_id_list(refs);
    out.references_count = static_cast<int>(ids.size());
    if (!ids.empty()) {
      out.first_reference = ids.front();
    }
  }

  const char* self_id = g_mime_message_get_message_id(message);
  if (self_id != nullptr && self_id[0] != '\0') {
    // GMime returns the Message-ID without surrounding angle brackets.
    out.self_message_id = self_id;
  }

  return out;
}

}  // namespace

ExtractedThreadFeatures extract_thread_features(const std::string& raw_rfc822) {
  GMimeMessage* message = parse_rfc822_message(raw_rfc822);
  ExtractedThreadFeatures out = extract_thread_features_from_message(message);
  if (message != nullptr) {
    g_object_unref(message);
  }
  return out;
}

namespace {

bool is_domain_char(char c) {
  return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '.' || c == '-';
}

// ---- throwaway-signer shape rule (TASK-178) ---------------------------------
// Kept in sync with the offline reference implementation.
// Measured on a held-out corpus: 23/556 spam, 0/500 ham.

// Second-level labels that commonly sit under a 2-letter ccTLD as part of the
// PUBLIC SUFFIX (org.es, biz.tr, co.uk ...). Tiny stand-in for the PSL — used
// only so a public-suffix label is not counted as a "subdomain" label.
bool is_cc_sld(const std::string& label) {
  static const std::set<std::string> kCcSld = {
      "com", "org", "net", "biz", "co", "ac", "gov", "edu", "info", "mil",
      "or", "ne", "in", "gen", "web",
  };
  return kCcSld.count(label) > 0;
}

// Infrastructure host labels a legitimate sender plausibly signs under.
bool is_common_sub_label(const std::string& label) {
  static const std::set<std::string> kCommon = {
      "mail", "email", "smtp", "mx", "mta", "send", "mailer", "bounce",
      "bounces", "news", "newsletter", "info", "mkt", "marketing", "post",
      "out", "relay", "mg", "spool", "app", "apps", "notify", "notification",
      "notifications", "alert", "alerts", "update", "updates", "service",
      "services", "support", "hello", "team", "no-reply", "noreply", "reply",
      "e", "em", "m", "msg",
  };
  return kCommon.count(label) > 0;
}

// Fleet-numbering convention (mail56 / atl71 / us4 / em1234 / mail132-2): an
// alphabetic WORD (>= 2 letters) followed by digits (optionally -digits) is how
// real sending infrastructure names shards, categorically different from the
// random mid-digit / vowel-free labels of throwaway signers (f9l / 1qb / jjlw).
// A single letter + digits (m1 / m4 / t9) is not a shard word; it is throwaway
// randomness, so it must stay "generated" (kept in sync with sender_utils.py).
bool is_fleet_numbered(const std::string& label) {
  size_t i = 0;
  while (i < label.size() && std::isalpha(static_cast<unsigned char>(label[i]))) { ++i;
}
  if (i < 2 || i == label.size()) { return false;
}
  size_t d = i;
  while (d < label.size() && std::isdigit(static_cast<unsigned char>(label[d]))) { ++d;
}
  if (d == i) { return false;
}
  if (d == label.size()) { return true;
}
  if (label[d] != '-') { return false;
}
  size_t e = d + 1;
  while (e < label.size() && std::isdigit(static_cast<unsigned char>(label[e]))) { ++e;
}
  return e > d + 1 && e == label.size();
}

// Pure 8-digit labels are key-rotation date stamps, not throwaway randomness:
// Google Workspace signs custom domains as <name>-<tld>.<yyyymmdd>.gappssmtp.com,
// and a digit-bearing customer name (42-fr, beer52-com) would otherwise make
// every label read "generated" — measured 7 real ham FPs in 75,635 (TASK-178
// OOD scan); zero spam in any corpus uses a date label.
bool is_date_stamp(const std::string& label) {
  if (label.size() != 8) { return false;
}
  return std::all_of(label.begin(), label.end(), [](char c) {
    return std::isdigit(static_cast<unsigned char>(c)) != 0;
  });
}

// Machine-generated host label: not a recognizable mail-infra word, not
// fleet-numbering, not a date stamp, and short (<= 4), digit-bearing, or
// vowel-free (jjlw / how / f9l / mim / 1qb / okk).
bool looks_generated(const std::string& label) {
  if (is_common_sub_label(label) || is_fleet_numbered(label) || is_date_stamp(label)) { return false;
}
  if (label.size() <= 4) { return true;
}
  bool has_digit = false;
  bool has_vowel = false;
  for (char const c : label) {
    if (std::isdigit(static_cast<unsigned char>(c))) { has_digit = true;
}
    if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u' || c == 'y') { has_vowel = true;
}
  }
  return has_digit || !has_vowel;
}

std::vector<std::string> split_labels(const std::string& host) {
  std::vector<std::string> labels;
  std::string cur;
  for (char const c : host) {
    if (c == '.') {
      if (!cur.empty()) { labels.push_back(cur);
}
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  if (!cur.empty()) { labels.push_back(cur);
}
  return labels;
}

// Number of trailing labels forming the org-domain: 2, or 3 over a ccSLD
// public suffix (populag.org.es) so the suffix label is not counted as a
// subdomain. Shared by org_domain and the throwaway-signer depth count —
// ONE org-domain definition (mirrors sender_utils.split_org).
size_t org_label_count(const std::vector<std::string>& labels) {
  return (labels.size() >= 3 && labels.back().size() == 2 &&
          is_cc_sld(labels[labels.size() - 2]))
             ? 3 : 2;
}

// eTLD+1 with the ccSLD nod (populag.org.es, foo.co.uk). A full Public
// Suffix List lookup is still the proper fix for exotic suffixes.
std::string org_domain(const std::string& host) {
  const std::vector<std::string> labels = split_labels(to_lower_ascii(host));
  if (labels.empty()) { return "";
}
  if (labels.size() == 1) { return labels[0];
}
  const size_t n = std::min(org_label_count(labels), labels.size());
  std::string out = labels[labels.size() - n];
  for (size_t i = labels.size() - n + 1; i < labels.size(); ++i) {
    out += '.';
    out += labels[i];
  }
  return out;
}

// eTLD+1 of a bare authority ("user@host:port" -> host -> eTLD+1), or "" if none.
// Shared by the body-URL scanner and the anchor/form parsers (TASK-239).
std::string registrable_domain_from_authority(std::string authority) {
  const size_t at = authority.find('@');
  if (at != std::string::npos) { authority = authority.substr(at + 1);
}
  const size_t colon = authority.find(':');
  if (colon != std::string::npos) { authority = authority.substr(0, colon);
}
  while (!authority.empty() && authority.back() == '.') { authority.pop_back();
}
  return org_domain(authority);
}

// eTLD+1 of a single URL (an href / form action), or "" for a non-http target
// (mailto:/tel:/#fragment/relative/bare). The authority runs to the first
// path/query/fragment/quote/bracket/space, mirroring url_domains_from_bodies.
// Full lowercased host of a URL (subdomains kept; no scheme/path/port/userinfo), or ""
// for a non-http target. Used for the brand-in-subdomain scan (TASK-242), which needs the
// labels org_domain discards.
// A URL's authority (host[:port]) runs from just after the scheme to the first
// of these: a path/query/fragment separator, a quote/bracket/comma that ends the
// URL in surrounding text, or whitespace. Shared by host_from_url and the body
// link scanner so the two never drift.
bool is_url_authority_delim(char c) {
  return c == '/' || c == '?' || c == '#' || c == '"' || c == '\'' ||
         c == '<' || c == '>' || c == ')' || c == ']' || c == ',' ||
         std::isspace(static_cast<unsigned char>(c));
}

std::string host_from_url(const std::string& url) {
  size_t b = 0;
  while (b < url.size() && std::isspace(static_cast<unsigned char>(url[b]))) { ++b;
}
  const std::string lower = to_lower_ascii(url.substr(b));
  size_t start = 0;
  if (lower.rfind("http://", 0) == 0) { start = 7;
  } else if (lower.rfind("https://", 0) == 0) { start = 8;
  } else if (lower.rfind("//", 0) == 0) { start = 2;        // protocol-relative
  } else { return "";                                        // mailto:/tel:/#/relative/bare
}
  // ']' is an authority delimiter (it ends a markdown link), EXCEPT inside a
  // bracketed IPv6 authority, where it terminates the host instead. Without this
  // "http://[2001:db8::1]/" stopped at the bracket and then port-stripped at the
  // first colon, yielding "[2001" — so no IPv6 URL host ever reached the
  // downstream checks (TASK-389).
  size_t end = start;
  bool in_bracket = false;
  while (end < lower.size()) {
    if (lower[end] == '[') {
      in_bracket = true;
    } else if (lower[end] == ']') {
      ++end;
      break;
    } else if (!in_bracket && is_url_authority_delim(lower[end])) {
      break;
    }
    ++end;
  }
  std::string host = lower.substr(start, end - start);
  const size_t at = host.find('@');
  if (at != std::string::npos) { host = host.substr(at + 1);
}
  if (!host.empty() && host.front() == '[') {
    // Bracketed IPv6: the literal is what is inside, and any ":port" follows the
    // closing bracket, so it must not be cut at the address's own colons.
    const size_t close = host.find(']');
    host = close == std::string::npos ? host.substr(1) : host.substr(1, close - 1);
  } else {
    const size_t colon = host.find(':');
    if (colon != std::string::npos) { host = host.substr(0, colon);
}
  }
  while (!host.empty() && host.back() == '.') { host.pop_back();
}
  return host;
}

std::string registrable_domain_from_url(const std::string& url) {
  return registrable_domain_from_authority(host_from_url(url));
}

bool is_html_space(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
}

// Return the index where the VALUE of attribute `name` begins (the opening quote
// for a quoted value, or the first char of an unquoted value) within the tag
// [start, tag_end), or npos if the attribute is absent or valueless. `start`
// points at the tag open ('<a', '<form'); the tag name is skipped.
//
// This tokenizes attributes the way an HTML parser does (name, optional
// '=' value, quoted or unquoted) instead of substring-searching for "href" /
// "action". A substring search matches "href" inside hreflang, "action" inside
// data-action/formaction, and a decoy planted inside a prior attribute's value
// (title="href=x"), so an attacker who orders a decoy first hides the true link
// from every phish scan. Walking real attribute boundaries (and skipping whole
// values, quoted OR unquoted, so a stray quote in a value cannot desync the
// scan) resolves the attribute a browser would actually use (C8, TASK-251).
// `lower` is the lowercased tag text; the returned index aligns with the
// original html too.
size_t find_attribute(const std::string& lower, const std::string& name,
                      size_t start, size_t tag_end) {
  size_t i = start;
  while (i < tag_end && !is_html_space(lower[i])) { ++i;  // skip the tag name
}
  while (i < tag_end) {
    while (i < tag_end && (is_html_space(lower[i]) || lower[i] == '/')) { ++i;
}
    const size_t name_start = i;
    while (i < tag_end && !is_html_space(lower[i]) &&
           lower[i] != '=' && lower[i] != '/') { ++i;
}
    const size_t name_len = i - name_start;
    while (i < tag_end && is_html_space(lower[i])) { ++i;
}
    size_t value_start = std::string::npos;
    if (i < tag_end && lower[i] == '=') {
      ++i;
      while (i < tag_end && is_html_space(lower[i])) { ++i;
}
      value_start = i;
      if (i < tag_end && (lower[i] == '"' || lower[i] == '\'')) {
        const size_t e = lower.find(lower[i], i + 1);
        i = (e == std::string::npos || e >= tag_end) ? tag_end : e + 1;
      } else {
        while (i < tag_end && !is_html_space(lower[i])) { ++i;
}
      }
    }
    if (name_len == name.size() && value_start != std::string::npos &&
        lower.compare(name_start, name_len, name) == 0) {
      return value_start;
    }
    // Each iteration consumes at least one char (a name token or the '=' value),
    // so the walk always advances toward tag_end.
  }
  return std::string::npos;
}

// Index of the '>' that closes the tag opening at `open`: the '>' that is not
// inside a quoted attribute value, so a decoy value (title="a>b" href=evil) does
// not truncate the tag window before the real href is seen (C8, TASK-251). A
// plain find('>') stops at that inner '>', find_attribute then never reaches the
// href, and the whole anchor/form/image phish scan misses the off-domain link.
// This walks attribute structure (the same skeleton as find_attribute) rather
// than pairing quotes blindly: a quote INSIDE an unquoted value (data-x=a")
// starts no span, so it cannot desync the scan. npos on an unterminated quoted
// value (HTML5 consumes it to EOF, so there is no tag) or a tag that never
// closes; every caller already breaks on npos. `lower` is the lowercased tag
// text; the returned index aligns with the original html too.
size_t find_tag_end(const std::string& lower, size_t open) {
  size_t i = open;
  while (i < lower.size() && !is_html_space(lower[i]) && lower[i] != '>') { ++i;  // tag name
}
  while (i < lower.size()) {
    while (i < lower.size() && (is_html_space(lower[i]) || lower[i] == '/')) { ++i;
}
    if (i >= lower.size()) { break;
}
    if (lower[i] == '>') { return i;                        // between attributes: closes the tag
}
    while (i < lower.size() && !is_html_space(lower[i]) &&
           lower[i] != '=' && lower[i] != '/' && lower[i] != '>') { ++i;  // attribute name
}
    while (i < lower.size() && is_html_space(lower[i])) { ++i;
}
    if (i < lower.size() && lower[i] == '=') {
      ++i;
      while (i < lower.size() && is_html_space(lower[i])) { ++i;
}
      if (i < lower.size() && (lower[i] == '"' || lower[i] == '\'')) {
        const size_t e = lower.find(lower[i], i + 1);    // quoted value: '>' inside is literal
        if (e == std::string::npos) { return std::string::npos;  // unterminated quote
}
        i = e + 1;
      } else {
        while (i < lower.size() && !is_html_space(lower[i]) && lower[i] != '>') { ++i;  // unquoted
}
      }
    }
  }
  return std::string::npos;
}

// A link parsed from raw HTML: the visible (tag-stripped) anchor text and the
// registrable domain of its href (TASK-239). href_domain is "" for non-http targets.
struct AnchorPair {
  std::string visible_text;
  std::string href_domain;
};

// Extract <a href=...>text</a> pairs from RAW html (tags intact, i.e. the output of
// collect_raw_body_parts, NOT html_to_text which strips the href attribute). Single
// forward pass, case-insensitive; nested tags in the inner text are stripped by reusing
// html_to_text. Bounded to kMaxAnchors so adversarial markup can't blow up cost.
std::vector<AnchorPair> anchors_from_html(const std::string& html) {
  std::vector<AnchorPair> out;
  constexpr size_t kMaxAnchors = 256;
  const std::string lower = to_lower_ascii(html);  // length-preserving, indexes html too
  size_t pos = 0;
  while (out.size() < kMaxAnchors) {
    // Find an opening <a that is a tag (next char is whitespace or '>').
    size_t at = lower.find("<a", pos);
    while (at != std::string::npos) {
      const char after = at + 2 < lower.size() ? lower[at + 2] : '>';
      if (after == ' ' || after == '\t' || after == '\n' || after == '\r' ||
          after == '>' || after == '/') { break;
}
      at = lower.find("<a", at + 2);
    }
    if (at == std::string::npos) { break;
}
    const size_t tag_end = find_tag_end(lower, at);
    if (tag_end == std::string::npos) { break;
}
    // href value within the open tag (quoted or unquoted).
    std::string href;
    const size_t v = find_attribute(lower, "href", at, tag_end);
    if (v != std::string::npos && v < tag_end) {
      if (html[v] == '"' || html[v] == '\'') {
        const size_t e = html.find(html[v], v + 1);
        if (e != std::string::npos) { href = html.substr(v + 1, e - (v + 1));
}
      } else {
        size_t e = v;
        while (e < tag_end && html[e] != ' ' && html[e] != '\t' && html[e] != '>') { ++e;
}
        href = html.substr(v, e - v);
      }
    }
    // Inner HTML up to </a> (or the next <a / EOF if malformed), tag-stripped to text.
    const size_t close = lower.find("</a", tag_end + 1);
    const size_t next_open = lower.find("<a", tag_end + 1);
    size_t inner_end = close;
    if (inner_end == std::string::npos || (next_open != std::string::npos && next_open < inner_end)) {
      inner_end = (next_open == std::string::npos) ? html.size() : next_open;
    }
    const std::string inner_html = html.substr(tag_end + 1, inner_end - (tag_end + 1));
    AnchorPair p;
    p.visible_text = collapse_whitespace(html_to_text(inner_html));
    p.href_domain = registrable_domain_from_url(href);
    out.push_back(std::move(p));
    pos = (close != std::string::npos && close > tag_end) ? close + 3 : inner_end;
  }
  return out;
}

// Anchors from a parsed message's RAW html parts (no re-parse), mirroring
// body_url_domains_from_message.
std::vector<AnchorPair> anchors_from_message(GMimeMessage* message) {
  std::vector<std::string> plain_parts;
  std::vector<std::string> html_parts;
  collect_raw_body_parts(g_mime_message_get_mime_part(message), plain_parts, html_parts);
  std::vector<AnchorPair> out;
  for (const std::string& h : html_parts) {
    auto pairs = anchors_from_html(h);
    for (auto& p : pairs) { out.push_back(std::move(p));
}
  }
  return out;
}

// Registrable domains of the action= of any <form> that contains a password input
// (TASK-239 AC#3): a credential-harvest form posting off-domain is a strong phish tell.
// Bounded to kMaxForms. Inner <input type=password> is matched case-insensitively with
// or without quotes/spacing.
std::vector<std::string> credential_form_actions(const std::string& html) {
  std::vector<std::string> out;
  constexpr size_t kMaxForms = 64;
  const std::string lower = to_lower_ascii(html);
  size_t pos = 0;
  while (out.size() < kMaxForms) {
    const size_t f = lower.find("<form", pos);
    if (f == std::string::npos) { break;
}
    const size_t tag_end = find_tag_end(lower, f);
    if (tag_end == std::string::npos) { break;
}
    std::string action;
    const size_t v = find_attribute(lower, "action", f, tag_end);
    if (v != std::string::npos && v < tag_end) {
      if (html[v] == '"' || html[v] == '\'') {
        const size_t e = html.find(html[v], v + 1);
        if (e != std::string::npos) { action = html.substr(v + 1, e - (v + 1));
}
      } else {
        size_t e = v;
        while (e < tag_end && html[e] != ' ' && html[e] != '\t' && html[e] != '>') { ++e;
}
        action = html.substr(v, e - v);
      }
    }
    const size_t close = lower.find("</form", tag_end + 1);
    const size_t next = lower.find("<form", tag_end + 1);
    size_t end = close;
    if (end == std::string::npos || (next != std::string::npos && next < end)) {
      end = (next == std::string::npos) ? lower.size() : next;
    }
    const std::string inner = lower.substr(tag_end + 1, end - (tag_end + 1));
    // A password field anywhere in the form (type=password, quoted or not).
    bool const has_password = inner.find("type=password") != std::string::npos ||
                        inner.find("type=\"password\"") != std::string::npos ||
                        inner.find("type='password'") != std::string::npos;
    if (has_password) {
      const std::string d = registrable_domain_from_url(action);
      if (!d.empty()) { out.push_back(d);
}
    }
    pos = (close != std::string::npos && close > tag_end) ? close + 5 : end;
  }
  return out;
}

std::vector<std::string> credential_form_actions_from_message(GMimeMessage* message) {
  std::vector<std::string> plain_parts;
  std::vector<std::string> html_parts;
  collect_raw_body_parts(g_mime_message_get_mime_part(message), plain_parts, html_parts);
  std::vector<std::string> out;
  for (const std::string& h : html_parts) {
    for (auto& d : credential_form_actions(h)) { out.push_back(std::move(d));
}
  }
  return out;
}

// Image-only / logo-spoof body (TASK-239 AC#4): an HTML body with near-zero visible text
// that is dominated by an anchored <img> linking OFF-domain. Returns the registrable
// domain of the first such anchored-image link (or "" if the body is not image-only).
// kMaxTextChars keeps it to genuinely text-empty bodies (a real logo-spoof phish).
std::string image_only_offdomain_link(GMimeMessage* message, const std::string& from_org) {
  std::vector<std::string> plain_parts;
  std::vector<std::string> html_parts;
  collect_raw_body_parts(g_mime_message_get_mime_part(message), plain_parts, html_parts);
  if (html_parts.empty()) { return "";
}
  std::string text;
  std::string html;
  for (const std::string& p : plain_parts) { text += p;
}
  for (const std::string& h : html_parts) { html += h;
}
  // Visible text across the whole body (plain + html stripped).
  text += html_to_text(html);
  size_t visible = 0;
  for (char const c : text) { if (!std::isspace(static_cast<unsigned char>(c))) { ++visible;
}
}
  constexpr size_t kMaxTextChars = 120;
  if (visible > kMaxTextChars) { return "";
}
  for (const std::string& h : html_parts) {
    const std::string lower = to_lower_ascii(h);
    // An <a ...> whose inner HTML (up to </a>) contains an <img>, with an off-domain href.
    size_t pos = 0;
    while (true) {
      const size_t at = lower.find("<a", pos);
      if (at == std::string::npos) { break;
}
      const size_t tag_end = find_tag_end(lower, at);
      if (tag_end == std::string::npos) { break;
}
      const size_t close = lower.find("</a", tag_end + 1);
      const size_t inner_end = close == std::string::npos ? lower.size() : close;
      pos = inner_end + 1;
      const size_t img = lower.find("<img", tag_end);  // scan once, not twice
      if (img == std::string::npos || img > inner_end) { continue;
}
      std::string href;
      const size_t v = find_attribute(lower, "href", at, tag_end);
      if (v != std::string::npos && v < tag_end) {
        if (h[v] == '"' || h[v] == '\'') {
          const size_t e = h.find(h[v], v + 1);
          if (e != std::string::npos) { href = h.substr(v + 1, e - (v + 1));
}
        } else {  // unquoted href (valid HTML5): runs to whitespace or '>'
          size_t e = v;
          while (e < tag_end && h[e] != ' ' && h[e] != '\t' && h[e] != '>') { ++e;
}
          href = h.substr(v, e - v);
        }
      }
      const std::string d = registrable_domain_from_url(href);
      if (!d.empty() && d != from_org) { return d;
}
    }
  }
  return "";
}

// All link hosts (FULL, subdomains kept) in the body: plain-text URLs + raw-HTML hrefs.
// Unlike body_url_domains_from_message (which org-reduces and loses the subdomain), this
// keeps the labels the brand-in-subdomain scan needs (TASK-242). Bounded to kMaxHosts.
std::vector<std::string> link_hosts_from_message(GMimeMessage* message) {
  std::vector<std::string> plain_parts;
  std::vector<std::string> html_parts;
  collect_raw_body_parts(g_mime_message_get_mime_part(message), plain_parts, html_parts);
  std::vector<std::string> out;
  constexpr size_t kMaxHosts = 512;
  auto const scan = [&](const std::string& s) {
    const std::string lower = to_lower_ascii(s);
    size_t pos = 0;
    while (out.size() < kMaxHosts) {
      const size_t at = lower.find("http", pos);
      if (at == std::string::npos) { break;
}
      // Only a real scheme starts a URL. A bare "http" (e.g. a long
      // delimiter-free "httphttp..." run) advances cheaply instead of copying the
      // whole tail. For a real URL, copy only scheme+authority (to the first
      // authority delimiter), so each host_from_url is O(host), not O(tail). pos
      // still advances just past the scheme, so a second URL embedded in this
      // one's path/query (a redirect link) is still found next iteration: same
      // hosts as before, without the O(n^2) tail copies (C7: was O(n^2), TASK-251).
      size_t scheme = 0;
      if (lower.compare(at, 7, "http://") == 0) { scheme = 7;
      } else if (lower.compare(at, 8, "https://") == 0) { scheme = 8;
}
      if (scheme == 0) { pos = at + 4; continue; }
      size_t end = at + scheme;
      while (end < s.size() && !is_url_authority_delim(s[end])) { ++end;
}
      std::string h = host_from_url(s.substr(at, end - at));
      if (!h.empty()) { out.push_back(std::move(h));
}
      pos = at + scheme;
    }
  };
  for (const std::string& p : plain_parts) { scan(p);
}
  for (const std::string& h : html_parts) { scan(h);
}
  return out;
}

// Structural body-URL features (TASK-257). Reuses the full-host link scan (no
// extra parse) and flags a bare-IP host: a link to a raw IP is a textbook
// phishing tell that legit domain-named senders don't produce.
ExtractedUrlFeatures extract_url_features_from_message(GMimeMessage* message) {
  ExtractedUrlFeatures out;
  if (message == nullptr) { return out;
}
  for (const std::string& h : link_hosts_from_message(message)) {
    if (host_is_ip_literal(h)) { out.raw_ip_url = true; break; }
  }
  return out;
}

// Body parts are passed in rather than re-collected: collect_raw_body_parts
// transfer-decodes and charset-transcodes every text part, so calling it again
// would re-decode the whole message to compute one bool that is false for
// essentially all traffic. preprocess_rfc822 already has the parts in hand.
ExtractedBodyFeatures body_features_from_parts(
    const char* subject,
    const std::vector<std::string>& plain_parts,
    const std::vector<std::string>& html_parts) {
  ExtractedBodyFeatures out;
  if (subject != nullptr && contains_gtube(subject)) {
    out.gtube_test = true;
    return out;
  }
  // SpamAssassin's convention puts the string in the BODY; Stalwart checks the
  // subject. Accept either, so a test message written for either convention
  // proves the same thing. These parts are transfer-decoded but not
  // whitespace-normalized, which is what the verbatim match needs.
  for (const std::vector<std::string>* parts : {&plain_parts, &html_parts}) {
    for (const std::string& body : *parts) {
      if (contains_gtube(body)) {
        out.gtube_test = true;
        return out;
      }
    }
  }

  // The callback shape needs the WHOLE body, not one part at a time: a lure that
  // puts the number in the text part and the links in the HTML part would
  // otherwise look link-free. Joined once, from the parts already decoded here.
  std::string joined;
  for (const std::vector<std::string>* parts : {&plain_parts, &html_parts}) {
    for (const std::string& body : *parts) {
      joined += body;
      joined += '\n';
    }
  }
  const std::string subject_str =
      subject != nullptr ? std::string(subject) : std::string();
  out.callback_shape = callback_shape::matches(subject_str, joined);

  // The no-contact predicate reads the VISIBLE TEXT, not the markup. The
  // callback shape wants the raw HTML because it hunts for hrefs, but a phrase
  // matcher run over raw HTML is defeated by ordinary formatting: measured,
  // "ne contactez pas <strong>votre agence</strong>" scored 0 while the same
  // sentence unstyled scored 1. That is not an exotic evasion, it is what a
  // marketing template does to every sentence it emphasises -- and it is also a
  // one-tag evasion for anyone who notices. html_to_text is idempotent on text
  // that carries no markup, so applying it to both part lists is safe for the
  // caller that has already converted them.
  std::string visible;
  for (const std::vector<std::string>* parts : {&plain_parts, &html_parts}) {
    for (const std::string& body : *parts) {
      visible += html_to_text(body);
      visible += '\n';
    }
  }
  out.no_contact_instruction = no_contact_shape::matches(subject_str, visible);
  return out;
}

ExtractedBodyFeatures extract_body_features_from_message(GMimeMessage* message) {
  if (message == nullptr) { return {};
}
  std::vector<std::string> plain_parts;
  std::vector<std::string> html_parts;
  collect_raw_body_parts(g_mime_message_get_mime_part(message), plain_parts, html_parts);
  return body_features_from_parts(g_mime_message_get_subject(message),
                                  plain_parts, html_parts);
}

// A FULL host deceptively presents a brand its registrable owner is not (TASK-242), the
// dominant real-phish pattern doc-14 measured that org-domain reduction misses:
//  - subdomain deception: a curated canonical brand domain appears as labels in the host
//    but is NOT the registrable (accounts.google.com.medbp.com -> google.com / medbp.com).
//  - brand-in-subdomain: a distinctive (Tier-1 coined) brand confusable-folds into the
//    SUBDOMAIN, and the registrable is not that brand's own domain (11paypal.duckdns.org).
// Distinctive-only + len>=5 keeps substring matching off dictionary words; the registrable
// not being the brand's canonical domain exempts a brand's own subdomains.
bool host_impersonates_brand(const std::string& host) {
  if (host.find('.') == std::string::npos) { return false;
}
  const std::string reg = org_domain(host);
  // The registrable itself is a curated brand domain: the brand's own host (any
  // subdomain, and canonical ccTLD variants like paypal.com.au whose labels contain
  // another canonical domain). MUST precede the label-pair loop: paypal.com.au
  // contains the labels "paypal.com" and would otherwise self-flag as deception.
  if (brand_kb::is_canonical_domain(reg)) { return false;
}
  const std::vector<std::string> labels = split_labels(host);
  // Subdomain deception: a curated canonical brand domain (2- OR 3-label, e.g. paypal.com
  // or a co.uk brand) appears as SUBDOMAIN labels of a registrable that is not the brand.
  // Candidates starting inside the registrable's own trailing labels ARE the registrable
  // (google.com inside google.com.tr, a ccTLD variant the KB has not enumerated), so the
  // scan stops there. The bound is positional, NOT stem equality: an attacker registrable
  // that merely shares the brand's stem (paypal.com hung above paypal.tk) must still fire.
  const std::size_t reg_start =
      labels.size() - std::min(org_label_count(labels), labels.size());
  for (std::size_t i = 0; i + 1 < labels.size() && i < reg_start; ++i) {
    const std::string cand2 = labels[i] + "." + labels[i + 1];
    if (brand_kb::is_canonical_domain(cand2)) { return true;
}
    if (i + 2 < labels.size()) {
      const std::string cand3 = cand2 + "." + labels[i + 2];
      if (brand_kb::is_canonical_domain(cand3)) { return true;
}
    }
  }
  if (host.size() <= reg.size()) { return false;               // no subdomain
}
  const std::string reg_sld = brand_names::domain_stem(reg);
  // Brand-in-subdomain: a DISTINCTIVE (coined, Tier-1) brand as a complete TOKEN of the
  // subdomain -- a dot-label or a hyphen part, with leading/trailing digits stripped and
  // confusable-folded (11paypal -> paypal, paypa1 -> paypal). EXACT-token only, NOT a
  // substring, so 'interac' does not match the legit word 'interactive', 'chase' not
  // 'purchase', 'ameli' not 'amelie'. Dictionary-word brands (apple/amazon/chase/orange)
  // are deliberately NOT matched in subdomains: as a bare token they collide with legit
  // compounds (orange-county, apple-valley), so they need the claimed-vs-authenticated KB
  // (TASK-232), not link scanning. This is the precision-hardened form after a code review
  // found the substring path false-firing on legit ESP/SaaS hosts.
  const std::string sub = host.substr(0, host.size() - reg.size());
  std::string tok;
  for (std::size_t i = 0; i <= sub.size(); ++i) {
    const char c = i < sub.size() ? sub[i] : '.';
    if (c == '.' || c == '-' || c == '_') {
      std::size_t a = 0;
      std::size_t b = tok.size();
      while (a < b && std::isdigit(static_cast<unsigned char>(tok[a]))) { ++a;
}
      while (b > a && std::isdigit(static_cast<unsigned char>(tok[b - 1]))) { --b;
}
      const std::string t = brand_names::confusable_fold(tok.substr(a, b - a));
      if (t.size() >= 5 && t != reg_sld &&
          brand_kb::is_brand_sld(t) && brand_names::is_distinctive_brand(t)) {
        return true;
      }
      tok.clear();
    } else {
      tok.push_back(c);
    }
  }
  return false;
}

// Attacker keywords that mark a brand-adjacent domain as a phishing combosquat rather
// than the brand's own infrastructure (paypal-secure vs paypal-email). Shared by the
// From/body distinctive-combosquat check and the anchor brand-prefix exemption (which
// also covers Tier-2 brands, where is_phishy_combosquat below does not apply).
// The UNAMBIGUOUS subset: keywords a legit brand never registers in a sending domain. A
// distinctive Tranco brand combosquat is licensed by ANY phishy keyword (the rare coined name is
// itself the precision), but a dictionary-word brand (orange, visa, shell) is licensed ONLY by a
// strong keyword -- the dual-use words (account, update, support, billing, service, portal,
// confirm, alert) appear in legit brand domains (visa-service, brand-support) and over-fire on a
// common word. Anchors are exempt from this narrowing: there the brand is CLAIMED in the visible
// text, which corroborates the dual-use keyword (href_lookalikes_brand uses the full set).
// The list was English-only until 2026-08-29, and the genre it was missing is the
// one our users actually report: French transactional imitation. `amazon-prime-
// resiliation.com` carries the brand token and a cancellation word, which is the
// same shape as `amazon-verify.com`, and fired on neither path -- "amazon" is a
// dictionary word (the river), so it is Tier-2, so a keyword is the ONLY thing
// that can license its combosquat, and no French one existed. Measured: the lure
// went from delivered at every profile to filed at both, with the transactional
// ham FP rate unchanged (model-lab/scripts/eval_fraud_discourse.py, and the
// before/after in eval-transactional).
//
// The bar for this set is unchanged and is what keeps it safe: a word a legit
// brand never puts in a SENDING domain. `resiliation`/`kuendigung` clear it for
// the same reason `unlock` does -- a brand cancels a subscription in its account
// area, it does not register a domain to do it from. Words that merely SOUND
// French-official (paiement, facture, compte, service) are dual-use and go in
// the wider set below, exactly as their English twins do.
const std::set<std::string>& strong_phishy_keywords() {
  static const std::set<std::string> k = {
      // English
      "secure", "security", "login", "signin", "verify", "verification",
      "recover", "recovery", "unlock", "suspended", "auth", "validate",
      // French. Accent-free by construction: a DNS label is ASCII, so
      // "verification" already covers "vérification" and needs no second entry.
      "securite", "securise", "connexion", "identifiant", "authentification",
      "deblocage", "debloquer", "suspendu", "validation", "resiliation",
      "resilier", "verifier",
      // German
      "sicherheit", "anmeldung", "anmelden", "verifizierung", "entsperren",
      "kuendigung", "bestaetigung",
  };
  return k;
}

// Attacker keywords that mark a brand-adjacent domain as a phishing combosquat rather than the
// brand's own infrastructure (paypal-secure vs paypal-email). The full set = the strong subset
// above PLUS the dual-use words; deriving it from strong_phishy_keywords() keeps the subset
// invariant by construction (a strong keyword added in one place can never go missing here).
// Shared by the distinctive-combosquat check and the anchor brand-prefix exemption.
const std::set<std::string>& phishy_keywords() {
  static const std::set<std::string> k = [] {
    std::set<std::string> s = strong_phishy_keywords();
    s.insert({"account", "update", "confirm", "support", "alert", "billing", "service", "portal",
              // French/German twins of the dual-use words above, dual-use for the
              // same reason: a real brand does register orange-assistance.fr or
              // lidl-kundenservice.de, so these license a combosquat only for a
              // DISTINCTIVE brand, never for a dictionary-word one.
              "compte", "paiement", "facture", "remboursement", "assistance", "client",
              "konto", "zahlung", "rechnung", "kundenservice"});
    return s;
  }();
  return k;
}

// Invoke fn for each '-'/'_'/'.'-delimited token of stem; stop early when fn returns true.
// The shared splitter for the combosquat-token checks below (a stem is a single DNS label,
// so '.' never actually appears, but accepting it keeps callers uniform).
// fn is invoked once per token in the loop below, so it is deliberately never
// forwarded/moved-from.
template <typename F>
// NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward)
bool any_stem_token(const std::string& stem, F&& fn) {
  size_t start = 0;
  while (start <= stem.size()) {
    const size_t sep = stem.find_first_of("-_.", start);
    if (fn(stem.substr(start, sep == std::string::npos ? std::string::npos : sep - start))) {
      return true;
}
    if (sep == std::string::npos) { break;
}
    start = sep + 1;
  }
  return false;
}

// The stem with word separators removed: a multi-word brand's hyphenated displayed domain
// (deutsche-bank) maps to its joined KB key (deutschebank).
// Fold Latin accents to their ASCII base, for the keyword lookup only.
//
// WHY THIS IS REQUIRED AND NOT A NICETY. The keyword sets are ASCII by
// construction, on the reasoning that a DNS label is ASCII. That is false for an
// IDN: GMime decodes `xn--amazon-prime-rsiliation-occ.com` to
// `amazon-prime-résiliation.com` before any of this runs, so the token the set
// is queried with is `résiliation` and the ASCII entry never matches. Verified
// against the built library: the ASCII domain scores display_impersonation=1 and
// both the punycode and raw-UTF-8 accented spellings score 0.
//
// For the English keywords that gap was theoretical. For the French ones it is
// the DEFAULT: `résiliation`, `sécurité` and `vérification` are the natural
// spellings, so the accented domain is the likelier registration and the ASCII
// one the exception. Shipping the keyword list without this would have been a
// mitigation an attacker bypasses by spelling the word correctly.
//
// Deliberately narrow: Latin-1 Supplement plus the Latin Extended-A letters that
// French, German, Spanish and Portuguese actually use. It is NOT a general
// Unicode normalizer and must not become one -- the homoglyph problem (Cyrillic
// а for Latin a) is a DIFFERENT attack with a different table, handled by
// brand_names::confusable_fold_unicode, and folding both here would let a
// Cyrillic domain match a keyword without the homoglyph path ever seeing it.
// Three spellings of the same word have to fold to one, because all three are
// registrable and a domain is compared case-insensitively:
//   precomposed lower   résiliation   (0xC3 0xA9)
//   precomposed UPPER   RÉSILIATION   (0xC3 0x89) -- to_lower_ascii cannot touch it
//   decomposed (NFD)    re<U+0301>siliation
// The uppercase half became reachable BECAUSE to_lower_ascii was fixed to leave
// bytes >= 0x80 alone: the locale tolower it replaced used to fold 0xC3 0x89 to
// mojibake, which matched nothing either, so this was never a working path. The
// decomposed half is what a Mac produces by default when you type the accent.
std::string fold_latin_accents(const std::string& s) {
  // Both cases of each letter, folded to the lower-case ASCII base.
  static const std::pair<const char*, char> kFolds[] = {
      {"à", 'a'}, {"á", 'a'}, {"â", 'a'}, {"ã", 'a'}, {"ä", 'a'}, {"å", 'a'},
      {"À", 'a'}, {"Á", 'a'}, {"Â", 'a'}, {"Ã", 'a'}, {"Ä", 'a'}, {"Å", 'a'},
      {"è", 'e'}, {"é", 'e'}, {"ê", 'e'}, {"ë", 'e'},
      {"È", 'e'}, {"É", 'e'}, {"Ê", 'e'}, {"Ë", 'e'},
      {"ì", 'i'}, {"í", 'i'}, {"î", 'i'}, {"ï", 'i'},
      {"Ì", 'i'}, {"Í", 'i'}, {"Î", 'i'}, {"Ï", 'i'},
      {"ò", 'o'}, {"ó", 'o'}, {"ô", 'o'}, {"õ", 'o'}, {"ö", 'o'}, {"ø", 'o'},
      {"Ò", 'o'}, {"Ó", 'o'}, {"Ô", 'o'}, {"Õ", 'o'}, {"Ö", 'o'}, {"Ø", 'o'},
      {"ù", 'u'}, {"ú", 'u'}, {"û", 'u'}, {"ü", 'u'},
      {"Ù", 'u'}, {"Ú", 'u'}, {"Û", 'u'}, {"Ü", 'u'},
      {"ç", 'c'}, {"ñ", 'n'}, {"ý", 'y'}, {"ÿ", 'y'},
      {"Ç", 'c'}, {"Ñ", 'n'}, {"Ý", 'y'}, {"Ÿ", 'y'},
  };
  std::string out;
  out.reserve(s.size());
  for (std::size_t i = 0; i < s.size();) {
    const auto c = static_cast<unsigned char>(s[i]);
    // Combining diacritics, U+0300..U+036F: 0xCC 0x80..0xBF and 0xCD 0x80..0xAF.
    // Dropping them turns the decomposed spelling into the base letter, which
    // the ASCII path below then handles unchanged.
    if (i + 1 < s.size() &&
        ((c == 0xCC) ||
         (c == 0xCD && static_cast<unsigned char>(s[i + 1]) <= 0xAF))) {
      i += 2;
      continue;
    }
    bool folded = false;
    if (c >= 0xC0 && i + 1 < s.size()) {
      const std::string pair2 = s.substr(i, 2);
      // ß is here rather than in the table because it expands to two characters.
      if (pair2 == "ß") { out += "ss"; i += 2; continue; }
      for (const auto& f : kFolds) {
        if (pair2 == f.first) { out.push_back(f.second); i += 2; folded = true; break; }
      }
    }
    if (!folded) {
      // Lower-case the ASCII we pass through: the uppercase folds above emit a
      // lower-case base, so "SÉCURITÉ" must not come out as "SeCURITe".
      out.push_back((s[i] >= 'A' && s[i] <= 'Z')
                        ? static_cast<char>(s[i] - 'A' + 'a')
                        : s[i]);
      ++i;
    }
  }
  return out;
}

std::string dehyphenate(const std::string& stem) {
  std::string out;
  for (char const c : stem) { if (c != '-' && c != '_') { out.push_back(c);
}
}
  return out;
}

// Any '-'/'_'/'.'-delimited token of the stem is an attacker keyword (apple-secure -> yes,
// apple-news -> no). Brand-agnostic, so it discriminates a combosquat from a brand's own
// infra for ANY brand, not only the distinctive ones is_phishy_combosquat handles.
bool stem_has_phishy_keyword(const std::string& stem) {
  return any_stem_token(stem, [](const std::string& t) {
    return phishy_keywords().count(fold_latin_accents(t)) > 0;
  });
}

// Does this separator-less stem decompose ENTIRELY into words we already list,
// with a KB brand and a strong keyword among them?
//
// The vocabulary is the four lists the engine already maintains, so this adds no
// new data to keep in sync: KB brand SLDs, phishy keywords, role words, and
// brand continuations (which carry the product lines). A cover is what tells a
// real concatenation from a coincidence, and that distinction is the entire
// reason this shape was chosen over the two that were tried first.
// EVERY token in the cover must itself be evidence. Not "a word the engine
// happens to know": that admitted role words and brand continuations as filler,
// and a count of three generic-but-known tokens is not a construction.
//
// `officesecuritysolutions.com` is the case that proved it, found by a cold
// review. It decomposed as [office][security][solutions], cleared the
// three-token floor, and set display_impersonation on a plausible security
// vendor's own domain -- at 0.99, on the bounce allowlist. The floor's comment
// below claims "no ordinary noun phrase looks like it", and "office security
// solutions" is an ordinary noun phrase, so the premise was simply wrong.
//
// A count cannot separate those, but composition can. The lure decomposes into
// a brand, ITS OWN product line, and an account action: [amazon][prime]
// [resiliation]. The vendor decomposes into a brand, a keyword, and a generic
// noun, and that generic noun is now inadmissible, so the cover fails rather
// than being outvoted.
bool is_known_stem_token(const std::string& t) {
  if (t.size() < 3) { return false;
}
  return brand_kb::is_brand_sld(t) ||
         // The STRONG set, not phishy_keywords(): the weak set exists to
         // corroborate elsewhere and is broad enough to be filler here.
         strong_phishy_keywords().count(t) > 0 ||
         // Product-line words, UNSCOPED here on purpose: see
         // is_product_line_word. The cover already requires a brand, a strong
         // keyword and a full decomposition, so a connecting product word cannot
         // build a match on its own.
         brand_names::is_product_line_word(t);
}

// THREE TOKENS MINIMUM, and that floor is the whole safety of this rule.
//
// A cover of exactly TWO tokens is how ordinary domains are built. `freesecurity`
// covers as [free][security] and "free" is a KB brand (the French ISP), so the
// first version of this fired on it -- the exact collision the comment at the
// call site names as the reason containment was rejected, shipped anyway because
// the tests only probed `freelancesecurity`. It is not a lone case:
// `officesecurity`, `livesecurity`, `visasecurity`, `wisesecurity` and
// `metasecurity` are all a KB brand glued to a strong keyword, and all read as
// perfectly ordinary product names. display_impersonation is a 0.99 offset that
// CAN authorize a bounce, so this was the worst place in the engine to be loose.
//
// Three tokens is different in kind. `amazonprimeresiliation` is [amazon][prime]
// [resiliation]: a brand, its product line, and an account action. Nobody
// registers that by accident, and no ordinary noun phrase looks like it.
//
// The accepted loss is stated rather than hidden: `amazonresiliation` (two
// tokens, Tier-2 brand) no longer fires here. It is structurally identical to
// `freesecurity` and cannot be told apart from it by this rule, so treating them
// the same is the honest outcome. The HYPHENATED spelling still fires through
// is_phishy_combosquat's token path, which is unchanged, and hyphenation is
// itself evidence of construction in a way concatenation is not.
inline constexpr std::size_t kMinCoverTokens = 3;

bool covers_brand_and_strong_keyword(const std::string& stem) {
  // Reachability over (position, seen a brand, seen a strong keyword, token
  // count capped at the floor). A DNS label is at most 63 bytes, so the scan is
  // bounded and tiny.
  const std::size_t n = stem.size();
  if (n < 9 || n > 63) { return false;
}
  const std::size_t kCap = kMinCoverTokens;  // count saturates here
  // No vocabulary entry is longer than this, so a candidate beyond it cannot be
  // a token and the inner loop stops. Without the bound the scan is O(n^2) in
  // the label length with a heap allocation per pair: measured 244 us on a
  // crafted 63-character stem of nothing but known tokens, which is
  // attacker-chosen input. `tok` is also hoisted so assign() reuses one buffer
  // instead of allocating ~2,000 short strings per call.
  constexpr std::size_t kMaxTokenLen = 24;
  // Each (i, j) substring is classified AT MOST ONCE, and only for a position
  // the DP can actually reach. Two earlier shapes were both worse and the
  // measurements are why this one is here:
  //
  //   classify inside the t/b/k loops   280 us  every pair classified 16x over
  //   precompute the whole table        699 us  every pair classified, reachable
  //                                             or not, and most are not
  //   this (lazy + hoisted)             110 us  only reachable positions, once
  //
  // All three timed the same way: spam_engine_extract_auth_features over a
  // message whose From domain is the adversarial stem, 2,000 calls after 50
  // warm-up, so the figures include parsing and are comparable to the 244 us
  // above. They are the WORST case by construction. The same call on the real
  // lure domain (amazon-prime-resiliation) is 15 us, which is the laziness
  // argument stated as a number: a genuine stem reaches almost no state.
  //
  // The eager table looked like the obvious optimisation and was 2.5x slower
  // than the naive version, because on a real stem almost no position is
  // reachable and the lazy form skipped them for free. Laziness is the win;
  // hoisting out of the STATE loops is the rest of it.
  struct Tok { bool known; bool brand; bool strong; };
  std::vector<std::vector<std::array<std::array<bool, 2>, 2>>> reach(
      n + 1, std::vector<std::array<std::array<bool, 2>, 2>>(
                 kCap + 1, {{{{false, false}}, {{false, false}}}}));
  reach[0][0][0][0] = true;
  std::string tok;
  std::vector<Tok> row(kMaxTokenLen + 1);
  for (std::size_t i = 0; i < n; ++i) {
    bool any = false;
    for (std::size_t t = 0; t <= kCap && !any; ++t) {
      for (int b = 0; b < 2 && !any; ++b) {
        for (int k = 0; k < 2 && !any; ++k) { any = reach[i][t][b][k];
}
      }
    }
    if (!any) { continue;  // unreachable prefix: classify nothing
}

    const std::size_t stop = std::min(n, i + kMaxTokenLen);
    for (std::size_t j = i + 3; j <= stop; ++j) {
      tok.assign(stem, i, j - i);
      row[j - i] = is_known_stem_token(tok)
                       ? Tok{true, brand_kb::is_brand_sld(tok),
                             strong_phishy_keywords().count(tok) > 0}
                       : Tok{false, false, false};
    }
    for (std::size_t t = 0; t <= kCap; ++t) {
      for (int b = 0; b < 2; ++b) {
        for (int k = 0; k < 2; ++k) {
          if (!reach[i][t][b][k]) { continue;
}
          for (std::size_t j = i + 3; j <= stop; ++j) {
            const Tok& tk = row[j - i];
            if (!tk.known) { continue;
}
            const std::size_t nt = t < kCap ? t + 1 : kCap;
            reach[j][nt][b || tk.brand][k || tk.strong] = true;
          }
        }
      }
    }
  }
  return reach[n][kCap][1][1];
}

// A PHISHY combosquat: a hyphen-delimited registrable domain with one token a brand AND
// another an attacker keyword (paypal-secure, orange-verify). The keyword is what makes a
// combosquat safe to flag: a legit brand-ESP domain (paypal-email.com, brand-mail, brand-
// news) carries no phishy keyword (TASK-239). The brand token may be a distinctive Tranco
// brand OR a KB brand of EITHER tier (TASK-232 AC#7): for a dictionary-word brand (orange,
// visa) the keyword is the only precision lever, exactly as the anchor path established, so
// the combosquat shape -- not a tier-1-distinctive name -- is what licenses the flag. A bare
// brand SLD len>=4 is required so a short ambiguous token (att, ing, db) does not combine
// with a keyword into a false combosquat.
bool is_phishy_combosquat(const std::string& org_domain) {
  // A curated brand's own domain is never a combosquat, whatever its stem tokenizes to.
  if (brand_kb::is_canonical_domain(org_domain)) { return false;
}
  std::string sld = brand_names::domain_stem(org_domain);
  // An `xn--` stem is decoded first, so a keyword spelled with its accents is
  // read the same whether it arrived through the From header (which GMime
  // decodes to UTF-8 for us) or through a body link (which stays punycode). It
  // was caught in the one and missed in the other, for the same message and the
  // same domain, until 2026-08-29.
  if (const std::string decoded = brand_names::idn_to_utf8(sld); !decoded.empty()) {
    sld = decoded;
  }
  if (sld.find_first_of("-_") == std::string::npos) {
    // Separator-less concatenation (TASK-251 FN1): a DISTINCTIVE brand glued directly to a
    // phishy keyword (paypalsupport, paypalverify, securepaypal). With no token to split
    // on, the exact brand+keyword / keyword+brand split is tested instead. Distinctive
    // (Tier-1 coined) brands only: a dictionary-word brand as a bare substring collides
    // with legit compounds (applet, freesecurity), and the curated distinctive set is
    // what licenses the any-keyword policy on the separator path too.
    // The keyword REMAINDER is folded, for the same reason the token path folds:
    // `paypalsecurite.com` fired and `paypalsécurité.com` did not, because this
    // branch queried the ASCII set with an accented string. The brand halves are
    // compared unfolded and against the curated ASCII stems, as everywhere else.
    for (const std::string& b : brand_kb::distinctive_slds()) {
      if (sld.size() <= b.size()) { continue;
}
      if (sld.compare(0, b.size(), b) == 0 &&
          phishy_keywords().count(fold_latin_accents(sld.substr(b.size())))) { return true;
}
      if (sld.compare(sld.size() - b.size(), b.size(), b) == 0 &&
          phishy_keywords().count(
              fold_latin_accents(sld.substr(0, sld.size() - b.size())))) { return true;
}
    }
    // A DICTIONARY-WORD (Tier-2) KB brand glued to a STRONG keyword, which is
    // the same asymmetry the hyphen path below already applies to that tier:
    // Tier-1 is licensed by any phishy keyword, Tier-2 only by a strong one.
    // Without it, removing the hyphens walked straight through the fix that
    // caught `amazon-prime-resiliation.com`: `amazonprimeresiliation.com` is one
    // keystroke away and matched nothing, because "amazon" is a dictionary word
    // and this branch was Tier-1-only.
    //
    // The test is a full TOKEN COVER, not a two-way split and not containment.
    // The stem must decompose ENTIRELY into words the engine already lists, with
    // nothing left over, and that cover must include a KB brand and a strong
    // keyword. See the note below for why the other two shapes both failed.
    //
    // The comment above warns that a dictionary brand as a bare substring
    // collides with legit compounds, and names `applet` and `freesecurity`. The
    // strong-keyword narrowing already answers the first: "let" is not a keyword,
    // so `applet` cannot fire. Measured for the rest over 2,908 distinct ham From
    // org-stems across the applemail, personalization, regular, marketing and
    // eml_good corpora: ZERO would newly fire. On the trap side it adds exactly
    // one stem in 76,076 (`adobelogin`), which is the honest yield: this genre
    // registers domains, it does not send from ones a trap has seen.
    //
    // The folded stem is what the split is searched over, so an accented keyword
    // is found here too. A KB brand stem is ASCII, so folding leaves that half
    // untouched and the brand lookup is unaffected.
    //
    // THREE SHAPES WERE TRIED. The first two are why the third looks elaborate.
    //
    // 1. EXACT TWO-WAY SPLIT (brand + keyword composing the whole stem). Safe,
    //    and too weak: a middle token defeats it, so `amazonprimeresiliation.com`
    //    walked through while its hyphenated twin was caught. One keystroke.
    //
    // 2. CONTAINMENT (a brand anywhere, a keyword anywhere). Catches the lure,
    //    and REJECTED. It measured 0 false positives on 2,908 distinct ham From
    //    org-stems, which was not evidence: the corpus cannot bound a rule whose
    //    match surface is every substring of a domain against a 142-entry brand
    //    list. Adversarial probes found the collisions at once, all of them a
    //    brand cut out of the middle of an ordinary word:
    //
    //      deliverysecurity   -> "live"  in de|LIVE|rysecurity
    //      olivesecurity      -> "live"  in o|LIVE|security
    //      freelancesecurity  -> "free" + "lance", and "lance" is not a word here
    //      alivelogin         -> "live"  in a|LIVE|login
    //
    // 3. TOKEN COVER, which is what ships. The stem must decompose ENTIRELY into
    //    known words with nothing left over, and that cover must contain a KB
    //    brand and a strong keyword. `amazonprimeresiliation` covers as
    //    [amazon][prime][resiliation]; `deliverysecurity` has no cover at all,
    //    because reaching "live" strands "de" and "rysecurity". The cover is
    //    exactly the distinction containment could not draw: a real concatenation
    //    versus a coincidence.
    //
    // Measured the same way as the others, and the probes are the binding half:
    // 0 of the same 2,908 ham stems, all four collisions silent, and the benign
    // concatenations stay silent for the right reason (`amazonnews` and
    // `amazonprimevideo` both COVER, and neither carries a strong keyword).
    const std::string folded = fold_latin_accents(sld);
    return covers_brand_and_strong_keyword(folded);
  }
  bool has_distinctive = false;
  bool has_kb_brand = false;
  bool has_keyword = false;
  bool has_strong = false;
  any_stem_token(sld, [&](const std::string& t) {
    if (brand_names::is_distinctive_brand(t)) { has_distinctive = true;
    } else if (brand_kb::is_brand_sld(t)) { has_kb_brand = true;  // is_brand_sld rejects len < 4
}
    // The keyword lookups fold accents; the BRAND lookups above deliberately do
    // not. A brand is matched against a curated list of real registrable stems,
    // which are ASCII, and folding there would make an accented look-alike read
    // as the brand itself instead of as the homoglyph/IDN morph it is.
    const std::string folded = fold_latin_accents(t);
    if (phishy_keywords().count(folded)) { has_keyword = true;
}
    if (strong_phishy_keywords().count(folded)) { has_strong = true;
}
    return false;  // visit every token
  });
  // Distinctive (Tier-1) brand: any phishy keyword. Dictionary-word (Tier-2) brand: STRONG only.
  return (has_distinctive && has_keyword) || (has_kb_brand && has_strong);
}

// Where a domain was found, which sets how aggressively it is matched as a brand cousin. The base
// signal is a MORPH -- a homoglyph / typosquat / IDN corruption a legit brand never sends from
// (Tier-1) -- and the scope adds the looser combosquat / tld-swap variants only where they are
// safe:
//  - Sender: the From org-domain, the sender's OWN domain and the strongest signal. Adds the
//    Tier-1 non-keyword combosquat (is_lookalike_domain) AND the keyword combosquat of either tier
//    (is_phishy_combosquat), plus the corroboration-gated tld-swap as Tier-2 (an exact brand SLD on
//    a non-canonical TLD is ambiguous with a legit regional domain the KB has not enumerated).
//  - Link: a body URL / anchor href. Adds ONLY the keyword combosquat -- a bare/Tier-1 combosquat
//    false-fires on the legit brand-ESP / notification infra bodies routinely reference
//    (paypal-email.com, hubspotemail-na2.net), so the phishy keyword is required.
//  - MultiField: a Reply-To. The strict morph subset only; even the keyword combosquat is too loose
//    over a secondary field (notif-laposte.info).
//
// The edit-distance typosquat is claim-gated in every scope (TASK-251 FP2): one edit of a
// brand SLD is Tier-1 only when the sender's presented identity (From / Reply-To display
// and local part) also CLAIMS that brand, "PayPal" <x@paypall.com>. Unclaimed it is
// ambiguous with a legit same-name company (lacoste.com is one edit from laposte,
// telecom.pt from telekom, amelie.fr from ameli; none Tranco-rescued): on the Sender scope
// it joins the corroboration-gated Tier-2 path like the tld-swap, and on the secondary
// scopes it fires only when the mail is already corroborated by a throwaway / free-host
// signer (`corroborated`, known before any cousin call, so clean mail never pays the KB
// scan per link). The caller precomputes `claimed_brands`, the distinctive KB SLDs its
// identity claims, so the per-domain claim gate scans a tiny (usually empty) list. IDN
// homoglyphs stay unconditional Tier-1: no legit sender cross-script-encodes another
// company's name.
enum class CousinScope : std::uint8_t { Sender, Link, MultiField };
brand_names::BrandMatch brand_cousin(const std::string& domain, CousinScope scope,
                                     const std::vector<std::string>& claimed_brands,
                                     bool corroborated) {
  brand_names::BrandMatch m;
  // One edit from a brand the sender CLAIMS. Cheap: scans only the claimed brands.
  auto const claimed_typosquat = [&] {
    if (claimed_brands.empty() || brand_kb::is_canonical_domain(domain)) { return false;
}
    const std::string sld = brand_names::domain_stem(domain);
    if (sld.size() < 5) { return false;
}
    return std::any_of(claimed_brands.begin(), claimed_brands.end(), [&](const std::string& b) {
      return brand_kb::within_edit1(sld, b);
    });
  };
  // Unclaimed one-edit domain: the full KB edit-distance scan, kept LAST in each OR and
  // gated (tier2 on Sender, corroborated-only on the secondary scopes) so it stays rare.
  auto const unclaimed_typosquat = [&] { return !brand_kb::typosquat_target_kb(domain).empty(); };
  switch (scope) {
    case CousinScope::Sender:
      // is_lookalike_domain already covers the homoglyph case (so no separate is_homoglyph_domain).
      m.tier1 = brand_names::is_lookalike_domain(domain) || is_phishy_combosquat(domain) ||
                brand_kb::is_idn_lookalike_kb(domain) || claimed_typosquat();
      m.tier2 = brand_kb::is_tld_swap_kb(domain) || (!m.tier1 && unclaimed_typosquat());
      break;
    case CousinScope::Link:
      m.tier1 = brand_names::is_homoglyph_domain(domain) || brand_kb::is_idn_lookalike_kb(domain) ||
                is_phishy_combosquat(domain) || claimed_typosquat() ||
                (corroborated && unclaimed_typosquat());
      break;
    case CousinScope::MultiField:
      m.tier1 = brand_names::is_homoglyph_domain(domain) || brand_kb::is_idn_lookalike_kb(domain) ||
                claimed_typosquat() || (corroborated && unclaimed_typosquat());
      break;
  }
  return m;
}

// The href stem is a look-alike of brand X: a same-brand combosquat (the brand appears as a
// token OR as the de-hyphenated multi-word prefix, alongside an attacker keyword:
// apple-secure, secure-apple, deutsche-bank-verify), a homoglyph (app1e folds to apple), or
// a typosquat (one edit of X). Brand-aware, so it catches Tier-2 (dictionary) brands that
// is_phishy_combosquat / is_homoglyph_domain miss -- those need a DISTINCTIVE brand. A href
// UNRELATED to X (a click-tracker a legit newsletter wraps the brand's own social URL
// through, e.g. linkedin.com -> tracker) is NOT a look-alike, so it does not fire: that
// unrelated-href ambiguity is what refuted the bare displayed-URL mismatch (TASK-239,
// real-inbox 23->64/800). Brand X is identified from the anchor's VISIBLE text.
bool href_lookalikes_brand(const std::string& href_stem, const std::string& brand) {
  if (stem_has_phishy_keyword(href_stem)) {                          // combosquat
    if (any_stem_token(href_stem, [&](const std::string& t) { return t == brand; })) { return true;
}
    const std::string joined = dehyphenate(href_stem);              // multi-word brand prefix
    if (joined.size() > brand.size() && joined.compare(0, brand.size(), brand) == 0) { return true;
}
  }
  if (brand_names::confusable_fold(href_stem) == brand) { return true;  // homoglyph (app1e)
}
  if (brand.size() >= 5 && brand_kb::within_edit1(href_stem, brand)) { return true;  // typosquat
}
  return false;
}

// Anchor-text vs href impersonation (TASK-232 AC#6, doc-12). A body link whose VISIBLE text
// claims a KB brand X -- by showing X's domain (https://www.apple.com) or naming X in the
// impersonation shape ("Apple Security") -- while the href is a LOOK-ALIKE of X is a
// displayed-URL / displayed-brand spoof. Using the visible text to name X lets the href be
// checked against that specific brand, recovering the Tier-2 anchor spoofs is_link_lookalike
// (Tier-1 only) misses, while requiring an actual X look-alike keeps legit newsletters that
// link a brand's social URL through a tracker from firing (the per-brand KB plus the
// look-alike requirement is what TASK-239 lacked). A link to X's own domain self-exempts:
// display_impersonates_brand's owns_prefix (href as the ownership anchor), the same-name
// regional guard, and the auth-set membership test.
bool anchor_impersonates_brand(const AnchorPair& a, const std::string& from_org) {
  if (a.href_domain.empty() || a.href_domain == from_org) { return false;
}
  std::string brand;
  const std::string text_dom = registrable_domain_from_url(a.visible_text);
  if (!text_dom.empty()) {
    const std::string st = brand_names::domain_stem(text_dom);
    if (brand_kb::brand_has_auth_set(st)) {
      brand = st;
    } else {
      // Multi-word brand: the displayed domain is hyphenated (deutsche-bank.de) but the KB
      // key is the joined form (deutschebank). Retry the lookup on the de-hyphenated stem.
      const std::string joined = dehyphenate(st);
      if (joined != st && brand_kb::brand_has_auth_set(joined)) { brand = joined;
}
    }
  }
  if (brand.empty()) {
    // The ownership anchor is the SENDER (from_org), not the href: passing the malicious
    // href here would let owns_prefix self-exempt the spoof (apple is a prefix of the
    // look-alike apple-secure). A link to the brand's own domain is instead exempted by
    // the auth-set / same-name-regional guards below.
    const brand_names::BrandMatch tb =
        brand_names::display_impersonates_brand(a.visible_text, from_org);
    if (tb.tier2 && brand_kb::brand_has_auth_set(tb.brand)) { brand = tb.brand;
}
  }
  if (brand.empty()) { return false;
}
  const std::string hs = brand_names::domain_stem(a.href_domain);
  if (hs == brand || brand_kb::domain_in_brand_auth_set(brand, a.href_domain)) { return false;
}
  return href_lookalikes_brand(hs, brand);
}


// True when the (lowercased) DKIM signing FQDN has the throwaway shape:
// >= 2 labels below its org-domain, every one machine-generated.
bool is_throwaway_signer(const std::string& fqdn) {
  const std::vector<std::string> labels = split_labels(fqdn);
  if (labels.size() < 2) { return false;
}
  const size_t org_len = org_label_count(labels);
  if (labels.size() < org_len + 2) { return false;
}
  for (size_t i = 0; i + org_len < labels.size(); ++i) {
    if (!looks_generated(labels[i])) { return false;
}
  }
  return true;
}

// Read a domain token at offset v: a run of [alnum . - @], then return the part
// after the last '@' (DKIM header.i may be "local@domain" or "@domain";
// header.d is a bare domain). Empty if no token.
std::string read_domain_token(const std::string& s, size_t v) {
  size_t e = v;
  while (e < s.size() && (is_domain_char(s[e]) || s[e] == '@')) { ++e;
}
  std::string const tok = s.substr(v, e - v);
  const auto at = tok.rfind('@');
  return at == std::string::npos ? tok : tok.substr(at + 1);
}

// Within an Authentication-Results value, find the domain asserted by the first
// dkim=pass result. Prefer header.d= (the signing domain proper); fall back to
// header.i=. Bounded to the dkim method chunk (up to the next ';'). `ar` must
// already be ASCII-lowercased (the caller lowercases once and reuses it).
std::string dkim_pass_signing_domain(const std::string& ar) {
  size_t pos = 0;
  while ((pos = ar.find("dkim=pass", pos)) != std::string::npos) {
    size_t end = ar.find(';', pos);
    if (end == std::string::npos) { end = ar.size();
}
    for (const char* tag : {"header.d=", "header.i="}) {
      const size_t t = ar.find(tag, pos);
      if (t != std::string::npos && t < end) {
        const std::string dom = read_domain_token(ar, t + std::strlen(tag));
        if (!dom.empty()) { return dom;
}
      }
    }
    pos = end;
  }
  return "";
}

// First Reply-To mailbox, split into the identity parts the brand claim-gate reads
// (display + local part; a BEC reply-hijack sets the brand in the Reply-To display)
// and the org-domain the multi-field cousin check compares.
struct ReplyToMailbox {
  std::string display, local, org;
};
ReplyToMailbox reply_to_mailbox(GMimeMessage* message) {
  ReplyToMailbox r;
  InternetAddressList* list = g_mime_message_get_reply_to(message);
  if (list == nullptr || internet_address_list_length(list) == 0) { return r;
}
  InternetAddress* ia = internet_address_list_get_address(list, 0);
  if (ia == nullptr || !INTERNET_ADDRESS_IS_MAILBOX(ia)) { return r;
}
  const char* nm = internet_address_get_name(ia);
  if (nm != nullptr) { r.display = nm;
}
  const char* addr = internet_address_mailbox_get_addr(INTERNET_ADDRESS_MAILBOX(ia));
  if (addr == nullptr) { return r;
}
  const std::string a(addr);
  const auto at = a.rfind('@');
  if (at != std::string::npos) {
    r.local = a.substr(0, at);
    r.org = org_domain(a.substr(at + 1));
  }
  return r;
}

// Body-URL registrable domains from the message's in-memory MIME tree (no re-parse).
std::vector<std::string> body_url_domains_from_message(GMimeMessage* message) {
  std::vector<std::string> plain_parts;
  std::vector<std::string> html_parts;
  collect_body_parts(g_mime_message_get_mime_part(message), plain_parts, html_parts);
  std::string plain;
  std::string html;
  for (const std::string& p : plain_parts) { plain += p; plain.push_back('\n'); }
  for (const std::string& h : html_parts) { html += h; html.push_back('\n'); }
  return url_domains_from_bodies(plain, html);
}

// Core sender-auth extraction from an already-parsed message. Shared by the
// standalone extract_auth_features (which parses) and preprocess_rfc822 (which
// reuses its own parse). Does NOT unref the message: the caller owns it.
ExtractedAuthFeatures extract_auth_features_from_message(GMimeMessage* message) {
  ExtractedAuthFeatures out;

  if (message == nullptr) {
    return out;
  }

  // From org-domain (from the parsed mailbox address, not the display name).
  // Also capture the display name for the impersonation check below.
  std::string from_display_name;
  std::string from_local_part;
  std::string from_fqdn;  // full From host (subdomains kept) for the brand-in-subdomain scan
  InternetAddressList* from_list = g_mime_message_get_from(message);
  if (from_list != nullptr && internet_address_list_length(from_list) > 0) {
    InternetAddress* ia = internet_address_list_get_address(from_list, 0);
    if (ia != nullptr && INTERNET_ADDRESS_IS_MAILBOX(ia)) {
      const char* nm = internet_address_get_name(ia);
      if (nm != nullptr) { from_display_name = nm;
}
      const char* addr = internet_address_mailbox_get_addr(INTERNET_ADDRESS_MAILBOX(ia));
      if (addr != nullptr) {
        const std::string a(addr);
        const auto at = a.rfind('@');
        if (at != std::string::npos) {
          from_fqdn = to_lower_ascii(a.substr(at + 1));
          while (!from_fqdn.empty() && from_fqdn.back() == '.') { from_fqdn.pop_back();
}
          out.from_org_domain = org_domain(a.substr(at + 1));
          from_local_part = a.substr(0, at);
        }
      }
    }
  }
  // Topmost Authentication-Results only: g_mime_object_get_header returns the
  // first occurrence, which is the one the receiving MTA prepended (trusted).
  // dmarc_pass = the message passed DMARC (aligned via DKIM OR SPF). Distinct from
  // out.dmarc_aligned, which is the stricter DKIM-only alignment; the brand auth-set
  // exoneration uses dmarc_pass so legit brand mail aligned via SPF is not condemned.
  bool dmarc_pass = false;
  const char* ar = g_mime_object_get_header(GMIME_OBJECT(message), "Authentication-Results");
  const bool has_ar = ar != nullptr && ar[0] != '\0';
  if (has_ar) {
    // Lowercase the header value once and reuse it for both the DKIM-signer
    // scan and the DMARC check (method tokens are case-insensitive; the signing
    // domain is normalised by org_domain regardless).
    const std::string ar_lower = to_lower_ascii(ar);
    const std::string signer = dkim_pass_signing_domain(ar_lower);
    if (!signer.empty()) {
      out.dkim_signing_fqdn = signer;
      out.dkim_signing_domain = org_domain(signer);
      out.signer_throwaway = is_throwaway_signer(signer);
    }
    dmarc_pass = ar_lower.find("dmarc=pass") != std::string::npos;
    out.dmarc_pass = dmarc_pass;
    out.dmarc_aligned = dmarc_pass && !out.dkim_signing_domain.empty()
                        && out.dkim_signing_domain == out.from_org_domain;
  }
  // The three-state DMARC verdict that gates the brand-ownership exonerations below. Unknown (no AR
  // header) is deliberately NOT Fail; see brand_kb::DmarcVerdict for why this is a tri-state.
  const brand_kb::DmarcVerdict dmarc =
      !has_ar ? brand_kb::DmarcVerdict::Unknown
              : (dmarc_pass ? brand_kb::DmarcVerdict::Pass : brand_kb::DmarcVerdict::Fail);

  // Display-name brand impersonation (TASK-214, doc-12). Computed after auth so a
  // Tier-2 (dictionary-word) brand can be gated on corroboration. Tier-1
  // (distinctive) condemns standalone; Tier-2 requires the impersonation shape
  // (in the match) AND an independent hard spam signal (a throwaway or free-host
  // DKIM signer), so the common-word FP class (Orange County, Apple Valley) can't
  // fire on legit aligned mail.
  // A brand claimed in the display name, or (doc-13 technique #5) in the address
  // local part ("paypal-support@evil.com") with no brand in the display. Both reuse
  // the same shape + ownership precision. Skip the local part once the display
  // already condemns standalone (tier1).
  const brand_names::BrandMatch bm =
      brand_names::display_impersonates_brand(from_display_name, out.from_org_domain);
  const brand_names::BrandMatch lp =
      bm.tier1 ? brand_names::BrandMatch{}
               : brand_names::display_impersonates_brand(from_local_part, out.from_org_domain);
  // Multi-word brand written as separate tokens ("La Poste", "Deutsche Bank") in the
  // display name or a dotted/hyphenated local part, which the single-token matcher
  // can't see. Curated KB + Tranco-distinctive, same ownership exemption (TASK-214).
  const brand_names::BrandMatch jn =
      brand_kb::display_join_impersonates(from_display_name, out.from_org_domain) |
      brand_kb::display_join_impersonates(from_local_part, out.from_org_domain);
  // Brand tokens the sender's presented IDENTITY claims: From display + local part and
  // Reply-To display + local part (a BEC reply-hijack sets the brand there). Single
  // folded tokens plus adjacent 2-3-token joins, mirroring display_join_impersonates,
  // so a multi-word claim ("Wells Fargo", "La Poste") matches its joined SLD form.
  // Identity fields ONLY, not subject/body prose: content mentioning brand X next to a
  // one-edit-of-X link is a legit-newsletter shape (an article on La Poste linking
  // lacoste.com must not fire).
  const ReplyToMailbox reply_to = reply_to_mailbox(message);
  std::set<std::string> claimed;
  auto const claim_tokens = [&](const std::string& src) {
    if (src.empty()) { return;
}
    const std::vector<brand_names::DisplayToken> toks = brand_names::tokenize_display(src);
    for (std::size_t i = 0; i < toks.size(); ++i) {
      claimed.insert(toks[i].plain);
      if (toks[i].perturbed) { claimed.insert(toks[i].conf);
}
      std::string join = toks[i].plain;
      for (std::size_t j = i + 1; j < toks.size() && j < i + 3; ++j) {
        join += toks[j].plain;
        claimed.insert(join);
      }
    }
  };
  claim_tokens(from_display_name);
  claim_tokens(from_local_part);
  claim_tokens(reply_to.display);
  claim_tokens(reply_to.local);
  // The distinctive KB brands among those claims (direct, or via the hyphen-stripped
  // form: a "Credit Agricole" display joins to "creditagricole", the KB SLD is
  // "credit-agricole"). Computed once so the per-domain typosquat claim-gate scans a
  // tiny, usually empty, list instead of the whole KB per link.
  std::vector<std::string> claimed_brands;
  if (!claimed.empty()) {
    for (const std::string& b : brand_kb::distinctive_slds()) {
      if (claimed.count(b) ||
          (b.find('-') != std::string::npos && claimed.count(dehyphenate(b)))) {
        claimed_brands.push_back(b);
      }
    }
  }
  // Tier-2 brands / ambiguous cousins need a corroborating hard signal (throwaway /
  // free-host DKIM signer). Computed before the cousin scans: the secondary scopes use
  // it to license the unclaimed-typosquat KB scan.
  const bool corroborated =
      out.signer_throwaway || decision::is_free_host_signed(out.dkim_signing_domain);
  // Cousin / look-alike SENDING domain, folded into the same tier policy as a display claim so the
  // verdict has one form: Tier-1 (morph/combosquat) condemns standalone, Tier-2 (tld-swap /
  // unclaimed typosquat) needs corroboration. The per-scope policy lives in brand_cousin.
  brand_names::BrandMatch cousin =
      brand_cousin(out.from_org_domain, CousinScope::Sender, claimed_brands, corroborated);
  // Reply-To pointing at a brand look-alike (BEC reply-hijack, TASK-237 AC#2): a cloned-template
  // phish often has a clean From but a brand-cousin Reply-To. MultiField scope = the strict morph
  // subset (a legit differing Reply-To -- an ESP, a personal webmail -- is not a morph).
  const std::string reply_to_org = reply_to.org;
  if (!cousin.tier1 && !reply_to_org.empty() && reply_to_org != out.from_org_domain &&
      brand_cousin(reply_to_org, CousinScope::MultiField, claimed_brands, corroborated).tier1) {
    cousin.tier1 = true;
  }
  // A brand look-alike link in the body (clean From, cloned-template phish). The text
  // scan sees only URLs that appear as visible text; the anchor parse additionally
  // recovers links that live ONLY in <a href=...> (html_to_text strips the attribute
  // before the URL scan), so HTML cloned-template phish with a clean visible text but a
  // look-alike href is caught (TASK-239 AC#1/#2). A link is a look-alike when it is a
  // strict cousin (homoglyph / typosquat / IDN) OR a PHISHY combosquat (brand + an
  // attacker keyword: paypal-secure, paypal-verify). Combosquat is admitted here ONLY
  // with the phishy keyword, so a legit brand-ESP domain (paypal-email.com, brand-mail)
  // does NOT fire -- that, not a bare combosquat, is what a real-inbox scan flagged.
  // The displayed-URL-text / displayed-brand vs unrelated-href mismatch (the case that
  // needed the per-brand KB to tell a phish from a legit multi-domain sender) is now
  // anchor_impersonates_brand below (TASK-232 AC#6).
  auto const is_link_lookalike = [&](const std::string& d) {
    return brand_cousin(d, CousinScope::Link, claimed_brands, corroborated).tier1;
  };
  const std::vector<AnchorPair> anchors = anchors_from_message(message);
  if (!cousin.tier1) {
    for (const std::string& d : body_url_domains_from_message(message)) {
      if (d != out.from_org_domain && is_link_lookalike(d)) { cousin.tier1 = true; break; }
    }
  }
  if (!cousin.tier1) {
    for (const AnchorPair& a : anchors) {
      const bool href_lookalike = !a.href_domain.empty() &&
          a.href_domain != out.from_org_domain && is_link_lookalike(a.href_domain);
      if (href_lookalike || anchor_impersonates_brand(a, out.from_org_domain)) {
        cousin.tier1 = true;
        break;
      }
    }
  }
  // Credential-harvest form (TASK-239 AC#3): an HTML <form> with a password input posting
  // to an off-domain, UNRECOGNIZED action host. A legit login form posts to the sender's
  // own org or a known/established auth domain; a phish posts to a throwaway/cousin. A
  // password field in mail is itself rare, so this is high-precision.
  if (!cousin.tier1) {
    for (const std::string& d : credential_form_actions_from_message(message)) {
      if (d.empty() || d == out.from_org_domain) { continue;
}
      if (brand_kb::is_canonical_domain(d) || brand_reputation::is_established_brand(d) ||
          decision::is_shared_sender_platform(d)) { continue;
}
      cousin.tier1 = true;
      break;
    }
  }
  // Image-only / logo-spoof body (TASK-239 AC#4): a body with near-zero visible text
  // dominated by an anchored <img> linking off-domain to an UNRECOGNIZED host. A legit
  // image newsletter carries real text and/or links to established/canonical/own domains;
  // a logo-spoof phish is a bare clickable image to a throwaway. Measured FP-neutral on a
  // real-inbox scan (the text floor + established-href exemption clear the newsletter class).
  if (!cousin.tier1) {
    const std::string d = image_only_offdomain_link(message, out.from_org_domain);
    if (!d.empty() && !brand_kb::is_canonical_domain(d) &&
        !brand_reputation::is_established_brand(d) &&
        !decision::is_shared_sender_platform(d)) {
      cousin.tier1 = true;
    }
  }
  // Brand-in-subdomain / subdomain-deception (TASK-242): the dominant real-phish pattern
  // doc-14 measured, which org-domain reduction misses. A distinctive brand sits in the
  // SUBDOMAIN of a host the brand does not own (11paypal.duckdns.org), or a canonical brand
  // domain appears as a non-registrable label (accounts.google.com.medbp.com). Scanned over
  // the From FQDN and every body link host (full, subdomains kept).
  if (!cousin.tier1 && host_impersonates_brand(from_fqdn)) { cousin.tier1 = true;
}
  if (!cousin.tier1) {
    for (const std::string& h : link_hosts_from_message(message)) {
      if (host_impersonates_brand(h)) { cousin.tier1 = true; break; }
    }
  }
  // Reply-To / Return-Path divergence (TASK-237 AC#1): a Reply-To pointing to a free-
  // webmail / disposable host redirects replies to an inbox outside the claimed domain
  // (BEC reply-hijack). It is too weak alone -- a personal-webmail Reply-To is common on
  // legit small-business mail -- so it corroborates ONLY the tld-swap cousin (a distinctive
  // brand SLD on a non-canonical TLD, e.g. paypal.co; never a surname). It deliberately
  // does NOT corroborate a display / local-part Tier-2: common surnames are Tier-2 stems
  // ('Bob Smith' + a gmail Reply-To must stay clean, the FP that reverted the first attempt).
  const bool reply_hijack =
      !reply_to_org.empty() && reply_to_org != out.from_org_domain &&
      (decision::is_shared_sender_platform(reply_to_org) ||
       decision::is_free_host_signed(reply_to_org));
  const bool display_tier2 = bm.tier2 || lp.tier2 || jn.tier2;
  // Claimed-vs-authenticated mismatch (TASK-232 AC#2/AC#4, doc-12 north star). For a brand
  // whose authenticated sending domains the KB knows -- EITHER tier -- the verdict is identity
  // consistency: a display/local-part that CLAIMS brand X from a domain NOT in X's authenticated
  // set is impersonation. This is the PRIMARY, durable signal for known brands -- the doc-12
  // "feature": it fires on clean aligned infrastructure with no throwaway/free-host corroborator
  // (the phish a string match misses), and for a KB brand it SUPERSEDES the bare string match --
  // a known brand is condemned only when authenticated_as_brand says the sender is not the brand
  // (in its auth set and not DMARC-failed; see that helper for the forgeable-From / no-AR rules).
  // Place names never reach here: a place/distinctive leftover ("Orange County") breaks the Tier-2
  // SHAPE upstream, so there is no claim. A same-name regional domain the KB has not enumerated
  // (orange.sk for "Orange", stem==brand) is excluded as ambiguous and stays on the corroboration-
  // gated tld-swap path rather than false-positiving as a mismatch.
  // A shared sender platform in the From org-domain does not authenticate as ANY brand (anyone can
  // send from it), so it cannot exempt a brand claim even when it is in the brand's auth/canonical
  // set (TASK-246). Computed once for all three exemptions below.
  const bool from_shared = decision::is_shared_sender_platform(out.from_org_domain);
  auto const kb_claim_mismatch = [&](const brand_names::BrandMatch& dm) {
    return (dm.tier1 || dm.tier2) && brand_kb::brand_has_auth_set(dm.brand) &&
           !brand_kb::authenticated_as_brand(dm.brand, out.from_org_domain, dmarc, from_shared) &&
           brand_names::domain_stem(out.from_org_domain) != dm.brand;
  };
  const bool kb_mismatch = kb_claim_mismatch(bm) || kb_claim_mismatch(lp);
  // The multi-word join is always a curated-KB brand claim (display_join matches the KB set only),
  // so it routes through the SAME claimed-vs-authenticated gate as bm/lp rather than condemning
  // standalone: a brand whose auth set the KB keys uses authenticated_as_brand; a join form the KB
  // does not key its own auth pairs for (e.g. Free Mobile -> freemobile) falls back to the canonical
  // set. The structural owns-prefix case was already exempted inside display_join (so jn.tier1 here
  // is a genuine non-owned claim), which is why no stem!=brand guard is needed.
  const bool jn_mismatch = jn.tier1 &&
      !(brand_kb::brand_has_auth_set(jn.brand)
            ? brand_kb::authenticated_as_brand(jn.brand, out.from_org_domain, dmarc, from_shared)
            : brand_kb::authenticated_canonical(out.from_org_domain, dmarc, from_shared));
  // Standalone string-condemn (the Tranco distinctive-coined list), demoted to a COLD-START
  // crutch (doc-12 long-term, AC#4): the single-token name match condemns on the name alone ONLY
  // for a distinctive brand the KB cannot adjudicate (no authenticated set). Once a brand enters
  // the KB, the claimed-vs-authenticated mismatch above is the sole condemn path for it -- the
  // string match no longer speaks. This is the day-0 fallback for the long tail, not the durable
  // core. (The multi-word join and cousin/look-alike paths are KB-gated or structural, not this
  // string list, so they keep their standalone condemn below.)
  auto const coldstart_condemns = [&](const brand_names::BrandMatch& dm) {
    return dm.tier1 && !brand_kb::brand_has_auth_set(dm.brand);
  };
  const bool coldstart_condemn = coldstart_condemns(bm) || coldstart_condemns(lp);
  // A KB identity mismatch of EITHER tier (fires on the mismatch alone -- the clean-infra phish a
  // corroboration-only gate misses), OR any Tier-2 claim on the old corroboration gate. Named for
  // the union, not tier-2 alone, so the Tier-1 KB path here is not overlooked.
  const bool kb_or_corroborated_fires = kb_mismatch || (display_tier2 && corroborated);
  // Exempt a DMARC-aligned sender that IS the brand on a domain it owns: a curated canonical brand
  // domain (covers mid-tier brands the top-10k misses) or a broad-established domain. A SHARED sender
  // platform never qualifies (from_shared) -- aligning to gmail/icloud/outlook/substack is not owning
  // a brand, even when the domain is in the brand's canonical set (TASK-246); also exclude free-host
  // signers from the established clause. A cousin/throwaway domain is not established, so phish fires.
  const bool reputable_aligned =
      out.dmarc_aligned && !from_shared &&
      (brand_kb::is_canonical_domain(out.from_org_domain) ||
       (brand_reputation::is_established_brand(out.from_org_domain) &&
        !decision::is_free_host_signed(out.from_org_domain)));
  out.display_impersonation =
      !reputable_aligned &&
      (coldstart_condemn ||                  // non-KB distinctive coined: day-0 string crutch
       kb_or_corroborated_fires ||           // KB identity mismatch (both tiers) OR dict-brand + corroboration
       jn_mismatch ||                        // multi-word KB-brand claim, claimed-vs-authenticated gated
       cousin.tier1 ||                       // structural look-alike (homoglyph/typosquat/combosquat/host)
       (cousin.tier2 && (corroborated || reply_hijack)));

  // Authenticated KB-brand credential (TASK-337/334): the receiving MTA verified
  // that a From org-domain the curated KB knows as a brand's own sending domain
  // is authenticated, and that domain is not a shared platform anyone can send
  // from. Authentication qualifies via EITHER an explicit dmarc=pass OR an
  // aligned DKIM pass (a verified DKIM signature whose signing org-domain equals
  // the From org-domain). The two are equivalent in what they certify: only the
  // domain owner can produce either, so a spoofer of a KB brand can produce
  // neither. Aligned DKIM must be accepted on its own because major providers
  // (notably Outlook/Hotmail) stamp `dkim=pass header.d=<brand>` with NO dmarc=
  // token, so demanding the literal token drops legit brand mail (badoo, ~22 of
  // the transactional panel FPs). Unknown/unauthenticated still does NOT qualify
  // -- this gates a strong ham rescue, not a condemn -- so AR-less trap corpora
  // are untouched. Threat model note: this trusts the topmost AR like every auth
  // signal here, but a forged AR now buys DELIVERY (-0.90), not just an
  // un-condemn. Acceptable because the majors (Gmail/Outlook/iCloud -- our Apple
  // Mail base) strip unauthorized ARs on ingress (RFC 8601 s1.6); revisit if we
  // ever classify for receivers that do not sanitize.
  const bool dkim_aligned_pass = !out.dkim_signing_domain.empty()
                                 && out.dkim_signing_domain == out.from_org_domain;
  out.kb_brand_dmarc_pass =
      (dmarc_pass || dkim_aligned_pass) && !from_shared &&
      (brand_kb::is_canonical_domain(out.from_org_domain) ||
       brand_kb::is_auth_set_domain(out.from_org_domain));

  return out;
}

// --- Structural markers (successor-model input enrichment, TASK-283/344) -----
// Byte-parity port of model-lab/scripts/enrich_structural.py
// signals()+render(..., "markers"): a BOUNDED plain-text summary the successor
// encoder (markers + P0.25 dropout) was trained on, so it sees image-heaviness /
// image-only payloads / link domains that html_to_text() strips, without any
// tokenizer vocab change. Parity is pinned by the marker tests (engine +
// model-lab/test_marker_parity.py) — keep the two in lockstep.

// Count "<img" followed by a tag-name boundary (mirrors Python rb"<img\b").
int count_img_tags(const std::string& html) {
  const std::string lower = to_lower_ascii(html);
  int n = 0;
  size_t pos = 0;
  while ((pos = lower.find("<img", pos)) != std::string::npos) {
    const size_t after = pos + 4;
    const char c = after < lower.size() ? lower[after] : '\0';
    // \b: the char after "img" must not continue the word (letter/digit/_).
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') { ++n;
}
    pos = after;
  }
  return n;
}

// Registrable eTLD+1 domains of every href="http(s)://…" in document order,
// deduped, capped. Mirrors Python _HREF_RE + _HOST_RE + org_domain: an href in
// ANY tag (not just <a>) whose value begins with an http(s) scheme.
std::vector<std::string> marker_link_domains(const std::string& html, size_t cap) {
  const std::string lower = to_lower_ascii(html);
  std::vector<std::string> out;
  std::set<std::string> seen;
  size_t pos = 0;
  while (out.size() < cap) {
    const size_t at = lower.find("href", pos);
    if (at == std::string::npos) { break;
}
    size_t i = at + 4;
    while (i < lower.size() && is_html_space(lower[i])) { ++i;
}
    if (i >= lower.size() || lower[i] != '=') { pos = at + 4; continue; }
    ++i;
    while (i < lower.size() && is_html_space(lower[i])) { ++i;
}
    if (i < lower.size() && (lower[i] == '"' || lower[i] == '\'')) { ++i;  // optional quote
}
    size_t scheme = 0;
    if (lower.compare(i, 7, "http://") == 0) { { scheme = i + 7;
    } } else if (lower.compare(i, 8, "https://") == 0) { { scheme = i + 8;
    } } else { pos = at + 4; continue; }
    // Host runs to the first of /:?# (Python _HOST_RE [^/:?#]+) or a URL-ending
    // quote/space/'>' (Python captured the URL as [^"'>\s]+ first).
    size_t end = scheme;
    while (end < lower.size()) {
      const char c = lower[end];
      if (c == '/' || c == ':' || c == '?' || c == '#' ||
          c == '"' || c == '\'' || c == '>' ||
          std::isspace(static_cast<unsigned char>(c))) { break;
}
      ++end;
    }
    const std::string d = org_domain(lower.substr(scheme, end - scheme));
    if (!d.empty() && seen.insert(d).second) { out.push_back(d);
}
    pos = end;
  }
  return out;
}

}  // namespace

std::string structural_marker_prefix(const std::string& raw_html,
                                     const std::string& base_for_imgonly) {
  if (raw_html.empty()) { return "";  // no HTML part -> no-op (plain-mail parity)
}
  const int n_img = count_img_tags(raw_html);
  const std::vector<std::string> domains = marker_link_domains(raw_html, 8);

  std::vector<std::string> parts;
  if (n_img > 0) {
    parts.push_back("images " + std::to_string(n_img));
    if (trim(base_for_imgonly).size() < 40) { parts.emplace_back("image only");
}
  }
  if (!domains.empty()) {
    std::string links;
    for (size_t i = 0; i < domains.size(); ++i) {
      if (i) { links += ' ';
}
      links += "link " + domains[i];
    }
    parts.push_back(std::move(links));
  }
  std::string prefix;
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i) { prefix += ' ';
}
    prefix += parts[i];
  }
  return prefix;  // "" when no signal — caller then leaves the base untouched
}

std::vector<std::string> anchor_href_domains(const std::string& html) {
  std::vector<std::string> out;
  for (const AnchorPair& a : anchors_from_html(html)) {
    out.push_back(a.href_domain);
  }
  return out;
}

std::vector<std::string> credential_form_action_domains(const std::string& html) {
  return credential_form_actions(html);
}

ExtractedAuthFeatures extract_auth_features(const std::string& raw_rfc822) {
  GMimeMessage* message = parse_rfc822_message(raw_rfc822);
  ExtractedAuthFeatures out = extract_auth_features_from_message(message);
  if (message != nullptr) {
    g_object_unref(message);
  }
  return out;
}

bool host_is_ip_literal(const std::string& host) {
  if (host.empty()) { return false;
}
  // IPv6 literal, delegated to the strict RFC-4291 parser (TASK-389). The old
  // rule here was "only hex digits and ':', >= 2 colons", which accepted
  // non-addresses like "::::" and "1:2:3" — every false accept is a spam-ward
  // push (kUrlRawIp) on a host that was never an IP literal, the opposite of the
  // precision-first bar that offset was justified against. parse_ipv6 handles
  // brackets and %zone itself; the shared host_from_url port-strip still mangles
  // bracketed forms upstream, so this mainly serves the direct/unit path.
  if (host.find(':') != std::string::npos) {
    uint64_t hi = 0;
    uint64_t lo = 0;
    return IpBlocklist::parse_ipv6(host, &hi, &lo);
  }
  // IPv4 dotted quad: exactly four 1-3 digit octets, each 0-255. A non-digit
  // label (example.com, 192.example.com) fails on the first non-digit octet.
  //
  // DELIBERATELY NOT IpBlocklist::parse_ipv4, which rejects leading-zero octets:
  // there, the input is an address an MTA observed, and "010.0.0.1" read as octal
  // would name a different host than the one checked. Here the input is a link a
  // spammer wrote, and octal-obfuscated IPs are themselves the tell we want to
  // catch. Same syntax, opposite correct answer — keep the two grammars apart.
  int octets = 0;
  size_t i = 0;
  while (true) {
    int val = 0;
    int digits = 0;
    while (i < host.size() && std::isdigit(static_cast<unsigned char>(host[i])) != 0) {
      val = (val * 10) + (host[i] - '0');
      if (val > 255) { return false;
}
      ++digits;
      ++i;
    }
    if (digits == 0 || digits > 3) { return false;
}
    ++octets;
    if (i == host.size()) { break;
}
    if (host[i] != '.') { return false;   // a non-dot separator => not an IPv4
}
    ++i;
    if (i == host.size()) { return false;  // trailing dot => malformed
}
  }
  return octets == 4;
}

bool contains_gtube(const std::string& text) {
  // Stored as two halves so this source file does not itself contain the string:
  // a scanner reading our own repository (or a fixture harvested from it) must
  // not trip. Joined once per process, not per call — it is checked against the
  // subject and every body part of every message.
  static const std::string kNeedle = std::string("XJS*C4JDBQADN1.NSBN3*2IDNEN*") +
                                     "GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X";
  return text.find(kNeedle) != std::string::npos;
}

ExtractedBodyFeatures extract_body_features(const std::string& raw_rfc822) {
  GMimeMessage* message = parse_rfc822_message(raw_rfc822);
  ExtractedBodyFeatures out = extract_body_features_from_message(message);
  if (message != nullptr) {
    g_object_unref(message);
  }
  return out;
}

ExtractedAttachmentFeatures extract_attachment_features(
    const std::string& raw_rfc822) {
  ensure_gmime_initialized();
  GMimeStream* stream = g_mime_stream_mem_new_with_buffer(
      raw_rfc822.data(), raw_rfc822.size());
  if (stream == nullptr) { throw std::runtime_error("Failed to create GMime stream");
}
  GMimeParser* parser = g_mime_parser_new_with_stream(stream);
  g_object_unref(stream);
  if (parser == nullptr) { throw std::runtime_error("Failed to create GMime parser");
}
  GMimeMessage* message = g_mime_parser_construct_message(parser, nullptr);
  g_object_unref(parser);
  if (message == nullptr) { throw std::runtime_error("Failed to parse RFC822 message");
}
  GObjectPtr<GMimeMessage> const guard(message);
  std::vector<AttachmentInput> attachments;
  int attachment_count = 0;
  std::size_t attachment_bytes_remaining = kAttachmentDecodedTotalMaxBytes;
  bool attachment_collection_truncated = false;
  int attachment_parts_visited = 0;
  collect_attachment_inputs(
      g_mime_message_get_mime_part(message), attachments,
      attachment_count, attachment_bytes_remaining,
      attachment_collection_truncated, attachment_parts_visited);
  return analyze_attachments(
      attachments, attachment_count, attachment_collection_truncated);
}

ExtractedUrlFeatures extract_url_features(const std::string& raw_rfc822) {
  GMimeMessage* message = parse_rfc822_message(raw_rfc822);
  ExtractedUrlFeatures out = extract_url_features_from_message(message);
  if (message != nullptr) {
    g_object_unref(message);
  }
  return out;
}

std::vector<std::string> url_domains_from_bodies(const std::string& plain_body,
                                                 const std::string& html_body) {
  std::set<std::string> domains;
  const std::string* parts[] = {&plain_body, &html_body};
  for (const std::string* part : parts) {
    const std::string& s = *part;
    // to_lower_ascii preserves length, so offsets into `lower` index `s` too.
    const std::string lower = to_lower_ascii(s);
    size_t pos = 0;
    while (true) {
      const size_t at_http = lower.find("http", pos);
      if (at_http == std::string::npos) { break;
}
      size_t scheme_end = std::string::npos;
      if (lower.compare(at_http, 7, "http://") == 0) { scheme_end = at_http + 7;
      } else if (lower.compare(at_http, 8, "https://") == 0) { scheme_end = at_http + 8;
}
      if (scheme_end == std::string::npos) { pos = at_http + 4; continue; }
      // Authority runs to the first path/query/fragment or quote/space/bracket.
      size_t end = scheme_end;
      while (end < s.size()) {
        const char c = s[end];
        if (c == '/' || c == '?' || c == '#' || c == '"' || c == '\'' ||
            c == '<' || c == '>' || c == ')' || c == ']' || c == ',' ||
            std::isspace(static_cast<unsigned char>(c))) { break;
}
        end++;
      }
      const std::string authority = s.substr(scheme_end, end - scheme_end);
      pos = end;
      const std::string od = registrable_domain_from_authority(authority);
      if (!od.empty()) { domains.insert(od);
}
    }
  }
  return {domains.begin(), domains.end()};
}

std::vector<std::string> extract_url_domains(const std::string& raw_rfc822) {
  const ExtractedEmailBody body = extract_email_body(raw_rfc822);
  return url_domains_from_bodies(body.plain_body, body.html_body);
}

}  // namespace spam_engine
