#include "email_preprocessor.h"

#include "brand_kb.h"  // curated canonical-domain exemption + cousin detection (TASK-232)
#include "brand_names.h"
#include "brand_reputation.h"  // is_established_brand (auth-reputation exemption, doc-12)
#include "decision_layer.h"  // is_free_host_signed (Tier-2 corroboration, doc-12)

#include <algorithm>
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

void ensure_gmime_initialized() {
  static std::once_flag once;
  std::call_once(once, []() { g_mime_init(); });
}

// RAII for a GMime GObject: unref on scope exit so a throw between construct and
// the manual unref (decode_header_text, extract_*, collect_body_parts all throw)
// no longer leaks the parsed message (TASK-251).
struct GObjectDeleter {
  void operator()(void* p) const { if (p != nullptr) g_object_unref(p); }
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
  return std::string(start, end);
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
    const unsigned char c = static_cast<unsigned char>(s[i]);
    std::uint32_t cp = c;
    std::size_t len = 1;
    if (c >= 0xF0 && i + 3 < n) {
      cp = (c & 0x07u) << 18 | (s[i + 1] & 0x3Fu) << 12 | (s[i + 2] & 0x3Fu) << 6 | (s[i + 3] & 0x3Fu);
      len = 4;
    } else if (c >= 0xE0 && i + 2 < n) {
      cp = (c & 0x0Fu) << 12 | (s[i + 1] & 0x3Fu) << 6 | (s[i + 2] & 0x3Fu);
      len = 3;
    } else if (c >= 0xC0 && i + 1 < n) {
      cp = (c & 0x1Fu) << 6 | (s[i + 1] & 0x3Fu);
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
  // Strip zero-width / invisible format chars from EVERY field, not just the body
  // (TASK-167 gap): a "PayP<U+200B>al" in the Subject or From display evades the
  // token the classifier keys on exactly as it would in the body.
  std::string normalized;
  const std::string clean_subject = strip_invisible_chars(subject);
  if (!clean_subject.empty()) {
    normalized += "subject: " + clean_subject + "\n";
  }
  const std::string clean_from = strip_invisible_chars(from);
  if (!clean_from.empty()) {
    normalized += "from: " + clean_from + "\n";
  }
  const std::string clean_body = strip_invisible_chars(body_text);
  if (!normalized.empty() && !clean_body.empty()) {
    normalized += "\n";
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

std::string collapse_whitespace(const std::string& input) {
  std::string output;
  output.reserve(input.size());

  bool in_space = false;
  bool last_was_newline = false;
  for (unsigned char uc : input) {
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

  for (std::size_t i = 0; i < html.size(); ++i) {
    char c = html[i];

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
        for (char tc : tag_name) {
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

  replace_all(text, "&nbsp;", " ");
  replace_all(text, "&amp;", "&");
  replace_all(text, "&lt;", "<");
  replace_all(text, "&gt;", ">");
  replace_all(text, "&quot;", "\"");
  replace_all(text, "&#39;", "'");
  replace_all(text, "&apos;", "'");

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

  std::string out(decoded);
  g_free(decoded);
  return collapse_whitespace(out);
}

// Lower-case a string in place (ASCII).
std::string to_lower_ascii(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

// Add `raw` (trimmed, lower-cased) to `out` if it's at least `min_len` chars.
void add_recipient_token(std::set<std::string>& out, const std::string& raw, size_t min_len) {
  const std::string t = to_lower_ascii(trim(raw));
  if (t.size() >= min_len) out.insert(t);
}

// Mine one address + display name into recipient identifier tokens: the full
// address, its local-part, the full display name, and each name word.
void add_address_tokens(std::set<std::string>& out, const char* email, const char* name) {
  if (email != nullptr && email[0] != '\0') {
    const std::string addr = email;
    add_recipient_token(out, addr, 5);                 // full address
    const size_t at = addr.find('@');
    if (at != std::string::npos) add_recipient_token(out, addr.substr(0, at), 4);  // local-part
  }
  if (name != nullptr && name[0] != '\0') {
    const std::string nm = decode_header_text(name);
    add_recipient_token(out, nm, 4);                   // full display name
    size_t i = 0;
    while (i < nm.size()) {                            // each word
      while (i < nm.size() && std::isspace(static_cast<unsigned char>(nm[i]))) i++;
      size_t j = i;
      while (j < nm.size() && !std::isspace(static_cast<unsigned char>(nm[j]))) j++;
      if (j > i) add_recipient_token(out, nm.substr(i, j - i), 4);
      i = j;
    }
  }
}

// Walk an InternetAddressList (recursing into groups) collecting recipient tokens.
// Walk an address list (recursing into groups) and invoke `on_mailbox` for each
// leaf mailbox. The shared skeleton for the two collectors below.
template <typename Fn>
void walk_mailboxes(InternetAddressList* list, Fn&& on_mailbox) {
  if (list == nullptr) return;
  const int n = internet_address_list_length(list);
  for (int i = 0; i < n; i++) {
    InternetAddress* addr = internet_address_list_get_address(list, i);
    if (addr == nullptr) continue;
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

std::string decode_part_content(GMimePart* part, GMimeContentType* content_type) {
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
    GByteArray* bytes = g_mime_stream_mem_get_byte_array(GMIME_STREAM_MEM(stream));
    if (bytes != nullptr && bytes->data != nullptr && bytes->len > 0) {
      decoded.assign(
          reinterpret_cast<const char*>(bytes->data),
          static_cast<std::size_t>(bytes->len));
    }
  }

  g_object_unref(stream);

  const char* charset = content_type == nullptr
      ? nullptr
      : g_mime_content_type_get_parameter(content_type, "charset");
  return decode_to_utf8(decoded, charset);
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

PreprocessedEmail preprocess_rfc822(const std::string& raw_rfc822) {
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
      if (v != nullptr) add_address_tokens(rcpt, v, nullptr);
    }
    out.recipient_tokens.assign(rcpt.begin(), rcpt.end());
  }

  std::vector<std::string> plain_parts;
  std::vector<std::string> html_parts;
  collect_body_parts(g_mime_message_get_mime_part(message), plain_parts, html_parts);
  message_guard.reset();

  out.plain_body_text = join_with_blank_lines(plain_parts);
  out.html_body_text = join_with_blank_lines(html_parts);
  out.normalized_plain_text = build_normalized_text(out.subject, out.from, out.plain_body_text);
  out.normalized_html_text = build_normalized_text(out.subject, out.from, out.html_body_text);

  out.body_text = !out.plain_body_text.empty() ? out.plain_body_text : out.html_body_text;
  out.normalized_text = build_normalized_text(out.subject, out.from, out.body_text);

  if (out.normalized_text.empty()) {
    throw std::runtime_error("No extractable text/plain or text/html content in RFC822 message");
  }

  return out;
}

namespace {

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
          plain_out = decode_part_content(GMIME_PART(part), part_ct);
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
    plain_out = decoded;
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
  auto not_ws = [](unsigned char c) {
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

}  // namespace

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

std::string ascii_lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

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
  while (i < label.size() && std::isalpha(static_cast<unsigned char>(label[i]))) ++i;
  if (i < 2 || i == label.size()) return false;
  size_t d = i;
  while (d < label.size() && std::isdigit(static_cast<unsigned char>(label[d]))) ++d;
  if (d == i) return false;
  if (d == label.size()) return true;
  if (label[d] != '-') return false;
  size_t e = d + 1;
  while (e < label.size() && std::isdigit(static_cast<unsigned char>(label[e]))) ++e;
  return e > d + 1 && e == label.size();
}

// Pure 8-digit labels are key-rotation date stamps, not throwaway randomness:
// Google Workspace signs custom domains as <name>-<tld>.<yyyymmdd>.gappssmtp.com,
// and a digit-bearing customer name (42-fr, beer52-com) would otherwise make
// every label read "generated" — measured 7 real ham FPs in 75,635 (TASK-178
// OOD scan); zero spam in any corpus uses a date label.
bool is_date_stamp(const std::string& label) {
  if (label.size() != 8) return false;
  for (char c : label) {
    if (!std::isdigit(static_cast<unsigned char>(c))) return false;
  }
  return true;
}

// Machine-generated host label: not a recognizable mail-infra word, not
// fleet-numbering, not a date stamp, and short (<= 4), digit-bearing, or
// vowel-free (jjlw / how / f9l / mim / 1qb / okk).
bool looks_generated(const std::string& label) {
  if (is_common_sub_label(label) || is_fleet_numbered(label) || is_date_stamp(label)) return false;
  if (label.size() <= 4) return true;
  bool has_digit = false;
  bool has_vowel = false;
  for (char c : label) {
    if (std::isdigit(static_cast<unsigned char>(c))) has_digit = true;
    if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u' || c == 'y') has_vowel = true;
  }
  return has_digit || !has_vowel;
}

std::vector<std::string> split_labels(const std::string& host) {
  std::vector<std::string> labels;
  std::string cur;
  for (char c : host) {
    if (c == '.') {
      if (!cur.empty()) labels.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  if (!cur.empty()) labels.push_back(cur);
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
  const std::vector<std::string> labels = split_labels(ascii_lower(host));
  if (labels.empty()) return "";
  if (labels.size() == 1) return labels[0];
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
  if (at != std::string::npos) authority = authority.substr(at + 1);
  const size_t colon = authority.find(':');
  if (colon != std::string::npos) authority = authority.substr(0, colon);
  while (!authority.empty() && authority.back() == '.') authority.pop_back();
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
  while (b < url.size() && std::isspace(static_cast<unsigned char>(url[b]))) ++b;
  const std::string lower = ascii_lower(url.substr(b));
  size_t start;
  if (lower.rfind("http://", 0) == 0) start = 7;
  else if (lower.rfind("https://", 0) == 0) start = 8;
  else if (lower.rfind("//", 0) == 0) start = 2;        // protocol-relative
  else return "";                                        // mailto:/tel:/#/relative/bare
  size_t end = start;
  while (end < lower.size() && !is_url_authority_delim(lower[end])) ++end;
  std::string host = lower.substr(start, end - start);
  const size_t at = host.find('@');
  if (at != std::string::npos) host = host.substr(at + 1);
  const size_t colon = host.find(':');
  if (colon != std::string::npos) host = host.substr(0, colon);
  while (!host.empty() && host.back() == '.') host.pop_back();
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
  while (i < tag_end && !is_html_space(lower[i])) ++i;  // skip the tag name
  while (i < tag_end) {
    while (i < tag_end && (is_html_space(lower[i]) || lower[i] == '/')) ++i;
    const size_t name_start = i;
    while (i < tag_end && !is_html_space(lower[i]) &&
           lower[i] != '=' && lower[i] != '/') ++i;
    const size_t name_len = i - name_start;
    while (i < tag_end && is_html_space(lower[i])) ++i;
    size_t value_start = std::string::npos;
    if (i < tag_end && lower[i] == '=') {
      ++i;
      while (i < tag_end && is_html_space(lower[i])) ++i;
      value_start = i;
      if (i < tag_end && (lower[i] == '"' || lower[i] == '\'')) {
        const size_t e = lower.find(lower[i], i + 1);
        i = (e == std::string::npos || e >= tag_end) ? tag_end : e + 1;
      } else {
        while (i < tag_end && !is_html_space(lower[i])) ++i;
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
  while (i < lower.size() && !is_html_space(lower[i]) && lower[i] != '>') ++i;  // tag name
  while (i < lower.size()) {
    while (i < lower.size() && (is_html_space(lower[i]) || lower[i] == '/')) ++i;
    if (i >= lower.size()) break;
    if (lower[i] == '>') return i;                        // between attributes: closes the tag
    while (i < lower.size() && !is_html_space(lower[i]) &&
           lower[i] != '=' && lower[i] != '/' && lower[i] != '>') ++i;  // attribute name
    while (i < lower.size() && is_html_space(lower[i])) ++i;
    if (i < lower.size() && lower[i] == '=') {
      ++i;
      while (i < lower.size() && is_html_space(lower[i])) ++i;
      if (i < lower.size() && (lower[i] == '"' || lower[i] == '\'')) {
        const size_t e = lower.find(lower[i], i + 1);    // quoted value: '>' inside is literal
        if (e == std::string::npos) return std::string::npos;  // unterminated quote
        i = e + 1;
      } else {
        while (i < lower.size() && !is_html_space(lower[i]) && lower[i] != '>') ++i;  // unquoted
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
  const std::string lower = ascii_lower(html);  // length-preserving, indexes html too
  size_t pos = 0;
  while (out.size() < kMaxAnchors) {
    // Find an opening <a that is a tag (next char is whitespace or '>').
    size_t at = lower.find("<a", pos);
    while (at != std::string::npos) {
      const char after = at + 2 < lower.size() ? lower[at + 2] : '>';
      if (after == ' ' || after == '\t' || after == '\n' || after == '\r' ||
          after == '>' || after == '/') break;
      at = lower.find("<a", at + 2);
    }
    if (at == std::string::npos) break;
    const size_t tag_end = find_tag_end(lower, at);
    if (tag_end == std::string::npos) break;
    // href value within the open tag (quoted or unquoted).
    std::string href;
    const size_t v = find_attribute(lower, "href", at, tag_end);
    if (v != std::string::npos && v < tag_end) {
      if (html[v] == '"' || html[v] == '\'') {
        const size_t e = html.find(html[v], v + 1);
        if (e != std::string::npos) href = html.substr(v + 1, e - (v + 1));
      } else {
        size_t e = v;
        while (e < tag_end && html[e] != ' ' && html[e] != '\t' && html[e] != '>') ++e;
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
  std::vector<std::string> plain_parts, html_parts;
  collect_raw_body_parts(g_mime_message_get_mime_part(message), plain_parts, html_parts);
  std::vector<AnchorPair> out;
  for (const std::string& h : html_parts) {
    auto pairs = anchors_from_html(h);
    for (auto& p : pairs) out.push_back(std::move(p));
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
  const std::string lower = ascii_lower(html);
  size_t pos = 0;
  while (out.size() < kMaxForms) {
    const size_t f = lower.find("<form", pos);
    if (f == std::string::npos) break;
    const size_t tag_end = find_tag_end(lower, f);
    if (tag_end == std::string::npos) break;
    std::string action;
    const size_t v = find_attribute(lower, "action", f, tag_end);
    if (v != std::string::npos && v < tag_end) {
      if (html[v] == '"' || html[v] == '\'') {
        const size_t e = html.find(html[v], v + 1);
        if (e != std::string::npos) action = html.substr(v + 1, e - (v + 1));
      } else {
        size_t e = v;
        while (e < tag_end && html[e] != ' ' && html[e] != '\t' && html[e] != '>') ++e;
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
    bool has_password = inner.find("type=password") != std::string::npos ||
                        inner.find("type=\"password\"") != std::string::npos ||
                        inner.find("type='password'") != std::string::npos;
    if (has_password) {
      const std::string d = registrable_domain_from_url(action);
      if (!d.empty()) out.push_back(d);
    }
    pos = (close != std::string::npos && close > tag_end) ? close + 5 : end;
  }
  return out;
}

std::vector<std::string> credential_form_actions_from_message(GMimeMessage* message) {
  std::vector<std::string> plain_parts, html_parts;
  collect_raw_body_parts(g_mime_message_get_mime_part(message), plain_parts, html_parts);
  std::vector<std::string> out;
  for (const std::string& h : html_parts) {
    for (auto& d : credential_form_actions(h)) out.push_back(std::move(d));
  }
  return out;
}

// Image-only / logo-spoof body (TASK-239 AC#4): an HTML body with near-zero visible text
// that is dominated by an anchored <img> linking OFF-domain. Returns the registrable
// domain of the first such anchored-image link (or "" if the body is not image-only).
// kMaxTextChars keeps it to genuinely text-empty bodies (a real logo-spoof phish).
std::string image_only_offdomain_link(GMimeMessage* message, const std::string& from_org) {
  std::vector<std::string> plain_parts, html_parts;
  collect_raw_body_parts(g_mime_message_get_mime_part(message), plain_parts, html_parts);
  if (html_parts.empty()) return "";
  std::string text, html;
  for (const std::string& p : plain_parts) text += p;
  for (const std::string& h : html_parts) html += h;
  // Visible text across the whole body (plain + html stripped).
  text += html_to_text(html);
  size_t visible = 0;
  for (char c : text) if (!std::isspace(static_cast<unsigned char>(c))) ++visible;
  constexpr size_t kMaxTextChars = 120;
  if (visible > kMaxTextChars) return "";
  for (const std::string& h : html_parts) {
    const std::string lower = ascii_lower(h);
    // An <a ...> whose inner HTML (up to </a>) contains an <img>, with an off-domain href.
    size_t pos = 0;
    while (true) {
      const size_t at = lower.find("<a", pos);
      if (at == std::string::npos) break;
      const size_t tag_end = find_tag_end(lower, at);
      if (tag_end == std::string::npos) break;
      const size_t close = lower.find("</a", tag_end + 1);
      const size_t inner_end = close == std::string::npos ? lower.size() : close;
      pos = inner_end + 1;
      const size_t img = lower.find("<img", tag_end);  // scan once, not twice
      if (img == std::string::npos || img > inner_end) continue;
      std::string href;
      const size_t v = find_attribute(lower, "href", at, tag_end);
      if (v != std::string::npos && v < tag_end) {
        if (h[v] == '"' || h[v] == '\'') {
          const size_t e = h.find(h[v], v + 1);
          if (e != std::string::npos) href = h.substr(v + 1, e - (v + 1));
        } else {  // unquoted href (valid HTML5): runs to whitespace or '>'
          size_t e = v;
          while (e < tag_end && h[e] != ' ' && h[e] != '\t' && h[e] != '>') ++e;
          href = h.substr(v, e - v);
        }
      }
      const std::string d = registrable_domain_from_url(href);
      if (!d.empty() && d != from_org) return d;
    }
  }
  return "";
}

// All link hosts (FULL, subdomains kept) in the body: plain-text URLs + raw-HTML hrefs.
// Unlike body_url_domains_from_message (which org-reduces and loses the subdomain), this
// keeps the labels the brand-in-subdomain scan needs (TASK-242). Bounded to kMaxHosts.
std::vector<std::string> link_hosts_from_message(GMimeMessage* message) {
  std::vector<std::string> plain_parts, html_parts;
  collect_raw_body_parts(g_mime_message_get_mime_part(message), plain_parts, html_parts);
  std::vector<std::string> out;
  constexpr size_t kMaxHosts = 512;
  auto scan = [&](const std::string& s) {
    const std::string lower = ascii_lower(s);
    size_t pos = 0;
    while (out.size() < kMaxHosts) {
      const size_t at = lower.find("http", pos);
      if (at == std::string::npos) break;
      // Only a real scheme starts a URL. A bare "http" (e.g. a long
      // delimiter-free "httphttp..." run) advances cheaply instead of copying the
      // whole tail. For a real URL, copy only scheme+authority (to the first
      // authority delimiter), so each host_from_url is O(host), not O(tail). pos
      // still advances just past the scheme, so a second URL embedded in this
      // one's path/query (a redirect link) is still found next iteration: same
      // hosts as before, without the O(n^2) tail copies (C7: was O(n^2), TASK-251).
      size_t scheme = 0;
      if (lower.compare(at, 7, "http://") == 0) scheme = 7;
      else if (lower.compare(at, 8, "https://") == 0) scheme = 8;
      if (scheme == 0) { pos = at + 4; continue; }
      size_t end = at + scheme;
      while (end < s.size() && !is_url_authority_delim(s[end])) ++end;
      std::string h = host_from_url(s.substr(at, end - at));
      if (!h.empty()) out.push_back(std::move(h));
      pos = at + scheme;
    }
  };
  for (const std::string& p : plain_parts) scan(p);
  for (const std::string& h : html_parts) scan(h);
  return out;
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
  if (host.find('.') == std::string::npos) return false;
  const std::string reg = org_domain(host);
  // The registrable itself is a curated brand domain: the brand's own host (any
  // subdomain, and canonical ccTLD variants like paypal.com.au whose labels contain
  // another canonical domain). MUST precede the label-pair loop: paypal.com.au
  // contains the labels "paypal.com" and would otherwise self-flag as deception.
  if (brand_kb::is_canonical_domain(reg)) return false;
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
    if (brand_kb::is_canonical_domain(cand2)) return true;
    if (i + 2 < labels.size()) {
      const std::string cand3 = cand2 + "." + labels[i + 2];
      if (brand_kb::is_canonical_domain(cand3)) return true;
    }
  }
  if (host.size() <= reg.size()) return false;               // no subdomain
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
      std::size_t a = 0, b = tok.size();
      while (a < b && std::isdigit(static_cast<unsigned char>(tok[a]))) ++a;
      while (b > a && std::isdigit(static_cast<unsigned char>(tok[b - 1]))) --b;
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
const std::set<std::string>& strong_phishy_keywords() {
  static const std::set<std::string> k = {
      "secure", "security", "login", "signin", "verify", "verification",
      "recover", "recovery", "unlock", "suspended", "auth", "validate",
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
    s.insert({"account", "update", "confirm", "support", "alert", "billing", "service", "portal"});
    return s;
  }();
  return k;
}

// Invoke fn for each '-'/'_'/'.'-delimited token of stem; stop early when fn returns true.
// The shared splitter for the combosquat-token checks below (a stem is a single DNS label,
// so '.' never actually appears, but accepting it keeps callers uniform).
template <typename F>
bool any_stem_token(const std::string& stem, F&& fn) {
  size_t start = 0;
  while (start <= stem.size()) {
    const size_t sep = stem.find_first_of("-_.", start);
    if (fn(stem.substr(start, sep == std::string::npos ? std::string::npos : sep - start)))
      return true;
    if (sep == std::string::npos) break;
    start = sep + 1;
  }
  return false;
}

// The stem with word separators removed: a multi-word brand's hyphenated displayed domain
// (deutsche-bank) maps to its joined KB key (deutschebank).
std::string dehyphenate(const std::string& stem) {
  std::string out;
  for (char c : stem) if (c != '-' && c != '_') out.push_back(c);
  return out;
}

// Any '-'/'_'/'.'-delimited token of the stem is an attacker keyword (apple-secure -> yes,
// apple-news -> no). Brand-agnostic, so it discriminates a combosquat from a brand's own
// infra for ANY brand, not only the distinctive ones is_phishy_combosquat handles.
bool stem_has_phishy_keyword(const std::string& stem) {
  return any_stem_token(stem, [](const std::string& t) { return phishy_keywords().count(t) > 0; });
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
  if (brand_kb::is_canonical_domain(org_domain)) return false;
  const std::string sld = brand_names::domain_stem(org_domain);
  if (sld.find_first_of("-_") == std::string::npos) {
    // Separator-less concatenation (TASK-251 FN1): a DISTINCTIVE brand glued directly to a
    // phishy keyword (paypalsupport, paypalverify, securepaypal). With no token to split
    // on, the exact brand+keyword / keyword+brand split is tested instead. Distinctive
    // (Tier-1 coined) brands only: a dictionary-word brand as a bare substring collides
    // with legit compounds (applet, freesecurity), and the curated distinctive set is
    // what licenses the any-keyword policy on the separator path too.
    for (const std::string& b : brand_kb::distinctive_slds()) {
      if (sld.size() <= b.size()) continue;
      if (sld.compare(0, b.size(), b) == 0 &&
          phishy_keywords().count(sld.substr(b.size()))) return true;
      if (sld.compare(sld.size() - b.size(), b.size(), b) == 0 &&
          phishy_keywords().count(sld.substr(0, sld.size() - b.size()))) return true;
    }
    return false;
  }
  bool has_distinctive = false, has_kb_brand = false, has_keyword = false, has_strong = false;
  any_stem_token(sld, [&](const std::string& t) {
    if (brand_names::is_distinctive_brand(t)) has_distinctive = true;
    else if (brand_kb::is_brand_sld(t)) has_kb_brand = true;  // is_brand_sld rejects len < 4
    if (phishy_keywords().count(t)) has_keyword = true;
    if (strong_phishy_keywords().count(t)) has_strong = true;
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
enum class CousinScope { Sender, Link, MultiField };
brand_names::BrandMatch brand_cousin(const std::string& domain, CousinScope scope,
                                     const std::vector<std::string>& claimed_brands,
                                     bool corroborated) {
  brand_names::BrandMatch m;
  // One edit from a brand the sender CLAIMS. Cheap: scans only the claimed brands.
  auto claimed_typosquat = [&] {
    if (claimed_brands.empty() || brand_kb::is_canonical_domain(domain)) return false;
    const std::string sld = brand_names::domain_stem(domain);
    if (sld.size() < 5) return false;
    for (const std::string& b : claimed_brands) {
      if (brand_kb::within_edit1(sld, b)) return true;
    }
    return false;
  };
  // Unclaimed one-edit domain: the full KB edit-distance scan, kept LAST in each OR and
  // gated (tier2 on Sender, corroborated-only on the secondary scopes) so it stays rare.
  auto unclaimed_typosquat = [&] { return !brand_kb::typosquat_target_kb(domain).empty(); };
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
    if (any_stem_token(href_stem, [&](const std::string& t) { return t == brand; })) return true;
    const std::string joined = dehyphenate(href_stem);              // multi-word brand prefix
    if (joined.size() > brand.size() && joined.compare(0, brand.size(), brand) == 0) return true;
  }
  if (brand_names::confusable_fold(href_stem) == brand) return true;  // homoglyph (app1e)
  if (brand.size() >= 5 && brand_kb::within_edit1(href_stem, brand)) return true;  // typosquat
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
  if (a.href_domain.empty() || a.href_domain == from_org) return false;
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
      if (joined != st && brand_kb::brand_has_auth_set(joined)) brand = joined;
    }
  }
  if (brand.empty()) {
    // The ownership anchor is the SENDER (from_org), not the href: passing the malicious
    // href here would let owns_prefix self-exempt the spoof (apple is a prefix of the
    // look-alike apple-secure). A link to the brand's own domain is instead exempted by
    // the auth-set / same-name-regional guards below.
    const brand_names::BrandMatch tb =
        brand_names::display_impersonates_brand(a.visible_text, from_org);
    if (tb.tier2 && brand_kb::brand_has_auth_set(tb.brand)) brand = tb.brand;
  }
  if (brand.empty()) return false;
  const std::string hs = brand_names::domain_stem(a.href_domain);
  if (hs == brand || brand_kb::domain_in_brand_auth_set(brand, a.href_domain)) return false;
  return href_lookalikes_brand(hs, brand);
}


// True when the (lowercased) DKIM signing FQDN has the throwaway shape:
// >= 2 labels below its org-domain, every one machine-generated.
bool is_throwaway_signer(const std::string& fqdn) {
  const std::vector<std::string> labels = split_labels(fqdn);
  if (labels.size() < 2) return false;
  const size_t org_len = org_label_count(labels);
  if (labels.size() < org_len + 2) return false;
  for (size_t i = 0; i + org_len < labels.size(); ++i) {
    if (!looks_generated(labels[i])) return false;
  }
  return true;
}

// Read a domain token at offset v: a run of [alnum . - @], then return the part
// after the last '@' (DKIM header.i may be "local@domain" or "@domain";
// header.d is a bare domain). Empty if no token.
std::string read_domain_token(const std::string& s, size_t v) {
  size_t e = v;
  while (e < s.size() && (is_domain_char(s[e]) || s[e] == '@')) ++e;
  std::string tok = s.substr(v, e - v);
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
    if (end == std::string::npos) end = ar.size();
    for (const char* tag : {"header.d=", "header.i="}) {
      const size_t t = ar.find(tag, pos);
      if (t != std::string::npos && t < end) {
        const std::string dom = read_domain_token(ar, t + std::strlen(tag));
        if (!dom.empty()) return dom;
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
  if (list == nullptr || internet_address_list_length(list) == 0) return r;
  InternetAddress* ia = internet_address_list_get_address(list, 0);
  if (ia == nullptr || !INTERNET_ADDRESS_IS_MAILBOX(ia)) return r;
  const char* nm = internet_address_get_name(ia);
  if (nm != nullptr) r.display = nm;
  const char* addr = internet_address_mailbox_get_addr(INTERNET_ADDRESS_MAILBOX(ia));
  if (addr == nullptr) return r;
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
  std::vector<std::string> plain_parts, html_parts;
  collect_body_parts(g_mime_message_get_mime_part(message), plain_parts, html_parts);
  std::string plain, html;
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
      if (nm != nullptr) from_display_name = nm;
      const char* addr = internet_address_mailbox_get_addr(INTERNET_ADDRESS_MAILBOX(ia));
      if (addr != nullptr) {
        const std::string a(addr);
        const auto at = a.rfind('@');
        if (at != std::string::npos) {
          from_fqdn = ascii_lower(a.substr(at + 1));
          while (!from_fqdn.empty() && from_fqdn.back() == '.') from_fqdn.pop_back();
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
    const std::string ar_lower = ascii_lower(ar);
    const std::string signer = dkim_pass_signing_domain(ar_lower);
    if (!signer.empty()) {
      out.dkim_signing_fqdn = signer;
      out.dkim_signing_domain = org_domain(signer);
      out.signer_throwaway = is_throwaway_signer(signer);
    }
    dmarc_pass = ar_lower.find("dmarc=pass") != std::string::npos;
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
  auto claim_tokens = [&](const std::string& src) {
    if (src.empty()) return;
    const std::vector<brand_names::DisplayToken> toks = brand_names::tokenize_display(src);
    for (std::size_t i = 0; i < toks.size(); ++i) {
      claimed.insert(toks[i].plain);
      if (toks[i].perturbed) claimed.insert(toks[i].conf);
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
  auto is_link_lookalike = [&](const std::string& d) {
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
      if (d.empty() || d == out.from_org_domain) continue;
      if (brand_kb::is_canonical_domain(d) || brand_reputation::is_established_brand(d) ||
          decision::is_shared_sender_platform(d)) continue;
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
  if (!cousin.tier1 && host_impersonates_brand(from_fqdn)) cousin.tier1 = true;
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
  auto kb_claim_mismatch = [&](const brand_names::BrandMatch& dm) {
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
  auto coldstart_condemns = [&](const brand_names::BrandMatch& dm) {
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

  return out;
}

}  // namespace

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

std::vector<std::string> url_domains_from_bodies(const std::string& plain_body,
                                                 const std::string& html_body) {
  std::set<std::string> domains;
  const std::string* parts[] = {&plain_body, &html_body};
  for (const std::string* part : parts) {
    const std::string& s = *part;
    // ascii_lower preserves length, so offsets into `lower` index `s` too.
    const std::string lower = ascii_lower(s);
    size_t pos = 0;
    while (true) {
      const size_t at_http = lower.find("http", pos);
      if (at_http == std::string::npos) break;
      size_t scheme_end = std::string::npos;
      if (lower.compare(at_http, 7, "http://") == 0) scheme_end = at_http + 7;
      else if (lower.compare(at_http, 8, "https://") == 0) scheme_end = at_http + 8;
      if (scheme_end == std::string::npos) { pos = at_http + 4; continue; }
      // Authority runs to the first path/query/fragment or quote/space/bracket.
      size_t end = scheme_end;
      while (end < s.size()) {
        const char c = s[end];
        if (c == '/' || c == '?' || c == '#' || c == '"' || c == '\'' ||
            c == '<' || c == '>' || c == ')' || c == ']' || c == ',' ||
            std::isspace(static_cast<unsigned char>(c))) break;
        end++;
      }
      const std::string authority = s.substr(scheme_end, end - scheme_end);
      pos = end;
      const std::string od = registrable_domain_from_authority(authority);
      if (!od.empty()) domains.insert(od);
    }
  }
  return std::vector<std::string>(domains.begin(), domains.end());
}

std::vector<std::string> extract_url_domains(const std::string& raw_rfc822) {
  const ExtractedEmailBody body = extract_email_body(raw_rfc822);
  return url_domains_from_bodies(body.plain_body, body.html_body);
}

}  // namespace spam_engine
