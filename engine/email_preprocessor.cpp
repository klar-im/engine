#include "email_preprocessor.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
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

std::string build_normalized_text(
    const std::string& subject,
    const std::string& from,
    const std::string& body_text) {
  std::string normalized;
  if (!subject.empty()) {
    normalized += "subject: " + subject + "\n";
  }
  if (!from.empty()) {
    normalized += "from: " + from + "\n";
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

  for (std::size_t i = 0; i < html.size(); ++i) {
    char c = html[i];

    if (c == '<') {
      in_tag = true;
      tag_name.clear();
      text.push_back(' ');
      continue;
    }

    if (in_tag) {
      if (c == '>') {
        in_tag = false;
        // Check if entering or leaving script/style
        std::string lower_tag;
        for (char tc : tag_name) {
          lower_tag.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(tc))));
        }
        if (lower_tag == "script" || lower_tag == "style") {
          in_script_or_style = true;
        } else if (lower_tag == "/script" || lower_tag == "/style") {
          in_script_or_style = false;
        }
      } else if (!std::isspace(static_cast<unsigned char>(c))) {
        tag_name.push_back(c);
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
void collect_address_list(InternetAddressList* list, std::set<std::string>& out) {
  if (list == nullptr) return;
  const int n = internet_address_list_length(list);
  for (int i = 0; i < n; i++) {
    InternetAddress* addr = internet_address_list_get_address(list, i);
    if (addr == nullptr) continue;
    if (INTERNET_ADDRESS_IS_GROUP(addr)) {
      collect_address_list(internet_address_group_get_members(INTERNET_ADDRESS_GROUP(addr)), out);
    } else if (INTERNET_ADDRESS_IS_MAILBOX(addr)) {
      add_address_tokens(out,
          internet_address_mailbox_get_addr(INTERNET_ADDRESS_MAILBOX(addr)),
          internet_address_get_name(addr));
    }
  }
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
      std::string out(converted, static_cast<std::size_t>(bytes_written));
      g_free(converted);
      return out;
    }

    if (error != nullptr) {
      g_error_free(error);
    }
  }

  char* guessed = g_mime_utils_decode_8bit(
      parser_options(), decoded_body.data(), decoded_body.size());
  if (guessed == nullptr) {
    return decoded_body;
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
  // Both lists are compared by their rendered email-only string so we don't
  // false-positive on display-name differences.
  InternetAddressList* reply_to_list = g_mime_message_get_reply_to(message);
  if (reply_to_list != nullptr && from_list != nullptr) {
    char* reply_to_rendered =
        internet_address_list_to_string(reply_to_list, nullptr, false);
    char* from_rendered =
        internet_address_list_to_string(from_list, nullptr, false);
    if (reply_to_rendered != nullptr && from_rendered != nullptr) {
      const std::string reply_to_str = decode_header_text(reply_to_rendered);
      const std::string from_str = decode_header_text(from_rendered);
      if (!reply_to_str.empty() && reply_to_str != from_str) {
        out.replyto_differs = true;
      }
    }
    if (reply_to_rendered != nullptr) g_free(reply_to_rendered);
    if (from_rendered != nullptr) g_free(from_rendered);
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
  g_object_unref(message);

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
  g_object_unref(message);

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
// alphabetic word followed by digits (optionally -digits) is how real sending
// infrastructure names shards — categorically different from the random
// mid-digit / vowel-free labels of throwaway signers (f9l / 1qb / jjlw).
bool is_fleet_numbered(const std::string& label) {
  size_t i = 0;
  while (i < label.size() && std::isalpha(static_cast<unsigned char>(label[i]))) ++i;
  if (i == 0 || i == label.size()) return false;
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

// Core sender-auth extraction from an already-parsed message. Shared by the
// standalone extract_auth_features (which parses) and preprocess_rfc822 (which
// reuses its own parse). Does NOT unref the message — the caller owns it.
ExtractedAuthFeatures extract_auth_features_from_message(GMimeMessage* message) {
  ExtractedAuthFeatures out;

  if (message == nullptr) {
    return out;
  }

  // From org-domain (from the parsed mailbox address, not the display name).
  InternetAddressList* from_list = g_mime_message_get_from(message);
  if (from_list != nullptr && internet_address_list_length(from_list) > 0) {
    InternetAddress* ia = internet_address_list_get_address(from_list, 0);
    if (ia != nullptr && INTERNET_ADDRESS_IS_MAILBOX(ia)) {
      const char* addr = internet_address_mailbox_get_addr(INTERNET_ADDRESS_MAILBOX(ia));
      if (addr != nullptr) {
        const std::string a(addr);
        const auto at = a.rfind('@');
        if (at != std::string::npos) {
          out.from_org_domain = org_domain(a.substr(at + 1));
        }
      }
    }
  }

  // Topmost Authentication-Results only: g_mime_object_get_header returns the
  // first occurrence, which is the one the receiving MTA prepended (trusted).
  const char* ar = g_mime_object_get_header(GMIME_OBJECT(message), "Authentication-Results");
  if (ar != nullptr && ar[0] != '\0') {
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
    const bool dmarc_pass = ar_lower.find("dmarc=pass") != std::string::npos;
    out.dmarc_aligned = dmarc_pass && !out.dkim_signing_domain.empty()
                        && out.dkim_signing_domain == out.from_org_domain;
  }

  return out;
}

}  // namespace

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
      std::string authority = s.substr(scheme_end, end - scheme_end);
      pos = end;
      // Drop userinfo (…@), port (:…) and trailing dots, then reduce to eTLD+1.
      const size_t at = authority.find('@');
      if (at != std::string::npos) authority = authority.substr(at + 1);
      const size_t colon = authority.find(':');
      if (colon != std::string::npos) authority = authority.substr(0, colon);
      while (!authority.empty() && authority.back() == '.') authority.pop_back();
      const std::string od = org_domain(authority);
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
