#include "attachment_features.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <set>
#include <sstream>
#include <string>
#include <utility>

#include <archive.h>
#include <archive_entry.h>

namespace spam_engine {
namespace {

enum class PayloadKind : std::uint8_t {
  kUnknown,
  kText,
  kHtml,
  kPdf,
  kZip,
  kArchive,
  kOle,
  kImage,
  kAudio,
  kPe,
  kElf,
  kMachO,
  kScript,
};

struct FileFacts {
  std::string name;
  std::string extension;
  std::string declared_mime;
  PayloadKind found = PayloadKind::kUnknown;
  std::size_t size = 0;
  bool dangerous_extension = false;
  bool double_extension = false;
  bool dangerous_payload = false;
  bool disguised_executable = false;
  bool macro_document = false;
  bool name_obfuscated = false;
  bool type_mismatch = false;
  bool nested_archive = false;
  bool non_regular_archive_entry = false;
  bool content_prefix_only = false;
  std::string text;
};

bool starts_with(const std::string &value, const char *prefix, std::size_t n) {
  return value.size() >= n && std::memcmp(value.data(), prefix, n) == 0;
}

std::string lower_ascii(std::string value) {
  for (char &c : value) {
    const auto uc = static_cast<unsigned char>(c);
    if (uc < 128) {
      c = static_cast<char>(std::tolower(uc));
}
  }
  return value;
}

std::size_t valid_utf8_length(const std::string &value, std::size_t offset) {
  const auto byte = [&](std::size_t i) {
    return static_cast<unsigned char>(value[offset + i]);
  };
  const unsigned char first = byte(0);
  if (first < 0x80) {
    return 1;
}
  std::size_t length = 0;
  if (first >= 0xc2 && first <= 0xdf) {
    length = 2;
  } else if (first >= 0xe0 && first <= 0xef) {
    length = 3;
  } else if (first >= 0xf0 && first <= 0xf4) {
    length = 4;
  } else {
    return 0;
}
  if (offset + length > value.size()) {
    return 0;
}
  for (std::size_t i = 1; i < length; ++i) {
    if ((byte(i) & 0xc0) != 0x80) {
      return 0;
}
  }
  // Reject overlong sequences, UTF-16 surrogates and values past U+10FFFF.
  if ((first == 0xe0 && byte(1) < 0xa0) ||
      (first == 0xed && byte(1) >= 0xa0) ||
      (first == 0xf0 && byte(1) < 0x90) ||
      (first == 0xf4 && byte(1) >= 0x90)) {
    return 0;
  }
  return length;
}

std::uint32_t utf8_code_point(const std::string &value, std::size_t offset,
                              std::size_t length);
bool filename_format_control(std::uint32_t code_point);

std::string raw_basename_only(const std::string &raw) {
  const std::size_t slash = raw.find_last_of("/\\");
  std::string const name = slash == std::string::npos ? raw : raw.substr(slash + 1);
  return name.empty() ? "unnamed" : name;
}

std::string basename_only(const std::string &raw) {
  const std::string name = raw_basename_only(raw);
  std::string out;
  out.reserve(std::min<std::size_t>(name.size(), 160));
  bool prior_space = false;
  for (std::size_t i = 0; i < name.size();) {
    const auto uc = static_cast<unsigned char>(name[i]);
    if (out.size() >= 160) {
      break;
}
    if (uc >= 0x80) {
      const std::size_t length = valid_utf8_length(name, i);
      if (length == 0) {
        if (!prior_space) {
          out.push_back(' ');
}
        prior_space = true;
        ++i;
        continue;
      }
      if (out.size() + length > 160) {
        break;
}
      if (filename_format_control(utf8_code_point(name, i, length))) {
        if (!prior_space) {
          out.push_back(' ');
}
        prior_space = true;
        i += length;
        continue;
      }
      out.append(name, i, length);
      prior_space = false;
      i += length;
      continue;
    }
    if (uc < 0x20 || uc == 0x7f || uc == '"' || uc == '`') {
      if (!prior_space) {
        out.push_back(' ');
}
      prior_space = true;
      ++i;
      continue;
    }
    out.push_back(static_cast<char>(uc));
    prior_space = false;
    ++i;
  }
  while (!out.empty() && out.front() == ' ') {
    out.erase(out.begin());
}
  while (!out.empty() && out.back() == ' ') {
    out.pop_back();
}
  return out.empty() ? "unnamed" : out;
}

std::string extension_of(const std::string &name) {
  const std::size_t dot = name.find_last_of('.');
  if (dot == std::string::npos || dot + 1 >= name.size()) {
    return "";
}
  return lower_ascii(name.substr(dot + 1));
}

std::uint32_t utf8_code_point(const std::string &value, std::size_t offset,
                              std::size_t length) {
  const auto byte = [&](std::size_t i) {
    return static_cast<unsigned char>(value[offset + i]);
  };
  if (length == 1) {
    return byte(0);
}
  if (length == 2) {
    return ((byte(0) & 0x1f) << 6) | (byte(1) & 0x3f);
}
  if (length == 3) {
    return ((byte(0) & 0x0f) << 12) | ((byte(1) & 0x3f) << 6) |
           (byte(2) & 0x3f);
  }
  return ((byte(0) & 0x07) << 18) | ((byte(1) & 0x3f) << 12) |
         ((byte(2) & 0x3f) << 6) | (byte(3) & 0x3f);
}

bool filename_format_control(std::uint32_t code_point) {
  return code_point == 0x00ad || code_point == 0x034f ||
         code_point == 0x061c ||
         (code_point >= 0x180b && code_point <= 0x180f) ||
         (code_point >= 0x200b && code_point <= 0x200f) ||
         (code_point >= 0x202a && code_point <= 0x202e) ||
         (code_point >= 0x2060 && code_point <= 0x206f) ||
         code_point == 0x3164 || code_point == 0xfeff ||
         code_point == 0xffa0;
}

// Build the ASCII-facing name that controls suffix classification. The
// rendered filename remains the sanitized original, but Windows-trimmed
// suffixes, bidi/zero-width controls and common full-width dot/ASCII forms
// must not hide an executable extension from the deterministic experiment.
std::string filename_for_classification(const std::string &name,
                                        bool &obfuscated) {
  std::string out;
  out.reserve(name.size());
  for (std::size_t i = 0; i < name.size();) {
    const auto c = static_cast<unsigned char>(name[i]);
    if (c < 0x80) {
      if (c < 0x20 || c == 0x7f) {
        obfuscated = true;
        ++i;
        continue;
      }
      out.push_back(static_cast<char>(c));
      ++i;
      continue;
    }
    const std::size_t length = valid_utf8_length(name, i);
    if (length == 0) {
      obfuscated = true;
      ++i;
      continue;
    }
    const std::uint32_t code_point = utf8_code_point(name, i, length);
    if (filename_format_control(code_point)) {
      obfuscated = true;
      i += length;
      continue;
    }
    if (code_point == 0x2024 || code_point == 0x3002 ||
        code_point == 0xfe52 || code_point == 0xff0e) {
      out.push_back('.');
      obfuscated = true;
      i += length;
      continue;
    }
    if (code_point >= 0xff01 && code_point <= 0xff5e) {
      out.push_back(static_cast<char>(code_point - 0xfee0));
      obfuscated = true;
      i += length;
      continue;
    }
    out.append(name, i, length);
    i += length;
  }
  while (!out.empty() && (out.back() == ' ' || out.back() == '.')) {
    out.pop_back();
    obfuscated = true;
  }
  return lower_ascii(out);
}

bool extension_in(const std::string &ext, const std::set<std::string> &values) {
  return values.find(ext) != values.end();
}

const std::set<std::string> &dangerous_extensions() {
  static const std::set<std::string> values = {
      "ade", "adp", "app",     "application", "bas", "bat", "bash",
      "chm", "cmd", "com",     "command",     "cpl", "desktop", "dll",
      "dmg", "elf", "exe",     "gadget",      "hta", "inf",     "ins",
      "isp", "jar", "js",      "jse",         "ksh", "lnk",     "mach-o",
      "mde", "msc", "msi",     "msp",         "mst", "pif",     "pkg",
      "prg", "ps1", "py",      "rb",          "reg", "run",     "scf",
      "scr", "sct", "sh",      "shb",         "shs", "url",     "vb",
      "vbe", "vbs", "wsc",     "wsf",         "wsh", "xll",     "xnk",
      "zsh",
  };
  return values;
}

const std::set<std::string> &harmless_looking_extensions() {
  static const std::set<std::string> values = {
      "csv",  "doc", "docx", "gif", "htm", "html", "ics",
      "jpeg", "jpg", "json", "odt", "pdf", "png",  "ppt",
      "pptx", "rtf", "svg",  "txt", "xls", "xlsx", "xml",
  };
  return values;
}

bool has_dangerous_double_extension(const std::string &lower_name) {
  const std::size_t last = lower_name.find_last_of('.');
  if (last == std::string::npos) {
    return false;
}
  const std::string final_ext = lower_name.substr(last + 1);
  if (!extension_in(final_ext, dangerous_extensions())) {
    return false;
}
  const std::size_t previous = lower_name.find_last_of('.', last - 1);
  if (previous == std::string::npos) {
    return false;
}
  const std::string claimed =
      lower_name.substr(previous + 1, last - previous - 1);
  return extension_in(claimed, harmless_looking_extensions());
}

bool is_probably_text(const std::string &bytes) {
  if (bytes.empty()) {
    return false;
}
  const std::size_t n = std::min<std::size_t>(bytes.size(), 4096);
  std::size_t controls = 0;
  for (std::size_t i = 0; i < n; ++i) {
    const auto c = static_cast<unsigned char>(bytes[i]);
    if (c == 0) {
      return false;
}
    if (c < 0x20 && c != '\n' && c != '\r' && c != '\t' && c != '\f') {
      ++controls;
    }
  }
  return controls * 20 <= n;
}

PayloadKind detect_kind(const std::string &bytes, const std::string &mime,
                        const std::string &ext) {
  if (starts_with(bytes, "%PDF-", 5)) {
    return PayloadKind::kPdf;
}
  if (bytes.size() >= 4 && static_cast<unsigned char>(bytes[0]) == 0x50 &&
      static_cast<unsigned char>(bytes[1]) == 0x4b &&
      ((static_cast<unsigned char>(bytes[2]) == 0x03 &&
        static_cast<unsigned char>(bytes[3]) == 0x04) ||
       (static_cast<unsigned char>(bytes[2]) == 0x05 &&
        static_cast<unsigned char>(bytes[3]) == 0x06) ||
       (static_cast<unsigned char>(bytes[2]) == 0x07 &&
        static_cast<unsigned char>(bytes[3]) == 0x08))) {
    return PayloadKind::kZip;
  }
  static const char kOle[] = {static_cast<char>(0xd0), static_cast<char>(0xcf),
                              static_cast<char>(0x11), static_cast<char>(0xe0),
                              static_cast<char>(0xa1), static_cast<char>(0xb1),
                              static_cast<char>(0x1a), static_cast<char>(0xe1)};
  if (starts_with(bytes, kOle, sizeof(kOle))) {
    return PayloadKind::kOle;
}
  if (starts_with(bytes, "MZ", 2)) {
    return PayloadKind::kPe;
}
  static const char kElf[] = {static_cast<char>(0x7f), 'E', 'L', 'F'};
  if (starts_with(bytes, kElf, sizeof(kElf))) {
    return PayloadKind::kElf;
}
  if (bytes.size() >= 4) {
    const std::array<unsigned char, 4> m = {
        static_cast<unsigned char>(bytes[0]),
        static_cast<unsigned char>(bytes[1]),
        static_cast<unsigned char>(bytes[2]),
        static_cast<unsigned char>(bytes[3])};
    if (m == std::array<unsigned char, 4>{0xfe, 0xed, 0xfa, 0xce} ||
        m == std::array<unsigned char, 4>{0xce, 0xfa, 0xed, 0xfe} ||
        m == std::array<unsigned char, 4>{0xfe, 0xed, 0xfa, 0xcf} ||
        m == std::array<unsigned char, 4>{0xcf, 0xfa, 0xed, 0xfe} ||
        m == std::array<unsigned char, 4>{0xca, 0xfe, 0xba, 0xbe} ||
        m == std::array<unsigned char, 4>{0xbe, 0xba, 0xfe, 0xca}) {
      return PayloadKind::kMachO;
    }
  }
  // AMR audio uses a shebang-shaped file signature. Recognize both standard
  // signatures before the generic script check or legitimate call recordings
  // become deterministic executable false positives.
  if (starts_with(bytes, "#!AMR\n", 6) ||
      starts_with(bytes, "#!AMR-WB\n", 9)) {
    return PayloadKind::kAudio;
  }
  if (starts_with(bytes, "#!", 2)) {
    return PayloadKind::kScript;
}
  if (starts_with(bytes, "\x89PNG\r\n\x1a\n", 8) ||
      starts_with(bytes, "GIF87a", 6) || starts_with(bytes, "GIF89a", 6) ||
      (bytes.size() >= 3 && static_cast<unsigned char>(bytes[0]) == 0xff &&
       static_cast<unsigned char>(bytes[1]) == 0xd8 &&
       static_cast<unsigned char>(bytes[2]) == 0xff)) {
    return PayloadKind::kImage;
  }
  if (bytes.size() >= 6 && static_cast<unsigned char>(bytes[0]) == 0x37 &&
      static_cast<unsigned char>(bytes[1]) == 0x7a &&
      static_cast<unsigned char>(bytes[2]) == 0xbc &&
      static_cast<unsigned char>(bytes[3]) == 0xaf &&
      static_cast<unsigned char>(bytes[4]) == 0x27 &&
      static_cast<unsigned char>(bytes[5]) == 0x1c) {
    return PayloadKind::kArchive;
  }
  // Declared MIME and suffix are fallbacks, never allowed to override a magic
  // signature above. This distinction is the point of reporting claimed and
  // found types separately.
  const std::string lower_mime = lower_ascii(mime);
  if (lower_mime == "text/html" || ext == "html" || ext == "htm") {
    return PayloadKind::kHtml;
  }
  if (lower_mime.rfind("text/", 0) == 0 ||
      extension_in(ext, {"csv", "ics", "json", "md", "rtf", "txt", "xml"})) {
    return PayloadKind::kText;
  }
  if (is_probably_text(bytes)) {
    return PayloadKind::kText;
}
  return PayloadKind::kUnknown;
}

bool dangerous_kind(PayloadKind kind) {
  return kind == PayloadKind::kPe || kind == PayloadKind::kElf ||
         kind == PayloadKind::kMachO || kind == PayloadKind::kScript;
}

const char *kind_name(PayloadKind kind) {
  switch (kind) {
  case PayloadKind::kText:
    return "text";
  case PayloadKind::kHtml:
    return "html";
  case PayloadKind::kPdf:
    return "pdf";
  case PayloadKind::kZip:
    return "zip";
  case PayloadKind::kArchive:
    return "archive";
  case PayloadKind::kOle:
    return "ole-office";
  case PayloadKind::kImage:
    return "image";
  case PayloadKind::kAudio:
    return "audio";
  case PayloadKind::kPe:
    return "pe-executable";
  case PayloadKind::kElf:
    return "elf-executable";
  case PayloadKind::kMachO:
    return "mach-o-executable";
  case PayloadKind::kScript:
    return "script";
  case PayloadKind::kUnknown:
    break;
  }
  return "unknown";
}

std::string collapse_text(const std::string &raw, std::size_t cap) {
  std::string out;
  out.reserve(std::min(raw.size(), cap));
  bool space = false;
  for (std::size_t i = 0; i < raw.size();) {
    if (out.size() >= cap) {
      break;
}
    const auto c = static_cast<unsigned char>(raw[i]);
    if (c >= 0x80) {
      const std::size_t length = valid_utf8_length(raw, i);
      if (length == 0) {
        ++i;
        continue;
      }
      if (space) {
        out.push_back(' ');
        space = false;
      }
      if (out.size() + length > cap) {
        break;
}
      out.append(raw, i, length);
      i += length;
      continue;
    }
    if (c < 0x09 || (c > 0x0d && c < 0x20) || c == 0x7f) {
      ++i;
      continue;
    }
    if (std::isspace(c) != 0) {
      space = !out.empty();
      ++i;
      continue;
    }
    if (space) {
      out.push_back(' ');
      space = false;
      if (out.size() >= cap) {
        break;
}
    }
    out.push_back(static_cast<char>(c));
    ++i;
  }
  return out;
}

std::string strip_markup(const std::string &raw, std::size_t cap) {
  std::string text;
  text.reserve(std::min(raw.size(), cap * 2));
  bool in_tag = false;
  bool in_entity = false;
  std::string entity;
  for (const char c : raw) {
    if (text.size() >= cap * 2) {
      break;
}
    if (in_tag) {
      if (c == '>') {
        in_tag = false;
        text.push_back(' ');
      }
      continue;
    }
    if (c == '<') {
      in_tag = true;
      continue;
    }
    if (in_entity) {
      if (c == ';' || entity.size() >= 10) {
        if (entity == "amp") {
          text.push_back('&');
        } else if (entity == "lt") {
          text.push_back('<');
        } else if (entity == "gt") {
          text.push_back('>');
        } else if (entity == "quot") {
          text.push_back('"');
        } else {
          text.push_back(' ');
}
        entity.clear();
        in_entity = false;
      } else {
        entity.push_back(c);
      }
      continue;
    }
    if (c == '&') {
      in_entity = true;
      entity.clear();
      continue;
    }
    text.push_back(c);
  }
  return collapse_text(text, cap);
}

bool text_extension(const std::string &ext) {
  static const std::set<std::string> values = {
      "csv", "htm", "html", "ics", "json", "md", "rtf", "txt", "xml",
  };
  return extension_in(ext, values);
}

bool office_xml_member(const std::string &lower_path) {
  return lower_path == "docprops/core.xml" ||
         lower_path == "xl/sharedstrings.xml" ||
         lower_path.rfind("word/", 0) == 0 ||
         lower_path.rfind("ppt/slides/", 0) == 0;
}

PayloadKind kind_claimed_by_extension(const std::string &extension) {
  if (extension == "pdf") {
    return PayloadKind::kPdf;
}
  if (extension_in(extension, {"zip", "docx", "dotx", "odt", "odp", "ods",
                               "pptx", "xlsx", "xltx"})) {
    return PayloadKind::kZip;
}
  if (extension_in(extension, {"gif", "jpeg", "jpg", "png"})) {
    return PayloadKind::kImage;
}
  if (extension_in(extension, {"htm", "html"})) {
    return PayloadKind::kHtml;
}
  if (text_extension(extension)) {
    return PayloadKind::kText;
}
  return PayloadKind::kUnknown;
}

bool kinds_compatible(PayloadKind claimed, PayloadKind found) {
  if (claimed == found) {
    return true;
}
  return (claimed == PayloadKind::kText && found == PayloadKind::kHtml) ||
         (claimed == PayloadKind::kHtml && found == PayloadKind::kText);
}

FileFacts inspect_file(const std::string &raw_name, const std::string &mime,
                       const std::string &bytes) {
  FileFacts f;
  f.name = basename_only(raw_name);
  const std::string classification_name =
      filename_for_classification(raw_basename_only(raw_name),
                                  f.name_obfuscated);
  f.extension = extension_of(classification_name);
  f.declared_mime = lower_ascii(mime);
  f.size = bytes.size();
  f.dangerous_extension = extension_in(f.extension, dangerous_extensions());
  f.double_extension = has_dangerous_double_extension(classification_name);
  f.found = detect_kind(bytes, f.declared_mime, f.extension);
  f.dangerous_payload = dangerous_kind(f.found);
  f.disguised_executable =
      f.double_extension || (f.dangerous_payload && !f.dangerous_extension) ||
      (f.dangerous_extension && f.name_obfuscated);
  const PayloadKind claimed = kind_claimed_by_extension(f.extension);
  f.type_mismatch = claimed != PayloadKind::kUnknown &&
                    f.found != PayloadKind::kUnknown &&
                    !kinds_compatible(claimed, f.found);
  f.macro_document = extension_in(
      f.extension, {"docm", "dotm", "xlsm", "xltm", "pptm", "potm"});
  if (f.found == PayloadKind::kHtml) {
    f.text = strip_markup(bytes, kAttachmentTextPerFileMaxBytes);
  } else if ((f.found == PayloadKind::kText ||
              f.found == PayloadKind::kScript) &&
             is_probably_text(bytes)) {
    f.text = collapse_text(bytes, kAttachmentTextPerFileMaxBytes);
  }
  return f;
}

void append_bounded(std::string &out, const std::string &line,
                    ExtractedAttachmentFeatures &features) {
  if (out.size() >= kAttachmentContextMaxBytes) {
    features.truncated = true;
    return;
  }
  const std::size_t remaining = kAttachmentContextMaxBytes - out.size();
  if (line.size() <= remaining) {
    out += line;
  } else {
    std::size_t keep = remaining;
    while (keep > 0 && keep < line.size() &&
           (static_cast<unsigned char>(line[keep]) & 0xc0) == 0x80) {
      --keep;
    }
    out.append(line, 0, keep);
    features.truncated = true;
  }
}

std::string size_bucket(std::size_t n) {
  if (n == 0) {
    return "empty";
}
  if (n < static_cast<std::size_t>(10U * 1024U)) {
    return "under-10kb";
}
  if (n < static_cast<std::size_t>(100U * 1024U)) {
    return "10-100kb";
}
  if (n < static_cast<std::size_t>(1024U * 1024U)) {
    return "100kb-1mb";
}
  if (n < static_cast<std::size_t>(10U * 1024U * 1024U)) {
    return "1-10mb";
}
  return "over-10mb";
}

void merge_file_flags(const FileFacts &f, bool archived,
                      ExtractedAttachmentFeatures &out) {
  if (archived) {
    out.archive_dangerous_type = out.archive_dangerous_type ||
                                 f.dangerous_payload || f.dangerous_extension;
    out.archive_disguised_executable =
        out.archive_disguised_executable || f.disguised_executable;
  } else {
    out.dangerous_type =
        out.dangerous_type || f.dangerous_payload || f.dangerous_extension;
    out.disguised_executable =
        out.disguised_executable || f.disguised_executable;
  }
  out.macro_document = out.macro_document || f.macro_document;
}

std::string render_file(const char *prefix, int index, const FileFacts &f) {
  std::ostringstream line;
  line << prefix << " " << index << ": name=\"" << f.name << "\""
       << " size=" << size_bucket(f.size);
  if (!f.extension.empty()) {
    line << " claimed=" << f.extension;
}
  if (!f.declared_mime.empty()) {
    line << " declared=" << f.declared_mime;
}
  line << " found=" << kind_name(f.found);
  if (f.double_extension) {
    line << " double-extension";
}
  if (f.disguised_executable) {
    line << " disguised-executable";
  } else if (f.dangerous_extension || f.dangerous_payload) {
    line << " dangerous-type";
}
  if (f.macro_document) {
    line << " macro-document";
}
  if (f.name_obfuscated) {
    line << " name-obfuscation";
}
  if (f.type_mismatch) {
    line << " type-mismatch";
}
  if (f.nested_archive) {
    line << " nested-archive";
}
  if (f.non_regular_archive_entry) {
    line << " non-regular-entry";
}
  if (f.content_prefix_only) {
    line << " content-prefix-only";
}
  line << "\n";
  if (!f.text.empty()) {
    line << prefix << " " << index << " text: " << f.text << "\n";
}
  return line.str();
}

void inspect_archive(const AttachmentInput &attachment,
                     ExtractedAttachmentFeatures &out, std::string &context) {
  if (attachment.payload.size() > kAttachmentArchiveInputMaxBytes) {
    out.truncated = true;
    return;
  }

  archive *ar = archive_read_new();
  if (ar == nullptr) {
    out.parse_failed = true;
    return;
  }
  // ZIP/OOXML only in D2. Registering every libarchive filter can fall back to
  // spawning an external decompressor when a codec was not built in, which is
  // outside this experiment's no-execution contract. ZIP deflate is handled by
  // libarchive itself and covers the carrier the data gate predeclares.
  archive_read_support_filter_none(ar);
  archive_read_support_format_zip(ar);
  if (archive_read_open_memory(ar, attachment.payload.data(),
                               attachment.payload.size()) != ARCHIVE_OK) {
    out.parse_failed = true;
    archive_read_free(ar);
    return;
  }

  archive_entry *entry = nullptr;
  std::size_t total_read = 0;
  int index = 0;
  int next_status = ARCHIVE_OK;
  bool stopped_on_truncated_member = false;
  while (index < kAttachmentArchiveMaxEntries) {
    next_status = archive_read_next_header(ar, &entry);
    if (next_status == ARCHIVE_EOF) {
      break;
}
    if (next_status != ARCHIVE_OK) {
      out.parse_failed = true;
      break;
    }
    ++index;
    ++out.archive_member_count;
    if (archive_entry_is_encrypted(entry) == 1) {
      out.encrypted_archive = true;
}
    const char *pathname = archive_entry_pathname(entry);
    const std::string raw_path = pathname == nullptr ? "unnamed" : pathname;
    const std::string lower_path = lower_ascii(raw_path);
    const mode_t type = archive_entry_filetype(entry);
    if (type != AE_IFREG) {
      FileFacts f = inspect_file(raw_path, "", "");
      f.non_regular_archive_entry = true;
      f.content_prefix_only = archive_entry_size(entry) != 0;
      merge_file_flags(f, true, out);
      append_bounded(context, render_file("archive member", index, f), out);
      // Do not call archive_read_data_skip(): a crafted non-regular ZIP entry
      // may still carry compressed data, and libarchive's skip path can read it.
      // Stop at the unsupported entry and make the partial scan visible.
      out.truncated = true;
      break;
    }
    const la_int64_t declared_size = archive_entry_size(entry);
    const std::size_t remaining_total =
        kAttachmentArchiveTotalReadMaxBytes - total_read;
    const std::size_t cap = std::min<std::size_t>(
        kAttachmentArchiveEntryReadMaxBytes, remaining_total);
    std::size_t wanted = cap;
    if (declared_size >= 0 &&
        static_cast<std::uint64_t>(declared_size) <= cap) {
      wanted = static_cast<std::size_t>(declared_size);
    }
    std::string bytes;
    bytes.resize(wanted);
    std::size_t filled = 0;
    bool reached_entry_end = bytes.empty() && declared_size == 0;
    bool read_failed = false;
    while (filled < bytes.size()) {
      const la_ssize_t n =
          archive_read_data(ar, bytes.data() + filled, bytes.size() - filled);
      if (n < 0) {
        out.parse_failed = true;
        read_failed = true;
        bytes.resize(filled);
        break;
      }
      if (n == 0) {
        reached_entry_end = true;
        break;
      }
      filled += static_cast<std::size_t>(n);
    }
    bytes.resize(filled);
    total_read += filled;
    const bool member_truncated =
        read_failed ||
        (declared_size < 0
             ? !reached_entry_end
             : static_cast<std::uint64_t>(declared_size) > filled);
    if (member_truncated) {
      out.truncated = true;
}

    FileFacts f = inspect_file(raw_path, "", bytes);
    f.content_prefix_only = member_truncated;
    f.nested_archive = f.found == PayloadKind::kZip ||
                       f.found == PayloadKind::kArchive;
    if (lower_path.find("vbaproject.bin") != std::string::npos) {
      f.macro_document = true;
    }
    if (office_xml_member(lower_path) && is_probably_text(bytes)) {
      f.text = strip_markup(bytes, kAttachmentTextPerFileMaxBytes);
    } else if (text_extension(f.extension) && is_probably_text(bytes)) {
      f.text = f.found == PayloadKind::kHtml
                   ? strip_markup(bytes, kAttachmentTextPerFileMaxBytes)
                   : collapse_text(bytes, kAttachmentTextPerFileMaxBytes);
    }
    merge_file_flags(f, true, out);
    append_bounded(context, render_file("archive member", index, f), out);
    // archive_read_data_skip() may repeatedly decompress the unconsumed entry.
    // Once the bounded prefix is exhausted, stop this archive rather than turn
    // a fail-visible scan cap into unbounded ZIP-bomb work.
    if (member_truncated) {
      stopped_on_truncated_member = true;
      break;
    }
  }
  if (index >= kAttachmentArchiveMaxEntries && next_status == ARCHIVE_OK &&
      !stopped_on_truncated_member) {
    next_status = archive_read_next_header(ar, &entry);
    if (next_status != ARCHIVE_EOF) {
      out.truncated = true;
}
  }
  if (archive_read_has_encrypted_entries(ar) == 1) {
    out.encrypted_archive = true;
}
  archive_read_close(ar);
  archive_read_free(ar);
}

} // namespace

ExtractedAttachmentFeatures
analyze_attachments(const std::vector<AttachmentInput> &attachments,
                    int observed_count, bool collection_truncated) {
  ExtractedAttachmentFeatures out;
  out.total_count = observed_count >= 0 ? observed_count
                                        : static_cast<int>(attachments.size());
  out.truncated = collection_truncated;
  std::string details;

  int index = 0;
  for (const auto &attachment : attachments) {
    FileFacts const f = inspect_file(attachment.filename, attachment.declared_mime,
                               attachment.payload);
    if (!attachment.counted_as_attachment) {
      // Inline image bodies belong to the image representation. Inspect them so
      // a declared image cannot hide an executable/archive or dangerous suffix,
      // but do not require an ever-growing allowlist of legitimate image magic.
      const bool promote = dangerous_kind(f.found) || f.dangerous_extension ||
                           f.found == PayloadKind::kZip ||
                           f.found == PayloadKind::kArchive;
      if (!promote) {
        continue;
}
      ++out.total_count;
    }
    ++index;
    out.total_bytes += attachment.payload.size();
    out.truncated = out.truncated || attachment.truncated;
    merge_file_flags(f, false, out);
    append_bounded(details, render_file("attachment", index, f), out);
    if (f.found == PayloadKind::kZip) {
      inspect_archive(attachment, out, details);
    }
  }
  if (out.total_count > 0) {
    std::string context = "[Attachment context]\n";
    std::ostringstream summary;
    summary << "attachment totals: files=" << out.total_count
            << " bytes=" << out.total_bytes
            << " archive-members=" << out.archive_member_count;
    if (out.disguised_executable || out.archive_disguised_executable) {
      summary << " disguised-executable";
    } else if (out.dangerous_type || out.archive_dangerous_type) {
      summary << " dangerous-type";
}
    if (out.encrypted_archive) {
      summary << " encrypted-archive";
}
    if (out.macro_document) {
      summary << " macro-document";
}
    if (out.truncated) {
      summary << " truncated";
}
    if (out.parse_failed) {
      summary << " parse-failed";
}
    summary << "\n[Email]\n";
    append_bounded(context, summary.str(), out);
    if (!details.empty()) {
      append_bounded(context, "[Attachment details]\n", out);
      append_bounded(context, details, out);
    }
    out.context = std::move(context);
  }
  return out;
}

} // namespace spam_engine
