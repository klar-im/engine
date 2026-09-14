#include "attachment_features.h"
#include "email_preprocessor.h"

#include <archive.h>
#include <archive_entry.h>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

void check(bool condition, const std::string &message) {
  if (!condition) {
    throw std::runtime_error(message);
}
}

std::string
make_zip(const std::vector<std::pair<std::string, std::string>> &files) {
  auto capacity = static_cast<std::size_t>(64 * 1024);
  for (const auto &[name, payload] : files) {
    capacity += name.size() + payload.size() + 1024;
}
  std::vector<char> storage(capacity);
  std::size_t used = 0;
  archive *writer = archive_write_new();
  check(writer != nullptr, "archive writer allocated");
  archive_write_set_format_zip(writer);
  check(archive_write_open_memory(writer, storage.data(), storage.size(),
                                  &used) == ARCHIVE_OK,
        "archive writer opened memory buffer");
  for (const auto &[name, payload] : files) {
    archive_entry *entry = archive_entry_new();
    archive_entry_set_pathname(entry, name.c_str());
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644);
    archive_entry_set_size(entry, static_cast<la_int64_t>(payload.size()));
    check(archive_write_header(writer, entry) == ARCHIVE_OK,
          "archive member header written");
    check(archive_write_data(writer, payload.data(), payload.size()) ==
              static_cast<la_ssize_t>(payload.size()),
          "archive member bytes written");
    archive_entry_free(entry);
  }
  check(archive_write_close(writer) == ARCHIVE_OK, "archive writer closed");
  archive_write_free(writer);
  return {storage.data(), used};
}

void test_plain_invoice_is_context_not_a_rule() {
  const auto f = spam_engine::analyze_attachments({
      {"invoice-2026.pdf", "application/pdf", "%PDF-1.7 inert fixture"},
  });
  check(f.total_count == 1, "one attachment counted");
  check(!f.disguised_executable && !f.dangerous_type,
        "ordinary PDF does not fire deterministic risk");
  check(f.context.find("name=\"invoice-2026.pdf\"") != std::string::npos,
        "filename enters the joint context");
  check(f.context.find("found=pdf") != std::string::npos,
        "magic-byte type enters the context");
  const std::size_t email = f.context.find("[Email]\n");
  const std::size_t details = f.context.find("[Attachment details]\n");
  check(email != std::string::npos && details > email,
        "email is inserted before verbose attachment details");
}

void test_direct_disguise_and_plain_executable_are_distinct() {
  const std::string inert_pe = std::string("MZ", 2) + " inert-not-executable";
  const auto disguised = spam_engine::analyze_attachments({
      {"invoice.pdf", "application/pdf", inert_pe},
  });
  check(disguised.disguised_executable,
        "PE bytes presented as PDF are a deception fact");
  check(disguised.dangerous_type, "dangerous payload shape is recorded");

  const auto plain = spam_engine::analyze_attachments({
      {"diagnostic.exe", "application/octet-stream", inert_pe},
  });
  check(!plain.disguised_executable,
        "honestly named executable is not mislabeled as disguise");
  check(plain.dangerous_type,
        "honestly named executable remains a moderate risk fact");
}

void test_magic_type_wins_over_declared_text() {
  const std::string png = "\x89PNG\r\n\x1a\n";
  const auto image = spam_engine::analyze_attachments({
      {"notes.txt", "text/plain", png},
  });
  check(image.context.find("claimed=txt declared=text/plain found=image") !=
            std::string::npos,
        "magic-byte type is not overwritten by claimed text metadata");
  check(image.context.find("type-mismatch") != std::string::npos,
        "claimed-versus-magic mismatch is explicit in the representation");
}

void test_amr_signature_is_not_a_script_shebang() {
  const std::string amr = "#!AMR\n" + std::string(64, '\x01');
  const auto audio = spam_engine::analyze_attachments({
      {"call.amr", "audio/amr", amr},
  });
  check(!audio.dangerous_type && !audio.disguised_executable,
        "AMR call recording is not a dangerous script");
  check(audio.context.find("claimed=amr declared=audio/amr found=audio") !=
            std::string::npos,
        "AMR magic is represented as audio before the shebang rule");
}

void test_model_context_is_valid_utf8_and_not_split_at_caps() {
  std::string invalid_name = "facture-";
  invalid_name.push_back(static_cast<char>(0xff));
  invalid_name += "-été.pdf";
  const auto features = spam_engine::analyze_attachments({
      {invalid_name, "text/plain", "bonjour été"},
  });
  check(features.context.find("été.pdf") != std::string::npos,
        "valid non-ASCII filename text is preserved");
  check(features.context.find(static_cast<char>(0xff)) == std::string::npos,
        "invalid filename bytes do not reach the tokenizer");

  std::vector<spam_engine::AttachmentInput> many;
  many.reserve(spam_engine::kAttachmentMaxFiles);
  for (int i = 0; i < spam_engine::kAttachmentMaxFiles; ++i) {
    many.push_back({
        "facture-été-" + std::to_string(i) + ".txt",
        "text/plain",
        std::string(spam_engine::kAttachmentTextPerFileMaxBytes, 'a') + " été",
    });
  }
  const auto capped = spam_engine::analyze_attachments(many);
  check(capped.truncated &&
            capped.context.size() <= spam_engine::kAttachmentContextMaxBytes,
        "large multilingual context reaches the declared hard cap");
  for (std::size_t i = 0; i < capped.context.size();) {
    const auto byte = static_cast<unsigned char>(capped.context[i]);
    std::size_t width = 1;
    if (byte >= 0xc2 && byte <= 0xdf) { width = 2;
    } else if (byte >= 0xe0 && byte <= 0xef) { width = 3;
    } else if (byte >= 0xf0 && byte <= 0xf4) { width = 4;
    } else if (byte >= 0x80) {
      check(false, "capped context has no orphan UTF-8 continuation byte");
}
    check(i + width <= capped.context.size(),
          "context cap never splits a UTF-8 sequence");
    for (std::size_t continuation = 1; continuation < width; ++continuation) {
      check((static_cast<unsigned char>(capped.context[i + continuation]) & 0xc0) ==
                0x80,
            "capped context remains valid UTF-8");
    }
    i += width;
  }
}

void test_archive_reads_member_bytes_and_text() {
  const std::string zip = make_zip({
      {"nested/invoice.pdf", "#!/bin/sh\necho inert"},
      {"readme.txt", "Payment is overdue. Act today."},
      {"word/vbaProject.bin", "inert macro marker"},
  });
  const auto f = spam_engine::analyze_attachments({
      {"documents.zip", "application/zip", zip},
  });
  check(f.archive_member_count == 3, "archive members counted");
  check(f.archive_disguised_executable,
        "archive member magic defeats a harmless member extension");
  check(f.archive_dangerous_type, "archive dangerous type recorded");
  check(f.macro_document, "OOXML macro member is recorded");
  check(f.context.find("name=\"invoice.pdf\"") != std::string::npos,
        "only archive-member basename enters context");
  check(f.context.find("Payment is overdue. Act today.") != std::string::npos,
        "bounded archive text enters the joint email representation");
  check(
      f.context.find("echo inert") != std::string::npos,
      "bounded script text enters the joint representation without execution");
  check(f.context.find("nested/") == std::string::npos,
        "archive paths do not enter model context");
}

void test_archive_caps_keep_filename_and_magic_evidence() {
  const std::string oversized =
      std::string("MZ", 2) +
      std::string(spam_engine::kAttachmentArchiveEntryReadMaxBytes + 1024, 'x');
  const std::string zip = make_zip({{"invoice.pdf", oversized}});
  const auto f = spam_engine::analyze_attachments({
      {"invoice.zip", "application/zip", zip},
  });
  check(f.truncated, "oversized member reports the inspection limit");
  check(f.archive_member_count == 1, "oversized member is still counted");
  check(f.archive_dangerous_type && f.archive_disguised_executable,
        "bounded member prefix still detects executable bytes disguised as PDF");
  check(f.context.find("name=\"invoice.pdf\"") != std::string::npos &&
            f.context.find("found=pe-executable") != std::string::npos &&
            f.context.find("content-prefix-only") != std::string::npos,
        "limit result preserves member metadata, magic and prefix-only status");
}

void test_archive_does_not_advance_after_capped_final_member() {
  std::vector<std::pair<std::string, std::string>> files;
  files.reserve(spam_engine::kAttachmentArchiveMaxEntries + 1);
  for (int i = 0; i < spam_engine::kAttachmentArchiveMaxEntries - 1; ++i) {
    files.emplace_back("small-" + std::to_string(i) + ".txt", "inert");
  }
  files.emplace_back(
      "invoice.pdf",
      std::string("MZ", 2) +
          std::string(spam_engine::kAttachmentArchiveEntryReadMaxBytes + 1024,
                      'x'));
  files.emplace_back("must-not-be-probed.txt", "unread");
  const auto features = spam_engine::analyze_attachments({
      {"capped-last-member.zip", "application/zip", make_zip(files)},
  });
  check(features.truncated, "the capped 64th member is fail-visible");
  check(features.archive_member_count ==
            spam_engine::kAttachmentArchiveMaxEntries,
        "inspection stops on the capped member without advancing to entry 65");
  check(features.archive_disguised_executable,
        "the bounded prefix still contributes its deception fact");
}

void test_filename_obfuscation_and_nested_archives_are_explicit() {
  // Deliberate: this is the exact RTL-override attack (U+202E) the detector
  // exists to catch, not accidental mixed-direction text.
  const std::string bidi_name =
      // NOLINTNEXTLINE(misc-misleading-bidirectional)
      std::string("invoice.pdf.") + "\xe2\x80\xae" + "exe";
  const auto disguised = spam_engine::analyze_attachments({
      {bidi_name, "application/octet-stream", "inert"},
  });
  check(disguised.dangerous_type && disguised.disguised_executable,
        "bidi controls cannot hide a dangerous double extension");
  check(disguised.context.find("name-obfuscation") != std::string::npos,
        "filename obfuscation is explicit in the model representation");
  // NOLINTNEXTLINE(misc-misleading-bidirectional)
  check(disguised.context.find("\xe2\x80\xae") == std::string::npos,
        "bidi controls do not survive into rendered model text");

  const std::string inner = make_zip({{"run.exe", "MZ inert"}});
  const std::string outer = make_zip({{"documents.zip", inner}});
  const auto nested = spam_engine::analyze_attachments({
      {"outer.zip", "application/zip", outer},
  });
  check(nested.context.find("nested-archive") != std::string::npos,
        "one-level scanner names nested archives without recursively executing");
}

void test_non_regular_archive_entry_stops_without_hiding_its_name() {
  std::vector<char> storage(static_cast<std::size_t>(64 * 1024));
  std::size_t used = 0;
  archive *writer = archive_write_new();
  check(writer != nullptr, "archive writer allocated");
  check(archive_write_set_format_zip(writer) == ARCHIVE_OK, "ZIP format set");
  check(archive_write_open_memory(writer, storage.data(), storage.size(), &used) ==
            ARCHIVE_OK,
        "ZIP memory writer opened");
  archive_entry *entry = archive_entry_new();
  archive_entry_set_pathname(entry, "shortcut-to-invoice.pdf");
  archive_entry_set_filetype(entry, AE_IFLNK);
  archive_entry_set_symlink(entry, "elsewhere");
  archive_entry_set_perm(entry, 0777);
  check(archive_write_header(writer, entry) == ARCHIVE_OK,
        "symlink ZIP header written");
  archive_entry_free(entry);
  check(archive_write_close(writer) == ARCHIVE_OK, "ZIP writer closed");
  archive_write_free(writer);
  const std::string zip(storage.data(), used);

  const auto f = spam_engine::analyze_attachments({
      {"non-regular.zip", "application/zip", zip},
  });
  check(f.truncated, "unsupported non-regular entry is fail-visible");
  check(f.context.find("name=\"shortcut-to-invoice.pdf\"") !=
            std::string::npos &&
            f.context.find("non-regular-entry") != std::string::npos,
        "non-regular member metadata remains in the representation");
}

void test_rfc822_extractor_uses_decoded_attachment_bytes() {
  const std::string eml =
      "From: sender@example.test\r\n"
      "To: user@example.test\r\n"
      "Subject: Urgent invoice\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/mixed; boundary=x\r\n\r\n"
      "--x\r\nContent-Type: text/plain\r\n\r\nPlease pay today.\r\n"
      "--x\r\nContent-Type: application/pdf; name=invoice.pdf\r\n"
      "Content-Disposition: attachment; filename=invoice.pdf\r\n"
      "Content-Transfer-Encoding: base64\r\n\r\nTVogaW5lcnQ=\r\n"
      "--x--\r\n";
  const auto f = spam_engine::extract_attachment_features(eml);
  check(f.total_count == 1, "GMime walk finds the attachment");
  check(f.disguised_executable,
        "risk inspection sees transfer-decoded MZ bytes");

  const auto shipping = spam_engine::preprocess_rfc822(eml);
  check(shipping.attachment_features.total_count == 0,
        "ordinary public-v0 preprocessing does no attachment work");
  const auto opted_in = spam_engine::preprocess_rfc822(eml, true);
  check(opted_in.attachment_features.total_count == 1 &&
            opted_in.attachment_features.disguised_executable,
        "an explicit treatment preprocesses attachment bytes");

  std::string inline_eml = eml;
  const std::string disposition = "Content-Disposition: attachment";
  inline_eml.replace(inline_eml.find(disposition), disposition.size(),
                     "Content-Disposition: inline");
  const auto inline_features =
      spam_engine::extract_attachment_features(inline_eml);
  check(inline_features.total_count == 1 &&
            inline_features.disguised_executable,
        "a named inline payload cannot evade attachment inspection");

  inline_eml.replace(inline_eml.find("application/pdf"),
                     std::strlen("application/pdf"), "image/png");
  inline_eml.replace(inline_eml.find("TVogaW5lcnQ="),
                     std::strlen("TVogaW5lcnQ="), "iVBORw0KGgo=");
  const auto inline_image =
      spam_engine::extract_attachment_features(inline_eml);
  check(
      inline_image.total_count == 0 && inline_image.context.empty(),
      "a real inline image stays in the image representation, not attachments");

  std::string inline_svg_eml = inline_eml;
  inline_svg_eml.replace(inline_svg_eml.find("image/png"),
                         std::strlen("image/png"), "image/svg+xml");
  inline_svg_eml.replace(inline_svg_eml.find("iVBORw0KGgo="),
                         std::strlen("iVBORw0KGgo="), "PHN2Zy8+");
  const auto inline_svg =
      spam_engine::extract_attachment_features(inline_svg_eml);
  check(inline_svg.total_count == 0 && inline_svg.context.empty(),
        "legitimate inline image formats do not need a magic allowlist");

  std::string disguised_inline_image = inline_eml;
  disguised_inline_image.replace(disguised_inline_image.find("iVBORw0KGgo="),
                                  std::strlen("iVBORw0KGgo="),
                                  "TVogaW5lcnQ=");
  const auto promoted_inline =
      spam_engine::extract_attachment_features(disguised_inline_image);
  check(promoted_inline.total_count == 1 &&
            promoted_inline.disguised_executable,
        "an image-declared executable is still promoted into attachment facts");

  const std::string inline_disposition =
      "Content-Disposition: inline; filename=invoice.pdf\r\n";
  const std::size_t inline_position = inline_eml.find(inline_disposition);
  check(inline_position != std::string::npos,
        "fixture contains the inline disposition to remove");
  inline_eml.erase(inline_position, inline_disposition.size());
  const auto image_without_disposition =
      spam_engine::extract_attachment_features(inline_eml);
  check(image_without_disposition.total_count == 0 &&
            image_without_disposition.context.empty(),
        "a named body image without Content-Disposition is not double-counted");
}

void test_rfc822_attachment_count_is_bounded_before_decoding() {
  std::string eml = "From: sender@example.test\r\n"
                    "To: user@example.test\r\n"
                    "Subject: Many files\r\n"
                    "MIME-Version: 1.0\r\n"
                    "Content-Type: multipart/mixed; boundary=x\r\n\r\n";
  for (int i = 0; i < spam_engine::kAttachmentMaxFiles + 2; ++i) {
    eml += "--x\r\nContent-Type: text/plain; name=file" + std::to_string(i) +
           ".txt\r\nContent-Disposition: attachment; filename=file" +
           std::to_string(i) + ".txt\r\n\r\ninert\r\n";
  }
  eml += "--x--\r\n";
  const auto f = spam_engine::extract_attachment_features(eml);
  check(f.total_count == spam_engine::kAttachmentMaxFiles + 2,
        "all MIME attachments are counted without decoding past the file cap");
  check(f.truncated, "more than the hard attachment cap is marked truncated");
  check(f.context.find("files=" +
                       std::to_string(spam_engine::kAttachmentMaxFiles + 2)) !=
            std::string::npos,
        "the context reports the observed total, not only decoded files");
}

void test_quoted_printable_source_is_bounded_before_decoding() {
  // Soft line breaks decode to no bytes. Place an MZ signature just beyond the
  // encoded-source budget: a 3x quoted-printable allowance would materialize it
  // before truncating, while the bounded decoder must never inspect it.
  std::string encoded;
  encoded.reserve(spam_engine::kAttachmentDecodedFileMaxBytes + 32);
  for (std::size_t i = 0;
       i + 3 <= spam_engine::kAttachmentDecodedFileMaxBytes - 1; i += 3) {
    encoded += "=\r\n";
  }
  check(encoded.size() == spam_engine::kAttachmentDecodedFileMaxBytes - 1,
        "quoted-printable fixture reaches one byte below the source cap");
  encoded += "MZ inert beyond the bounded source";

  const std::string eml =
      "From: sender@example.test\r\n"
      "To: user@example.test\r\n"
      "Subject: Large quoted-printable attachment\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/mixed; boundary=x\r\n\r\n"
      "--x\r\nContent-Type: text/plain\r\n\r\ninert\r\n"
      "--x\r\nContent-Type: application/pdf; name=invoice.pdf\r\n"
      "Content-Disposition: attachment; filename=invoice.pdf\r\n"
      "Content-Transfer-Encoding: quoted-printable\r\n\r\n" +
      encoded + "\r\n--x--\r\n";
  const auto features = spam_engine::extract_attachment_features(eml);
  check(features.truncated,
        "quoted-printable source beyond the per-file cap is marked truncated");
  check(!features.disguised_executable && !features.dangerous_type,
        "bytes beyond the quoted-printable source cap are never inspected");
  check(features.total_bytes <= spam_engine::kAttachmentDecodedFileMaxBytes,
        "quoted-printable decoded bytes remain within the declared file cap");
}

void test_rfc822_mime_walk_has_a_total_node_cap() {
  std::string eml = "From: sender@example.test\r\n"
                    "To: user@example.test\r\n"
                    "Subject: Too many parts\r\n"
                    "MIME-Version: 1.0\r\n"
                    "Content-Type: multipart/mixed; boundary=x\r\n\r\n";
  for (int i = 0; i < spam_engine::kAttachmentMimeMaxParts + 20; ++i) {
    eml += "--x\r\nContent-Type: text/plain; name=file" + std::to_string(i) +
           ".txt\r\nContent-Disposition: attachment; filename=file" +
           std::to_string(i) + ".txt\r\n\r\ninert\r\n";
  }
  eml += "--x--\r\n";
  const auto features = spam_engine::extract_attachment_features(eml);
  check(features.truncated, "MIME node cap is reported as truncation");
  check(features.total_count < spam_engine::kAttachmentMimeMaxParts + 20,
        "MIME traversal stops instead of counting attacker-controlled parts forever");
}

} // namespace

int main() {
  try {
    const auto run = [](const char *name, auto test) {
      try {
        test();
      } catch (const std::exception &e) {
        throw std::runtime_error(std::string(name) + ": " + e.what());
      }
    };
    run("plain invoice", test_plain_invoice_is_context_not_a_rule);
    run("direct disguise", test_direct_disguise_and_plain_executable_are_distinct);
    run("magic precedence", test_magic_type_wins_over_declared_text);
    run("AMR signature", test_amr_signature_is_not_a_script_shebang);
    run("valid UTF-8 context", test_model_context_is_valid_utf8_and_not_split_at_caps);
    run("archive inspection", test_archive_reads_member_bytes_and_text);
    run("archive cap evidence", test_archive_caps_keep_filename_and_magic_evidence);
    run("archive final-member cap",
        test_archive_does_not_advance_after_capped_final_member);
    run("filename and nesting hardening",
        test_filename_obfuscation_and_nested_archives_are_explicit);
    run("non-regular archive entry",
        test_non_regular_archive_entry_stops_without_hiding_its_name);
    run("RFC822 extraction", test_rfc822_extractor_uses_decoded_attachment_bytes);
    run("RFC822 file cap", test_rfc822_attachment_count_is_bounded_before_decoding);
    run("quoted-printable source cap",
        test_quoted_printable_source_is_bounded_before_decoding);
    run("RFC822 MIME node cap", test_rfc822_mime_walk_has_a_total_node_cap);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "attachment_features_tests: %s\n", e.what());
    return 1;
  }
}
