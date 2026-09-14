#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace spam_engine {

// One decoded MIME attachment. The caller owns MIME parsing and transfer-
// encoding; this layer owns byte inspection, bounded archive reading, and the
// model-facing representation. Keeping this input small lets tests exercise the
// security-sensitive code without constructing an RFC822 message.
struct AttachmentInput {
  std::string filename;
  std::string declared_mime;
  std::string payload;
  // True when MIME decoding stopped at a hard byte budget. Payload facts then
  // describe only the observed prefix and must not be presented as exhaustive.
  bool truncated = false;
  // Inline image bodies belong to the existing image representation, not the
  // attachment count. They are still byte-inspected: if an image-declared part
  // is actually a script/executable/archive, it is promoted into this context.
  bool counted_as_attachment = true;
};

// Facts shared by the model representation and the deterministic experiment.
// None is a malware verdict: they describe observable container/payload shape.
struct ExtractedAttachmentFeatures {
  int total_count = 0;
  std::uint64_t total_bytes = 0;
  int archive_member_count = 0;

  bool disguised_executable = false;
  bool archive_disguised_executable = false;
  bool dangerous_type = false;
  bool archive_dangerous_type = false;
  bool macro_document = false;
  bool encrypted_archive = false;
  bool truncated = false;
  bool parse_failed = false;

  // Bounded deterministic insertion template for an artifact that declares
  // attachment_context=true. A compact risk/count summary precedes `[Email]`;
  // sanitized filenames, type/size facts and bounded extracted text follow it.
  // The runtime inserts subject/body at that marker so verbose ZIP listings
  // cannot consume the 128-token window before the joint email signal appears.
  std::string context;
};

// Hard limits are deliberately part of the public contract so tests and the
// Python parity harness can assert them without duplicating magic numbers.
inline constexpr std::size_t kAttachmentArchiveInputMaxBytes =
    static_cast<std::size_t>(16U * 1024U * 1024U);
inline constexpr int kAttachmentMaxFiles = 64;
inline constexpr int kAttachmentMimeMaxDepth = 32;
inline constexpr int kAttachmentMimeMaxParts = 512;
inline constexpr std::size_t kAttachmentDecodedFileMaxBytes =
    static_cast<std::size_t>(16U * 1024U * 1024U);
inline constexpr std::size_t kAttachmentDecodedTotalMaxBytes =
    static_cast<std::size_t>(32U * 1024U * 1024U);
inline constexpr int kAttachmentArchiveMaxEntries = 64;
inline constexpr std::size_t kAttachmentArchiveEntryReadMaxBytes =
    static_cast<std::size_t>(1024U * 1024U);
inline constexpr std::size_t kAttachmentArchiveTotalReadMaxBytes =
    static_cast<std::size_t>(4U * 1024U * 1024U);
inline constexpr std::size_t kAttachmentContextMaxBytes = 8192;
inline constexpr std::size_t kAttachmentTextPerFileMaxBytes = 2048;

ExtractedAttachmentFeatures
analyze_attachments(const std::vector<AttachmentInput> &attachments,
                    int observed_count = -1, bool collection_truncated = false);

} // namespace spam_engine
