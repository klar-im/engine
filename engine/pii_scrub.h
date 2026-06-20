#pragma once

#include <string>
#include <vector>

namespace spam_engine {

// On-device PII scrub for the data-flywheel contribution path (TASK-135).
//
// GMime (email_preprocessor) has already done the structural work before this
// runs: attachments and inline images are excluded from the body, and real
// headers (To/Cc/Received/…) are split off — they never enter the body text fed
// to feature extraction. So the ONLY PII that can still reach the hashed
// contribution bag lives *inside the decoded body text*:
//   1. quoted/forwarded header lines (a forwarded message's `To:`/`Received:`
//      reproduced as body text), and
//   2. inline `data:` URIs (base64 images embedded in HTML).
//
// `scrub_body_text` redacts (1) — fold-aware, and only when the line actually
// carries contact PII (an email address or an IPv4), so ordinary prose like
// "To: buy milk" is preserved as spam signal — and strips (2). It is
// self-contained (no GMime, no model state) so it unit-tests against the strip
// table directly and runs identically for every engine client.
//
// `recipient_tokens` (lower-cased; from the parsed To/Cc/Bcc/Delivered-To… of
// THIS message — see PreprocessedEmail) are redacted wherever they appear in the
// body: the recipient's own address, local-part, and name leak via greetings
// ("Dear Jane"), footers, and tracking links, and generic patterns can't know
// which name is the recipient's. Beyond those, the scrub also removes generic
// email addresses (keeping the domain), URL-embedded identifiers, phone numbers,
// IPv6 literals, and Luhn-valid card numbers.
std::string scrub_body_text(const std::string& body,
                            const std::vector<std::string>& recipient_tokens = {});

}  // namespace spam_engine
