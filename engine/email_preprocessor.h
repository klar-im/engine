#pragma once

#include <string>
#include <vector>

namespace spam_engine {

// Structural conversation-thread signals. GMime extracts and unfolds the
// headers; brackets are stripped from Message-IDs. Used by the Swift
// classifier as a soft ham bias when an inbound message looks like a reply.
struct ExtractedThreadFeatures {
  bool        has_in_reply_to = false;
  int         references_count = 0;
  std::string in_reply_to;       // first <…> ID, brackets stripped
  std::string first_reference;   // first ID from References:, brackets stripped
  std::string self_message_id;   // own Message-ID:, brackets stripped (for Phase 2 DB)
};

// Sender-authentication signals parsed from the receiving MTA's topmost
// Authentication-Results header (the one our trusted hop added — a spammer can
// inject lower A-R headers but not the top). The DKIM *signing domain*
// (header.d / header.i) is the domain that cryptographically signed the
// message: unforgeable, unlike a From-header suffix. The Swift
// SenderAuthClassifier uses it as a soft decision-layer offset — a free-hosting
// signer (firebaseapp.com etc.) is a near-zero-ham spam prior (measured 0/500
// ham), measured on a held-out ham/spam corpus.
struct ExtractedAuthFeatures {
  // org-domain (eTLD+1, lowercased) the message's DKIM signature asserts; empty
  // if there is no dkim=pass result in the top Authentication-Results header.
  std::string dkim_signing_domain;
  // Full signing FQDN (lowercased, pre-org-reduction) — the shape the
  // throwaway-signer check reads (jjlw.how.populag.org.es).
  std::string dkim_signing_fqdn;
  // org-domain of the From: address, lowercased.
  std::string from_org_domain;
  // dmarc=pass AND the DKIM signing org-domain == the From org-domain. Note:
  // alignment alone is NOT a legitimacy signal (spammers align throwaway
  // domains — see TASK-170); surfaced for the reputation-gated ham rescue.
  bool        dmarc_aligned = false;
  // The signing FQDN has the throwaway shape: >= 2 labels below its
  // org-domain, every one machine-generated (short / digit-bearing /
  // vowel-free, and neither a common mail-infra word nor ESP fleet-numbering
  // like mail56/atl71). Phish campaigns sign with such domains and
  // DMARC-align them, so no alignment or free-host rule catches them.
  // Measured 23/556 spam, 0/500 ham (TASK-178); kept in sync with the
  // offline reference implementation.
  bool        signer_throwaway = false;
  // The From DISPLAY NAME claims a distinctive Tranco brand the From org-domain
  // is NOT (e.g. display "Scaleway", From depilacionlasercanarias.com) — the
  // display-name impersonation tell. Precision-first (dictionary-filtered brand
  // names): measured 0/51 ham FP, catches the Scaleway/LeroyMerlin phish
  // (TASK-214). Kept in sync with the Swift mirror.
  bool        display_impersonation = false;
};

// Structural body-URL signals for the decision layer (TASK-257). Only the
// freshness-independent, structurally-safe one is surfaced: raw_ip_url. Its
// two siblings (url_shortener, shared_bare_cdn) were built + ablated and NOT
// wired: a bare-IP host is ~never legit (0/56 ham, structural), whereas
// shortener wrappers (t.co/lnkd.in) and shared CDNs (S3/imgur/googleapis) carry
// real legit mail, so their clean corpus rate was sample-luck. See the block in
// decision_layer.h and pythonDiscovery/scripts/measure_url_structure.py.
struct ExtractedUrlFeatures {
  // A body link whose host is a bare IPv4 (or IPv6) literal: legit senders use
  // domain names, so this is a textbook phishing tell. IPv4 is the covered case;
  // IPv6 literals are rare and best-effort (the shared host_from_url port-strip
  // mangles bracketed forms).
  bool raw_ip_url = false;
};

struct PreprocessedEmail {
  std::string subject;
  std::string from;
  std::string plain_body_text;
  std::string html_body_text;
  std::string normalized_plain_text;
  std::string normalized_html_text;
  std::string body_text;
  std::string normalized_text;
  // True if the message has a Reply-To header that differs from the From
  // header. Common spam pattern (legitimate senders rarely need to differ).
  // Surfaced via CustomerInfo so the head can learn from it; see
  // engine/PARITY_PLAN.md for the full list of planned signals.
  bool replyto_differs = false;
  // Recipient identifiers (To/Cc/Bcc/Delivered-To/Envelope-To/X-Original-To
  // addresses, their local-parts, and display-name tokens), lower-cased. Used
  // ONLY to redact the recipient's own identity from the flywheel contribution
  // body (PII scrub) — never for classification.
  std::vector<std::string> recipient_tokens;
  // Structural thread + sender-auth signals, computed from the SAME GMime parse
  // (TASK-173 — no separate re-parse). classify_rfc822 surfaces these on its
  // result so the Swift decision layer reads them off the ML call instead of
  // re-parsing the message two more times.
  ExtractedThreadFeatures thread_features;
  ExtractedAuthFeatures   auth_features;
  ExtractedUrlFeatures    url_features;
};

// For ML classification: extracts and normalizes text content.
PreprocessedEmail preprocess_rfc822(const std::string& raw_rfc822);

// For display: extracts raw HTML body without text conversion.
struct ExtractedEmailBody {
  std::string html_body;       // Raw HTML content (empty if no HTML part)
  std::string plain_body;      // Raw plain text content
  std::string subject;         // Decoded subject header
  std::string from;            // Decoded from header
  std::string text_preview;    // Plain text for preview (plain_body or html-to-text)
  std::string date;            // RFC2822 date header value
};

ExtractedEmailBody extract_email_body(const std::string& raw_rfc822);

// Standalone parse-and-extract entry points (used by the C ABI and its tests).
// The classification hot path does NOT call these — preprocess_rfc822 computes
// the same features from its own parse (TASK-173). Both share the internal
// *_from_message cores so the extraction logic stays single-sourced.
ExtractedThreadFeatures extract_thread_features(const std::string& raw_rfc822);
ExtractedAuthFeatures extract_auth_features(const std::string& raw_rfc822);
ExtractedUrlFeatures extract_url_features(const std::string& raw_rfc822);

// True if `host` is a bare IP literal: an IPv4 dotted quad (each octet 0-255) or
// an IPv6 literal (contains ':' and only hex/':'). Exposed for the offset unit
// test. Not for a hostname that merely contains digits (192.example.com is false).
bool host_is_ip_literal(const std::string& host);

// Distinct eTLD+1 domains of every http(s) URL in the message body (plain +
// HTML), lowercased + deduped. Foundation for the link/domain reputation
// signal (TASK-201): org_domain() reduces a per-subdomain phishing host
// (login.evil.web.app) to its registrable domain (web.app), the key a bundled
// SURBL/URIBL-style blocklist matches on. Pure extraction — no list lookup.
std::vector<std::string> extract_url_domains(const std::string& raw_rfc822);

// Same, but from already-extracted body parts — lets the classification hot path
// reuse its single GMime parse (preprocess_rfc822 keeps plain_body_text /
// html_body_text) instead of re-parsing, when the URL-reputation offset wires in.
std::vector<std::string> url_domains_from_bodies(const std::string& plain_body,
                                                 const std::string& html_body);

// Convert HTML to plain text (strips tags, decodes entities).
std::string html_to_text(const std::string& html);

// Registrable href domains of every <a ...> in a raw HTML body, in document
// order ("" for a non-http/mailto target). Exposed so tests can assert the
// anchor parser resolves the TRUE href even when a decoy attribute (hreflang,
// data-href) precedes it (C8, TASK-251); the classify path reads the richer
// AnchorPair form internally.
std::vector<std::string> anchor_href_domains(const std::string& html);

// Registrable action domains of every <form> that contains a password input in
// a raw HTML body (the credential-harvest phish signal). Exposed for tests
// (C8, TASK-251).
std::vector<std::string> credential_form_action_domains(const std::string& html);

}  // namespace spam_engine
