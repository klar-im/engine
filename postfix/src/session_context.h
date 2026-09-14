#pragma once
#include <chrono>
#include <string>
#include <vector>

namespace klar {

struct SessionContext {
    // Textual address of the peer that opened this SMTP connection, as the MTA
    // observed it ("" for a unix socket or an unknown family). Per-CONNECTION,
    // so unlike the fields below it survives xxfi_envfrom's per-message reset.
    std::string connect_ip;
    // Received lines in header order, topmost first — the order libmilter
    // delivers them, and the order the trust walk depends on (TASK-387).
    // Per-MESSAGE, so xxfi_envfrom clears it.
    std::vector<std::string> received;
    std::string queue_id;
    std::string mail_from;
    std::string from_header_name;   // display name from From: header
    std::string from_header_email;  // address from From: header
    std::vector<std::string> rcpt_to;
    std::string raw_rfc822;
    std::string message_id_header;
    // cfg.auth_results == "ignore", latched per message in xxfi_envfrom so a
    // SIGHUP mid-message cannot strip half the headers and keep the other half.
    bool drop_auth_results = false;
    bool truncated = false;
    uint64_t buffered_bytes = 0;
    bool bypass_due_overload = false;
    std::chrono::steady_clock::time_point started;
};

} // namespace klar
