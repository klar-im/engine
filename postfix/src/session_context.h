#pragma once
#include <chrono>
#include <string>
#include <vector>

namespace klar {

struct SessionContext {
    std::string queue_id;
    std::string mail_from;
    std::string from_header_name;   // display name from From: header
    std::string from_header_email;  // address from From: header
    std::vector<std::string> rcpt_to;
    std::string raw_rfc822;
    std::string message_id_header;
    bool truncated = false;
    uint64_t buffered_bytes = 0;
    bool bypass_due_overload = false;
    std::chrono::steady_clock::time_point started;
};

} // namespace klar
