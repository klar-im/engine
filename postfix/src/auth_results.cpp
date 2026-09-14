#include "auth_results.h"

#include <strings.h>

#include <string_view>

namespace klar {

bool ignores_auth_results(const Config& cfg) {
    return cfg.auth_results == "ignore";
}

bool is_auth_results_header(const char* name) {
    if (!name) return false;
    return strcasecmp(name, "Authentication-Results") == 0 ||
           strcasecmp(name, "ARC-Authentication-Results") == 0;
}

std::string strip_authentication_results(const std::string& raw) {
    std::string out;
    out.reserve(raw.size());
    size_t pos = 0;
    bool dropping = false;
    while (pos < raw.size()) {
        size_t eol = raw.find('\n', pos);
        const size_t next = (eol == std::string::npos) ? raw.size() : eol + 1;
        const std::string_view line(raw.data() + pos, next - pos);
        // End of the header block: the body follows verbatim.
        if (line == "\r\n" || line == "\n") {
            out.append(raw, pos, std::string::npos);
            return out;
        }
        const bool continuation = line[0] == ' ' || line[0] == '\t';
        if (continuation) {
            if (!dropping) out.append(line);
        } else {
            const size_t colon = line.find(':');
            std::string name(colon == std::string_view::npos ? std::string_view() : line.substr(0, colon));
            dropping = !name.empty() && is_auth_results_header(name.c_str());
            if (!dropping) out.append(line);
        }
        pos = next;
    }
    return out;
}

} // namespace klar
