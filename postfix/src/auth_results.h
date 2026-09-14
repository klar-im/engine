#pragma once

#include <string>

#include "config.h"

// The `auth_results = "ignore"` switch (config.h). Two entry points because the
// two binaries receive a message differently: the milter gets it header by
// header from libmilter and drops the offending ones as they arrive
// (`drops_header`); the CLI reads a whole .eml and strips them from the text
// (`strip_authentication_results`). Both answer the same question, so the
// header-name predicate is shared and there is exactly one spelling of it.

namespace klar {

// True when `cfg` says the engine must not see Authentication-Results at all.
bool ignores_auth_results(const Config& cfg);

// The headers `ignore` removes. Authentication-Results (RFC 8601) is what the
// engine parses; ARC-Authentication-Results carries the same claims one hop
// removed and is dropped with it so a forger cannot smuggle the claim under
// the ARC name. Case-insensitive, as header names are.
bool is_auth_results_header(const char* name);

// Remove every header `is_auth_results_header` matches from a raw RFC 822
// message, folded continuation lines included, and leave everything else
// byte-for-byte. The body is never touched: the scan stops at the first blank
// line. A message without such a header comes back unchanged.
std::string strip_authentication_results(const std::string& raw);

} // namespace klar
