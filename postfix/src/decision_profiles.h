#pragma once

#include <string>

// Single-owned fact shared by every server-side integration that exposes the
// cautious/standard/aggressive profile knob (postfix/ milter, spamd/ daemon).
// Do not hardcode these three floats a second time — extend this header and
// both consumers pick it up. See repo CLAUDE.md: "generate rather than
// duplicate where the fact has a single owner."
//
// Lives here, not in engine/, on purpose: engine/ARCHITECTURE.md's boundary
// ("Host integrations consume the engine via the C ABI in
// spam_engine_c_api.h") is about the engine's own model/decision surface.
// This header has nothing to do with the engine's internals — it is two
// integrations sharing a constant table — so it does not belong inside the
// directory that boundary protects (code-review finding, 2026-09-07). Placed
// under postfix/ rather than a new top-level directory because it already
// has exactly one other consumer (spamd/), the same reasoning
// spamd/scripts/setup.sh uses to call postfix/scripts/ensure_engine_artifacts.sh
// directly instead of duplicating it.
namespace klar {

inline double profile_to_threshold(const std::string& profile) {
    if (profile == "cautious") {
        return 0.70;
    }
    if (profile == "standard") {
        return 0.50;
    }
    if (profile == "aggressive") {
        return 0.30;
    }
    return 0.50; // fallback
}

inline bool is_valid_profile(const std::string& profile) {
    return profile == "cautious" || profile == "standard" || profile == "aggressive";
}

} // namespace klar
