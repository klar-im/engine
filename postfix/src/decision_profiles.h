#pragma once

#include <cstddef>
#include <string>

#include "../../engine/decision_layer.h"
#include "../../engine/spam_engine_c_api.h"

// The three profile names every server-side integration exposes (postfix/
// milter, spamd/ daemon), mapped onto the ENGINE's profile. Nothing numeric
// lives here: ONE name table (`kProfileNames`), and the threshold is the
// engine's own `threshold_for_profile` over the engine's own enum, so a name
// cannot fold at one gate and print another. The three `kThreshold*` constants
// in engine/decision_layer.h are the product's numbers (mirrored in
// FilteringProfileSetting.swift, sender_utils.py and the Allium spec, all
// pinned by model-lab/test_decision_layer_sync.py, which also refuses a
// threshold literal in postfix/src, spamd/src or integrations/).
//
// Until 2026-09-18 this header returned 0.70 / 0.50 / 0.30, a table from the
// milter's first commit that predated the calibration knot and the 0.99 gate
// every offset is pinned to. The milter applied it to the same calibrated,
// offset-adjusted spam side the Mac app gates at 0.99, so it junked what the
// app delivers: on klar.im 424 of 694 spam labels over five days sat between
// 0.50 and 0.99 with no rule fired, a reply to the user's own mail among
// them (adjusted 0.78; TASK-510). A consumer that embeds a threshold is a
// check that embeds the other side.
//
// Lives here, not in engine/, on purpose: engine/ARCHITECTURE.md's boundary
// ("Host integrations consume the engine via the C ABI in
// spam_engine_c_api.h") is about the engine's own model/decision surface.
// This is two integrations sharing a name table, so it stays under postfix/,
// which already has exactly one other consumer (spamd/), the same reasoning
// spamd/scripts/setup.sh uses to call postfix/scripts/ensure_engine_artifacts.sh.
// decision_layer.h is header-only and published (engine/publish/allowlist.txt),
// so including it links nothing.
namespace klar {

struct ProfileName {
    const char* name;
    spam_engine_profile_t engine;
};

// The names a config may carry, in the order the docs list them. "standard"
// is also what an unknown or empty name resolves to (profile_to_engine).
inline constexpr ProfileName kProfileNames[] = {
    {"cautious", SPAM_ENGINE_PROFILE_CAUTIOUS},
    {"standard", SPAM_ENGINE_PROFILE_STANDARD},
    {"aggressive", SPAM_ENGINE_PROFILE_AGGRESSIVE},
};

inline bool is_valid_profile(const std::string& profile) {
    for (const ProfileName& p : kProfileNames) {
        if (profile == p.name) return true;
    }
    return false;
}

inline spam_engine_profile_t profile_to_engine(const std::string& profile) {
    for (const ProfileName& p : kProfileNames) {
        if (profile == p.name) return p.engine;
    }
    return SPAM_ENGINE_PROFILE_STANDARD;
}

// The C ABI enum is the C++ enum by value (spam_engine_c_api.cpp maps them
// one to one), so the threshold is one cast into the engine's own table.
// The asserts hold the two enums together; a profile added to one side
// without the other fails to compile here rather than folding at a wrong gate.
namespace detail {
using EngineProfile = spam_engine::decision::Profile;
static_assert(static_cast<int>(EngineProfile::Standard) == SPAM_ENGINE_PROFILE_STANDARD);
static_assert(static_cast<int>(EngineProfile::Cautious) == SPAM_ENGINE_PROFILE_CAUTIOUS);
static_assert(static_cast<int>(EngineProfile::Learning) == SPAM_ENGINE_PROFILE_LEARNING);
static_assert(static_cast<int>(EngineProfile::Aggressive) == SPAM_ENGINE_PROFILE_AGGRESSIVE);
}  // namespace detail

inline double profile_to_threshold(spam_engine_profile_t profile) {
    return spam_engine::decision::threshold_for_profile(static_cast<detail::EngineProfile>(profile));
}

} // namespace klar
