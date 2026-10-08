#pragma once
#include <atomic>
#include <mutex>
#include <string>

#include "../../engine/spam_engine_c_api.h"  // spam_engine_profile_t, the handle

namespace klar {

struct Config;

struct ClassifyResult {
    float spam = 0;
    float regular = 0;
    float marketing = 0;
    // Spam-side confidence after the engine decision layer folds the structural
    // offsets (spam + free-host/throwaway DKIM-signer push − thread-header
    // ham bias), clamped to [0,1] — the SAME value the Apple extension thresholds on
    // (TASK-179). Drives the junk/tag decision.
    float adjusted_spam = 0;
    // Spam-side after the artifact's own calibration knot and BEFORE any offset
    // (the engine's calibrated_spam_side). This is what the bounce/reject gate
    // reads as "the content model is highly confident": model-independent
    // (every artifact's knot lands on the same 0.99 gate) and free of the
    // structural offsets, which are the reject rule's second factor and must not
    // also be its first. The raw `spam` above is per-model: a label-smoothed
    // head never reaches 0.99 raw.
    float calibrated_spam = 0;
    // True if a spam-ward structural offset fired (free-host/throwaway DKIM
    // signer). An independent strong signal the reject/bounce gate requires as
    // corroboration (TASK-179) — a destructive bounce never rides on the content
    // model alone.
    bool structural_condemn = false;
    // The fold's own account of which structural offsets fired, comma-separated,
    // "!" marking the one credited with flipping the verdict (TASK-388). Recorded
    // on the decision event so a verdict is explainable after the fact.
    std::string fired_offsets;
    // True when one of them actually changed the decision (the "!" above).
    bool flipped_by_offset = false;
    bool ok = false;
    std::string error;
};

// A recipient's own Junk corrections for this message's sender (TASK-547): the
// net count (+1 per move out of Junk, -1 per move into it) for the exact From
// address and for its domain. Handed to the engine as two caller-state fields.
struct CorrectionMemory {
    int sender = 0;
    int domain = 0;
};

// Reads that memory from the event store: (its path, recipient address, From
// address). Defined in correction_memory.cpp, which ships closed; the milter
// calls it only when cmake/closed.cmake defines KLAR_CORRECTION_MEMORY, so a
// build without the file looks nothing up and hands the engine zeros.
CorrectionMemory lookup_corrections(const std::string& event_store_path,
                                    const std::string& recipient,
                                    const std::string& from_email);

class ModelRuntime {
public:
    ModelRuntime();
    ~ModelRuntime();

    bool load(const Config& cfg);
    bool reload_if_needed(const Config& cfg);
    // `connect_ip_blocked` says the peer that opened this SMTP connection sits in
    // a DROP netblock (OriginIpBlocklist); `header_ip_blocked` says the same of an
    // origin recovered from the Received chain behind a trusted relay, which
    // carries a weaker offset (TASK-387). No defaults: the first is condemn-
    // capable, so a new call site must decide what it observed rather than
    // silently inherit "false" (TASK-113/231). `profile` is the policy in
    // force for THIS message (EffectivePolicy::engine_profile from
    // resolve_policy: the global one or the recipient domain's), handed in
    // per call rather than cached at load so a config reload or a per-domain
    // profile reaches the fold; the engine folds and marks flips at that
    // gate, the same one policy.cpp thresholds the label at (TASK-510).
    ClassifyResult classify_rfc822(const std::string& raw_email,
                                   const std::string& sender_name,
                                   const std::string& sender_email,
                                   bool connect_ip_blocked,
                                   bool header_ip_blocked,
                                   spam_engine_profile_t profile,
                                   CorrectionMemory corrections = {});
    std::string loaded_model_version() const;
    uint64_t generation() const;
    bool is_loaded() const;

private:
    spam_engine_handle_t* handle_ = nullptr;
    mutable std::mutex mutex_;
    std::string model_version_;
    std::atomic<uint64_t> generation_{0};
    bool loaded_ = false;

public:
    // The model's version string, from `model_version_file`: the first line of a
    // plain VERSION file, or `model_uuid` when the file is the engine's own
    // MANIFEST.json (its first line is `{`, which is not a version). Public and
    // static so the runtime test can pin both shapes without a model.
    static std::string read_version_file(const std::string& path);
};

} // namespace klar
