#pragma once
#include <atomic>
#include <mutex>
#include <string>

// Forward declare - we include the C header in .cpp only
typedef struct spam_engine_handle spam_engine_handle_t;

namespace klar {

struct Config;

struct ClassifyResult {
    float spam = 0;
    float regular = 0;
    float marketing = 0;
    float gibberish = 0;
    // Spam-side confidence after the engine decision layer folds the structural
    // offsets (spam+gibberish + free-host/throwaway DKIM-signer push − thread-header
    // ham bias), clamped to [0,1] — the SAME value the Apple extension thresholds on
    // (TASK-179). Drives the junk/tag decision; the raw `spam` above still drives the
    // bounce/reject gate so a structural prior never bounces mail.
    float adjusted_spam = 0;
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
    // silently inherit "false" (TASK-113/231).
    ClassifyResult classify_rfc822(const std::string& raw_email,
                                   const std::string& sender_name,
                                   const std::string& sender_email,
                                   bool connect_ip_blocked,
                                   bool header_ip_blocked);
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
