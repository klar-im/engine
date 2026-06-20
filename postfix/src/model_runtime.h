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
    bool ok = false;
    std::string error;
};

class ModelRuntime {
public:
    ModelRuntime();
    ~ModelRuntime();

    bool load(const Config& cfg);
    bool reload_if_needed(const Config& cfg);
    ClassifyResult classify_rfc822(const std::string& raw_email,
                                   const std::string& sender_name,
                                   const std::string& sender_email);
    std::string loaded_model_version() const;
    uint64_t generation() const;
    bool is_loaded() const;

private:
    spam_engine_handle_t* handle_ = nullptr;
    mutable std::mutex mutex_;
    std::string model_version_;
    std::atomic<uint64_t> generation_{0};
    bool loaded_ = false;

    std::string read_version_file(const std::string& path);
};

} // namespace klar
