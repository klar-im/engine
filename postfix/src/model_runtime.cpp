#include "model_runtime.h"
#include "config.h"
#include "spam_engine_c_api.h"

#include <fstream>
#include <sstream>

namespace klar {

ModelRuntime::ModelRuntime() {
    handle_ = spam_engine_create();
}

ModelRuntime::~ModelRuntime() {
    if (handle_) {
        if (loaded_) {
            spam_engine_unload(handle_);
        }
        spam_engine_destroy(handle_);
        handle_ = nullptr;
    }
}

bool ModelRuntime::load(const Config& cfg) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!handle_) return false;

    spam_engine_status_t st = spam_engine_load(
        handle_,
        cfg.model_dir.c_str(),
        /*learning_rate=*/0.0f,
        /*ftrl_path=*/nullptr);

    if (st != SPAM_ENGINE_STATUS_OK) {
        loaded_ = false;
        return false;
    }

    loaded_ = true;
    model_version_ = read_version_file(cfg.model_version_file);
    generation_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

bool ModelRuntime::reload_if_needed(const Config& cfg) {
    std::string new_version = read_version_file(cfg.model_version_file);

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (new_version.empty() || new_version == model_version_) {
            return false;
        }
    }

    // Version changed: unload and reload
    std::lock_guard<std::mutex> lock(mutex_);

    // Re-check under lock
    if (new_version == model_version_) return false;

    if (loaded_) {
        spam_engine_unload(handle_);
        loaded_ = false;
    }

    spam_engine_status_t st = spam_engine_load(
        handle_,
        cfg.model_dir.c_str(),
        /*learning_rate=*/0.0f,
        /*ftrl_path=*/nullptr);

    if (st != SPAM_ENGINE_STATUS_OK) {
        return false;
    }

    loaded_ = true;
    model_version_ = new_version;
    generation_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

ClassifyResult ModelRuntime::classify_rfc822(const std::string& raw_email,
                                              const std::string& sender_name,
                                              const std::string& sender_email) {
    std::lock_guard<std::mutex> lock(mutex_);
    ClassifyResult cr;

    if (!handle_ || !loaded_) {
        cr.ok = false;
        cr.error = "model not loaded";
        return cr;
    }

    spam_engine_result_t result{};
    // Capture the structural signals from the SAME parse (TASK-173) so the
    // decision layer below can fold them — the milter no longer ships the raw
    // verdict alone (TASK-179).
    spam_engine_parsed_signals_t signals{};
    // "ensemble": neural head + low-weight FTRL blend, then the structural
    // decision layer below (TASK-219; mode is now a required C-API arg).
    spam_engine_status_t st = spam_engine_classify_rfc822(
        handle_,
        raw_email.data(),
        raw_email.size(),
        sender_name.c_str(),
        sender_email.c_str(),
        "ensemble",
        &result,
        &signals);

    if (st != SPAM_ENGINE_STATUS_OK) {
        cr.ok = false;
        const char* err = spam_engine_get_last_error(handle_);
        cr.error = err ? err : "classify failed";
        return cr;
    }

    cr.ok = true;
    cr.spam = result.scores.spam;
    cr.regular = result.scores.regular;
    cr.marketing = result.scores.marketing;
    cr.gibberish = result.scores.gibberish;

    // Decision layer (TASK-179): fold the structural offsets onto the spam side,
    // exactly as the Apple extension does, so the milter's junk decision agrees.
    // The engine-derived signals (thread headers, free-host/throwaway DKIM signer)
    // come from `signals`; the local-state offsets (Message-ID DB, sender history)
    // aren't available to the milter, so they're zero. We read only the adjusted
    // spam-side (profile-independent); policy.cpp applies the milter's own threshold.
    // Shared builder fills scores + argmax label + the parsed-signal fields; the
    // milter has no local Message-ID DB or sender history, so the caller-state
    // counts stay zero from the value-init (TASK-231).
    spam_engine_decision_input_t din{};
    spam_engine_decision_input_from_signals(&din, &result.scores, &signals);
    din.profile = SPAM_ENGINE_PROFILE_STANDARD;

    spam_engine_decision_result_t dout{};
    if (spam_engine_decide(&din, &dout) == SPAM_ENGINE_STATUS_OK) {
        cr.adjusted_spam = static_cast<float>(dout.adjusted_spam_side);
        cr.structural_condemn = (dout.condemn_offset_fired != 0);
    } else {
        // Defensive: fall back to the bare spam-side (spam+gibberish) if the fold
        // somehow fails — never worse than the pre-TASK-179 behaviour.
        cr.adjusted_spam = result.scores.spam + result.scores.gibberish;
        cr.structural_condemn = false;
    }
    return cr;
}

std::string ModelRuntime::loaded_model_version() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return model_version_;
}

uint64_t ModelRuntime::generation() const {
    return generation_.load(std::memory_order_relaxed);
}

bool ModelRuntime::is_loaded() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return loaded_;
}

std::string ModelRuntime::read_version_file(const std::string& path) {
    if (path.empty()) return {};

    std::ifstream f(path);
    if (!f.is_open()) return {};

    std::string line;
    if (!std::getline(f, line)) return {};

    // Trim whitespace
    auto start = line.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    auto end = line.find_last_not_of(" \t\r\n");
    return line.substr(start, end - start + 1);
}

} // namespace klar
