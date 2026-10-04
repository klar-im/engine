#include "model_runtime.h"
#include "config.h"
#include "spam_engine_c_api.h"

#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp>

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
                                              const std::string& sender_email,
                                              bool connect_ip_blocked,
                                              bool header_ip_blocked,
                                              spam_engine_profile_t profile) {
    std::lock_guard<std::mutex> lock(mutex_);
    ClassifyResult cr;

    if (!handle_ || !loaded_) {
        cr.ok = false;
        cr.error = "model not loaded";
        return cr;
    }

    // One call (TASK-540): parse, "ensemble" scoring, and the structural fold at
    // the configured profile, the same one policy.cpp thresholds the adjusted
    // side with, so the flip marks and condemn_offset_fired describe the gate
    // the label uses. The engine applies the artifact's calibration knot itself.
    // The milter has no Message-ID DB or sender history, so those counts stay
    // zero; what it does have is the two transport facts no parse can produce
    // (TASK-113/387): who actually connected, resolved against DROP from an
    // address it OBSERVED (condemn-capable only because of that provenance), and
    // the same hit on an origin behind a trusted relay.
    spam_engine_caller_state_t caller{};
    caller.profile = profile;
    caller.connect_ip_blocked = connect_ip_blocked ? 1 : 0;
    caller.header_ip_blocked = header_ip_blocked ? 1 : 0;
    spam_engine_full_result_t full{};
    spam_engine_status_t st = spam_engine_classify_full(
        handle_,
        raw_email.data(),
        raw_email.size(),
        sender_name.c_str(),
        sender_email.c_str(),
        "ensemble",
        &caller,
        &full);

    if (st != SPAM_ENGINE_STATUS_OK) {
        cr.ok = false;
        const char* err = spam_engine_get_last_error(handle_);
        cr.error = err ? err : "classify failed";
        return cr;
    }

    cr.ok = true;
    cr.spam = full.ensemble_spam;
    cr.regular = full.neural_scores.regular;
    cr.marketing = full.neural_scores.marketing;
    cr.adjusted_spam = static_cast<float>(full.decision.adjusted_spam_side);
    cr.calibrated_spam = static_cast<float>(full.decision.calibrated_spam_side);
    cr.structural_condemn = (full.decision.condemn_offset_fired != 0);
    cr.fired_offsets = full.decision.fired_offsets;
    cr.flipped_by_offset = cr.fired_offsets.find('!') != std::string::npos;
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
    line = line.substr(start, end - start + 1);
    if (line[0] != '{') return line;

    // A MANIFEST.json: the engine's model directory carries no VERSION file,
    // and `{` is not a version. Its model_uuid is the artifact's identity
    // (engine/CLAUDE.md), so that is what X-Klar-Model-Version reports. Parsed
    // with the same library the engine reads it with (spam_engine.cpp), and
    // read again from the top since getline consumed the first line.
    f.clear();
    f.seekg(0);
    try {
        const auto doc = nlohmann::json::parse(f);
        return doc.value("model_uuid", std::string{});
    } catch (const nlohmann::json::exception&) {
        return {};
    }
}

} // namespace klar
