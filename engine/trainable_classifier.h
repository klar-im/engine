#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
// Anchor-set content fingerprint for the function-space trust region
// (TASK-193 AC#8/#9) -- already linked via ftrl_classifier.h's identical
// include, so this adds no new dependency.
#define XXH_INLINE_ALL
#include <xxhash.h>

using nlohmann::json;

class TrainableClassifierHead {
public:
    // L2 regularization toward original weights prevents catastrophic forgetting.
    // lr=0.0001, l2=0.1, max_grad_norm=1.0: balances learning vs forgetting.
    //
    // max_drift_steps is a hard trust region around the frozen origin weights:
    // after each update every tensor is projected back so ‖w - w0‖ stays within
    // a budget of `max_drift_steps` OPTIMIZER UPDATES' worth of movement. One
    // RFC822 correction can produce two updates when its plain and HTML bodies
    // differ. The soft L2
    // anchor is only a *pull*, which Adam's momentum overpowers under a one-sided
    // correction stream (30 ham / 0 spam in a row), walking the spam/regular
    // boundary across the borderline cluster until a whole class collapses. The
    // cap turns that into a saturating bound (TASK-193).
    //
    // The unit is load-bearing and it used to be wrong. The budget was
    // `max_drift * ‖w0‖`, a fraction of the SHIPPED WEIGHTS' norm — but what it
    // has to bound is an Adam step, and Adam's step norm is `lr * sqrt(n)`,
    // set by the PARAMETER COUNT and not by the weights. The two have no fixed
    // relationship, so one scalar meant four different things across the head's
    // four tensors, and something else again on every new model. Measured on the
    // shipped Gen 3 head at the shipped max_drift = 0.006 (TASK-417):
    //
    //     tensor              n      ‖w0‖   adam step   budget   IN STEPS
    //     dense_weight   589824    15.429     0.07680  0.09258       1.21
    //     dense_bias        768     0.040     0.00277  0.00024       0.09
    //     out_proj_weight  3072     1.167     0.00554  0.00700       1.26
    //     out_proj_bias       4     0.004     0.00020  0.00002       0.12
    //
    // A budget below one step means the projection undoes each correction before
    // the next one arrives: not a trust region, an off switch, and 8x tighter on
    // the biases for no reason other than that a bias vector has a small norm.
    // Expressed in steps the bound means the same thing for every tensor and
    // survives a change of encoder.
    //
    // The immutable origin is persisted with every personalized snapshot. If it
    // were silently reset to the current weights on reload, each training batch
    // would receive a fresh trust region and the lifetime cap would not be a cap.
    // function_space_anchor_path: empty disables the mechanism entirely (the
    // existing weight-space project_to_trust_region below runs unchanged).
    // Non-empty loads a flat binary file of anchor_count * hidden_size floats
    // (row-major per anchor) and switches every subsequent step() to the
    // function-space projection instead of the weight-space one.
    // The adjacent floats mirror persisted scalar config fields. Moving them
    // behind an options object is a separate API and serialization migration.
    explicit TrainableClassifierHead(const std::string& model_dir,
                            float learning_rate = 0.0001F,  // NOLINT(bugprone-easily-swappable-parameters)
                            float l2_lambda = 0.1F,
                            float max_grad_norm = 1.0F,
                            float max_drift_steps = 30.0F,
                            const std::string& function_space_anchor_path = "",
                            float function_space_budget = 0.0F)
        : learning_rate_(learning_rate), l2_lambda_(l2_lambda),
          max_grad_norm_(max_grad_norm), max_drift_steps_(max_drift_steps) {
        std::ifstream config_file(model_dir + "/classifier_config.json");
        json config;
        config_file >> config;

        hidden_size_ = config["hidden_size"];
        num_labels_ = config["num_labels"];
        source_model_ = config.value("source_model", "");
        const std::string& source_model = source_model_;
        const std::string input_format = config.value(
            "input_format",
            // This exact historical Gen 3 object predates the field and was
            // already published under an immutable UUID. Its engine used raw
            // input globally. Do not rewrite the remote config to retrofit the
            // declaration; all new artifacts must declare it explicitly.
            source_model == "klar/e5-base-ft-markers-gen3"
                ? "raw" : "legacy_wrapped");
        if (input_format == "raw") {
            uses_raw_input_ = true;
        } else if (input_format == "legacy_wrapped") {
            uses_raw_input_ = false;
        } else {
            throw std::runtime_error(
                "classifier_config.json: input_format must be raw or legacy_wrapped");
        }
        if (config.contains("structural_markers") &&
            !config["structural_markers"].is_boolean()) {
            throw std::runtime_error(
                "classifier_config.json: structural_markers must be boolean");
        }
        uses_structural_markers_ = config.value(
            "structural_markers",
            // This immutable historical object was trained with markers before
            // the property existed. New artifacts declare the choice explicitly.
            source_model == "klar/e5-base-ft-markers-gen3");
        if (config.contains("attachment_context") &&
            !config["attachment_context"].is_boolean()) {
            throw std::runtime_error(
                "classifier_config.json: attachment_context must be boolean");
        }
        uses_attachment_context_ = config.value("attachment_context", false);

        // Where THIS artifact's spam side sits, so the decision layer can map it
        // onto the product's fixed Standard gate instead of moving the gate and
        // disarming every condemn-capable offset. Absent means the identity map,
        // which is what public-v0 has always had. See decision_layer.h
        // calibrate_spam_side and HOW_TO_TRAIN_A_MODEL.md "Move the score, not
        // the gate".
        if (config.contains("spam_side_calibration_knot")) {
            if (!config["spam_side_calibration_knot"].is_number()) {
                throw std::runtime_error(
                    "classifier_config.json: spam_side_calibration_knot must be a number");
            }
            spam_side_calibration_knot_ =
                config["spam_side_calibration_knot"].get<double>();
            // A knot outside (0,1) cannot describe a point on a spam side, and
            // silently treating it as "undeclared" would ship an artifact whose
            // calibration was quietly ignored.
            if (!(spam_side_calibration_knot_ > 0.0) ||
                !(spam_side_calibration_knot_ < 1.0)) {
                throw std::runtime_error(
                    "classifier_config.json: spam_side_calibration_knot must be "
                    "strictly between 0 and 1");
            }
        }

        // classifier_config.json is model-supplied; reject implausible dims
        // before they drive allocations and loop bounds (int overflow in
        // hidden_size_*hidden_size_, or OOB indexing on a too-small num_labels_).
        if (hidden_size_ <= 0 || hidden_size_ > 8192 ||
            num_labels_ <= 0 || num_labels_ > 64) {
            throw std::runtime_error(
                "classifier_config.json: implausible hidden_size/num_labels");
        }

        if (!config.contains("label_map") || !config["label_map"].is_object()) {
            throw std::runtime_error(
                "classifier_config.json: label_map is required");
        }
        label_names_.resize(num_labels_);
        for (int i = 0; i < num_labels_; ++i) {
            const std::string key = std::to_string(i);
            if (!config["label_map"].contains(key) ||
                !config["label_map"][key].is_string()) {
                throw std::runtime_error(
                    "classifier_config.json: label_map must name every output index");
            }
            label_names_[i] = config["label_map"][key].get<std::string>();
            if (label_names_[i].empty() ||
                std::count(label_names_.begin(), label_names_.begin() + i,
                           label_names_[i]) != 0) {
                throw std::runtime_error(
                    "classifier_config.json: label names must be non-empty and unique");
            }
        }
        for (const std::string& required : {"marketing", "regular", "spam"}) {
            if (label_index(required) < 0) {
                throw std::runtime_error(
                    "classifier_config.json: missing required label " + required);
            }
        }

        dense_weight_.resize(static_cast<size_t>(hidden_size_) * hidden_size_);
        dense_bias_.resize(hidden_size_);
        out_proj_weight_.resize(static_cast<size_t>(num_labels_) * hidden_size_);
        out_proj_bias_.resize(num_labels_);

        load_binary(model_dir + "/classifier_dense_weight.bin", dense_weight_);
        load_binary(model_dir + "/classifier_dense_bias.bin", dense_bias_);
        load_binary(model_dir + "/classifier_out_proj_weight.bin", out_proj_weight_);
        load_binary(model_dir + "/classifier_out_proj_bias.bin", out_proj_bias_);

        load_or_initialize_anchor(model_dir);

        if (!function_space_anchor_path.empty() && function_space_budget > 0.0F) {
            // Set before loading: load_function_space_anchor's post-load check
            // needs function_space_budget_ already in place (codex review,
            // 2026-08-29 -- see that method's comment on migrated snapshots).
            function_space_budget_ = function_space_budget;
            function_space_enabled_ = true;
            load_function_space_anchor(function_space_anchor_path, model_dir);
        }

        // Initialize gradient accumulators
        dense_weight_grad_.resize(dense_weight_.size(), 0.0F);
        dense_bias_grad_.resize(dense_bias_.size(), 0.0F);
        out_proj_weight_grad_.resize(out_proj_weight_.size(), 0.0F);
        out_proj_bias_grad_.resize(out_proj_bias_.size(), 0.0F);

        // For Adam optimizer
        dense_weight_m_.resize(dense_weight_.size(), 0.0F);
        dense_weight_v_.resize(dense_weight_.size(), 0.0F);
        dense_bias_m_.resize(dense_bias_.size(), 0.0F);
        dense_bias_v_.resize(dense_bias_.size(), 0.0F);
        out_proj_weight_m_.resize(out_proj_weight_.size(), 0.0F);
        out_proj_weight_v_.resize(out_proj_weight_.size(), 0.0F);
        out_proj_bias_m_.resize(out_proj_bias_.size(), 0.0F);
        out_proj_bias_v_.resize(out_proj_bias_.size(), 0.0F);
    }

    // Forward pass with caching for backprop
    std::vector<float> forward(const std::vector<float>& cls_embedding, bool cache_for_backward = false) {
        // Self-guard the sharp edge: the loops below index cls_embedding[j] for
        // j in [0, hidden_size_). One comparison against an O(hidden_size^2) loop
        // keeps any direct caller (not just SpamEngine's boundary check) from an
        // OOB heap read; backward() reuses the cached copy, so it is covered too
        // (C4, TASK-251).
        if (cls_embedding.size() < static_cast<size_t>(hidden_size_)) {
            throw std::invalid_argument(
                "TrainableClassifierHead::forward: embedding shorter than hidden_size");
        }
        if (cache_for_backward) {
            cached_input_ = cls_embedding;
            cached_hidden_pre_activation_.resize(hidden_size_);
            cached_hidden_.resize(hidden_size_);
        }

        // Dense layer: hidden_size -> hidden_size
        std::vector<float> hidden(hidden_size_);
        for (int i = 0; i < hidden_size_; ++i) {
            float sum = dense_bias_[i];
            for (int j = 0; j < hidden_size_; ++j) {
                sum += cls_embedding[j] * dense_weight_[(i * hidden_size_) + j];
            }
            if (cache_for_backward) {
                cached_hidden_pre_activation_[i] = sum;
            }
            // Tanh activation
            hidden[i] = std::tanh(sum);
            if (cache_for_backward) {
                cached_hidden_[i] = hidden[i];
            }
        }

        // Output projection: hidden_size -> num_labels
        std::vector<float> logits(num_labels_);
        for (int i = 0; i < num_labels_; ++i) {
            float sum = out_proj_bias_[i];
            for (int j = 0; j < hidden_size_; ++j) {
                sum += hidden[j] * out_proj_weight_[(i * hidden_size_) + j];
            }
            logits[i] = sum;
        }

        if (cache_for_backward) {
            cached_logits_ = logits;
        }

        return logits;
    }

    // The artifact's own declaration of what it is. Reported through the C ABI so
    // a caller can say which model produced a verdict; answering that used to mean
    // hashing files on the host and comparing them against every UUID on S3.
    [[nodiscard]] int hidden_size() const noexcept { return hidden_size_; }
    [[nodiscard]] const std::string& source_model() const noexcept { return source_model_; }

    [[nodiscard]] bool uses_raw_input() const noexcept { return uses_raw_input_; }
    // 0 when the artifact declares nothing: the identity calibration.
    [[nodiscard]] double spam_side_calibration_knot() const noexcept {
        return spam_side_calibration_knot_;
    }
    [[nodiscard]] bool uses_structural_markers() const noexcept {
        return uses_structural_markers_;
    }
    [[nodiscard]] bool uses_attachment_context() const noexcept {
        return uses_attachment_context_;
    }

    [[nodiscard]] int output_size() const noexcept { return num_labels_; }

    [[nodiscard]] int label_index(const std::string& name) const noexcept {
        const auto it = std::find(label_names_.begin(), label_names_.end(), name);
        return it == label_names_.end()
            ? -1
            : static_cast<int>(std::distance(label_names_.begin(), it));
    }

    static std::vector<float> softmax(const std::vector<float>& logits) {
        std::vector<float> result(logits.size());
        float const max_val = *std::max_element(logits.begin(), logits.end());
        float sum = 0.0F;

        for (size_t i = 0; i < logits.size(); ++i) {
            result[i] = std::exp(logits[i] - max_val);
            sum += result[i];
        }

        for (float & i : result) {
            i /= sum;
        }

        return result;
    }

    // Backward pass - computes gradients given the true label
    // Returns the cross-entropy loss
    float backward(int true_label) {
        // Compute softmax probabilities
        std::vector<float> probs = softmax(cached_logits_);

        // Allocate every scratch buffer before mutating persistent gradients.
        // If allocation fails, the enclosing RFC822 sample remains wholly
        // unapplied and can safely stay retryable in the correction database.
        std::vector<float> d_logits(num_labels_);
        std::vector<float> d_hidden(hidden_size_, 0.0F);
        std::vector<float> d_pre_activation(hidden_size_);

        // Cross-entropy loss
        float const loss = -std::log(probs[true_label] + 1e-10F);

        // Gradient of cross-entropy loss w.r.t. logits
        // d_loss/d_logits = probs - one_hot(true_label)
        for (int i = 0; i < num_labels_; ++i) {
            d_logits[i] = probs[i] - (i == true_label ? 1.0F : 0.0F);
        }

        // Gradient w.r.t. out_proj weights and bias
        for (int i = 0; i < num_labels_; ++i) {
            out_proj_bias_grad_[i] += d_logits[i];
            for (int j = 0; j < hidden_size_; ++j) {
                out_proj_weight_grad_[(i * hidden_size_) + j] += d_logits[i] * cached_hidden_[j];
            }
        }

        // Gradient w.r.t. hidden layer output
        for (int j = 0; j < hidden_size_; ++j) {
            for (int i = 0; i < num_labels_; ++i) {
                d_hidden[j] += d_logits[i] * out_proj_weight_[(i * hidden_size_) + j];
            }
        }

        // Gradient through tanh: d_tanh/d_x = 1 - tanh(x)^2
        for (int i = 0; i < hidden_size_; ++i) {
            float const tanh_val = cached_hidden_[i];
            d_pre_activation[i] = d_hidden[i] * (1.0F - (tanh_val * tanh_val));
        }

        // Gradient w.r.t. dense weights and bias
        for (int i = 0; i < hidden_size_; ++i) {
            dense_bias_grad_[i] += d_pre_activation[i];
            for (int j = 0; j < hidden_size_; ++j) {
                dense_weight_grad_[(i * hidden_size_) + j] += d_pre_activation[i] * cached_input_[j];
            }
        }

        return loss;
    }

    // Apply gradients with Adam optimizer + L2 regularization + gradient clipping
    void step(int batch_size = 1) {
        timestep_++;
        float beta1 = 0.9F;
        float beta2 = 0.999F;
        float epsilon = 1e-8F;

        // Gradient clipping: the clip decision has to be made on the AVERAGED
        // batch gradient, matching what actually gets applied below, or a
        // multipart (plain+HTML) correction's clipped step comes out
        // MIME-count-dependent. Computing grad_norm from the raw per-view SUM
        // and only dividing by batch_size when applying the clip (further
        // down) meant a clip that fires collapsed the post-clip step norm to
        // max_grad_norm_ / batch_size instead of max_grad_norm_ — a 2-view
        // correction that trips clipping got HALF the effective step of a
        // 1-view correction hitting the identical clip (TASK-193 AC#7).
        // batch_size == 1 (the common single-part case) is bit-identical to
        // the previous computation either way.
        const float inv_batch_size = 1.0F / static_cast<float>(batch_size);
        float grad_norm_sq = 0.0F;
        for (float const g : dense_weight_grad_) { float const a = g * inv_batch_size; grad_norm_sq += a * a; }
        for (float const g : dense_bias_grad_) { float const a = g * inv_batch_size; grad_norm_sq += a * a; }
        for (float const g : out_proj_weight_grad_) { float const a = g * inv_batch_size; grad_norm_sq += a * a; }
        for (float const g : out_proj_bias_grad_) { float const a = g * inv_batch_size; grad_norm_sq += a * a; }

        float const grad_norm = std::sqrt(grad_norm_sq);
        float clip_coef = (grad_norm > max_grad_norm_) ? (max_grad_norm_ / grad_norm) : 1.0F;

        // Bias correction
        float bc1 = 1.0F - std::pow(beta1, timestep_);
        float bc2 = 1.0F - std::pow(beta2, timestep_);

        // Adam update with L2 regularization toward original weights (anti-forgetting)
        // + gradient clipping to prevent catastrophic updates
        auto const adam_update_with_l2 = [&](std::vector<float>& param,
                                       const std::vector<float>& orig_param,
                                       std::vector<float>& grad,
                                       std::vector<float>& m,
                                       std::vector<float>& v) {
            for (size_t i = 0; i < param.size(); ++i) {
                // Clip gradient (grad_norm/clip_coef above are already computed
                // on this same averaged scale, so the clip fires on the actual
                // step being applied, not on the pre-average sum).
                float const clipped_grad = (grad[i] * inv_batch_size) * clip_coef;
                // Add L2 gradient: d/dw (lambda * ||w - w0||^2) = 2 * lambda * (w - w0)
                float const l2_grad = 2.0F * l2_lambda_ * (param[i] - orig_param[i]);
                float const g = clipped_grad + l2_grad;

                m[i] = (beta1 * m[i]) + ((1.0F - beta1) * g);
                v[i] = (beta2 * v[i]) + ((1.0F - beta2) * g * g);
                float const m_hat = m[i] / bc1;
                float const v_hat = v[i] / bc2;
                param[i] -= learning_rate_ * m_hat / (std::sqrt(v_hat) + epsilon);
                grad[i] = 0.0F;  // Reset gradient
            }
        };

        // Snapshot pre-Adam weights only when the function-space path needs
        // them for its pre/post bisection; the weight-space path below reads
        // orig_* directly and needs no snapshot.
        std::vector<float> pre_dense_weight;
        std::vector<float> pre_dense_bias;
        std::vector<float> pre_out_proj_weight;
        std::vector<float> pre_out_proj_bias;
        if (function_space_enabled_) {
            pre_dense_weight = dense_weight_;
            pre_dense_bias = dense_bias_;
            pre_out_proj_weight = out_proj_weight_;
            pre_out_proj_bias = out_proj_bias_;
        }

        adam_update_with_l2(dense_weight_, orig_dense_weight_,
                            dense_weight_grad_, dense_weight_m_, dense_weight_v_);
        adam_update_with_l2(dense_bias_, orig_dense_bias_,
                            dense_bias_grad_, dense_bias_m_, dense_bias_v_);
        adam_update_with_l2(out_proj_weight_, orig_out_proj_weight_,
                            out_proj_weight_grad_, out_proj_weight_m_, out_proj_weight_v_);
        adam_update_with_l2(out_proj_bias_, orig_out_proj_bias_,
                            out_proj_bias_grad_, out_proj_bias_m_, out_proj_bias_v_);

        if (function_space_enabled_) {
            // TASK-193 AC#9: bound drift by the change in the head's OUTPUT on
            // the anchor set, not by ‖w-w0‖. Direct analog of the weight-space
            // projection below, in output space instead: if the full (alpha=1)
            // Adam step moves the anchor set's spam-side scores too far from
            // p0, project_to_function_space_budget bisects the interpolation
            // factor between the pre-step and post-step weights until it's
            // back inside budget (doc-30, mutation (1), the "safer default to
            // prototype first" — a post-hoc clamp on an already-computed step,
            // not a loss term needing its own well-behaved gradient).
            // REPLACES the weight-space projection entirely while enabled,
            // matching what Phase A actually measured. Sound because the
            // pre-step state (`pre_*` above) is itself always within budget:
            // either this same projection put it there on a previous step, or
            // load_function_space_anchor did at construction time.
            //
            // Explicit copies of the post-Adam state, not references to
            // dense_weight_ etc. themselves: project_to_function_space_budget
            // repeatedly overwrites those members while bisecting, so a `to`
            // argument aliasing the same storage would read back its own
            // partially-mutated output on every call after the first instead
            // of a fixed target.
            const std::vector<float> post_dense_weight = dense_weight_;
            const std::vector<float> post_dense_bias = dense_bias_;
            const std::vector<float> post_out_proj_weight = out_proj_weight_;
            const std::vector<float> post_out_proj_bias = out_proj_bias_;
            project_to_function_space_budget(
                pre_dense_weight, post_dense_weight, pre_dense_bias, post_dense_bias,
                pre_out_proj_weight, post_out_proj_weight, pre_out_proj_bias, post_out_proj_bias,
                label_index("spam"));
        } else {
            // Hard trust region: project each tensor back into the ‖w - w0‖ ball
            // so a one-sided correction stream saturates instead of collapsing a
            // class.
            //
            // Do not reach for a per-tensor budget scale here: it was built, wired
            // to SPAM_ENGINE_BIAS_DRIFT_SCALE and measured on 2026-08-10, and it is
            // a dead end. The step budget is absolute while a bias norm is not, so
            // at max_drift_steps=3 it permits a 66.5% relative move on the e5 head's
            // three-element out_proj_bias (‖w0‖ = 0.0008) against 1.9% on
            // public-v0's, which looked like it would explain a collapse that
            // presents as global desensitization. Freezing both bias tensors
            // outright moves the untouched 2026 spam panel from 1,463 to 1,466 of
            // 3,000 and leaves the ham fixes at 37 of 68 exactly. The uniform shift
            // comes from the WEIGHT tensors. See qualification/bias-probe/ and
            // HOW_TO_TRAIN_A_MODEL.md, "Two mitigations that do not work".
            project_to_trust_region(dense_weight_, orig_dense_weight_);
            project_to_trust_region(dense_bias_, orig_dense_bias_);
            project_to_trust_region(out_proj_weight_, orig_out_proj_weight_);
            project_to_trust_region(out_proj_bias_, orig_out_proj_bias_);
        }
    }

    // Discard an unapplied batch. RFC822 training may accumulate gradients from
    // more than one MIME representation before taking its single optimizer
    // step; if preparing a later representation fails, none of that partial
    // sample may leak into the next correction.
    void zero_grad() noexcept {
        std::fill(dense_weight_grad_.begin(), dense_weight_grad_.end(), 0.0F);
        std::fill(dense_bias_grad_.begin(), dense_bias_grad_.end(), 0.0F);
        std::fill(out_proj_weight_grad_.begin(), out_proj_weight_grad_.end(), 0.0F);
        std::fill(out_proj_bias_grad_.begin(), out_proj_bias_grad_.end(), 0.0F);
    }

    // Save updated weights
    void save(const std::string& model_dir) {
        save_binary(model_dir + "/classifier_dense_weight.bin", dense_weight_);
        save_binary(model_dir + "/classifier_dense_bias.bin", dense_bias_);
        save_binary(model_dir + "/classifier_out_proj_weight.bin", out_proj_weight_);
        save_binary(model_dir + "/classifier_out_proj_bias.bin", out_proj_bias_);
        save_binary(model_dir + "/classifier_anchor_dense_weight.bin", orig_dense_weight_);
        save_binary(model_dir + "/classifier_anchor_dense_bias.bin", orig_dense_bias_);
        save_binary(model_dir + "/classifier_anchor_out_proj_weight.bin", orig_out_proj_weight_);
        save_binary(model_dir + "/classifier_anchor_out_proj_bias.bin", orig_out_proj_bias_);
    }

    void set_learning_rate(float lr) { learning_rate_ = lr; }
    [[nodiscard]] float get_learning_rate() const { return learning_rate_; }
    [[nodiscard]] int optimizer_steps() const { return timestep_; }

    // How full the trust region is, as a fraction of budget, maxed over the four
    // tensors. 1.0 means the weights are pinned to the boundary and every
    // further Adam step is projected straight back, which makes the learning
    // rate a no-op — the state doc-26 had to infer from a 50x lr sweep moving
    // the same 113 messages. Reading it directly turns that inference into a
    // measurement. Returns 0 when the cap is disabled.
    [[nodiscard]] float drift_saturation() const {
        if (max_drift_steps_ <= 0.0F) { return 0.0F;
}
        return std::max({saturation_of(dense_weight_, orig_dense_weight_),
                                 saturation_of(dense_bias_, orig_dense_bias_),
                        saturation_of(out_proj_weight_, orig_out_proj_weight_),
                                 saturation_of(out_proj_bias_, orig_out_proj_bias_)});
    }

    // ‖w - w0‖ / ‖w0‖ maxed over the four tensors: how far the head has actually
    // travelled, independent of what the budget happens to be.
    [[nodiscard]] float relative_drift() const {
        return std::max({rel_drift_of(dense_weight_, orig_dense_weight_),
                                 rel_drift_of(dense_bias_, orig_dense_bias_),
                        rel_drift_of(out_proj_weight_, orig_out_proj_weight_),
                                 rel_drift_of(out_proj_bias_, orig_out_proj_bias_)});
    }

    // Expected CLS-embedding length (n_embd): the public boundary validates
    // embedding.size() == input_size() to reject a wrong-length vector before it
    // reaches the head, and load() asserts it equals the encoder's n_embd
    // (C4, TASK-251).
    [[nodiscard]] int input_size() const { return hidden_size_; }

private:
    void load_or_initialize_anchor(const std::string& model_dir) {
        namespace fs = std::filesystem;
        const std::string dense_weight = model_dir + "/classifier_anchor_dense_weight.bin";
        const std::string dense_bias = model_dir + "/classifier_anchor_dense_bias.bin";
        const std::string out_weight = model_dir + "/classifier_anchor_out_proj_weight.bin";
        const std::string out_bias = model_dir + "/classifier_anchor_out_proj_bias.bin";
        const int present = static_cast<int>(fs::exists(dense_weight))
            + static_cast<int>(fs::exists(dense_bias))
            + static_cast<int>(fs::exists(out_weight))
            + static_cast<int>(fs::exists(out_bias));

        if (present == 0) {
            // A base model has no separate anchor: its current head is the
            // immutable origin. The first save persists it for every successor.
            orig_dense_weight_ = dense_weight_;
            orig_dense_bias_ = dense_bias_;
            orig_out_proj_weight_ = out_proj_weight_;
            orig_out_proj_bias_ = out_proj_bias_;
            return;
        }
        if (present != 4) {
            throw std::runtime_error(
                "TrainableClassifierHead: incomplete persisted trust-region anchor");
        }

        orig_dense_weight_.resize(dense_weight_.size());
        orig_dense_bias_.resize(dense_bias_.size());
        orig_out_proj_weight_.resize(out_proj_weight_.size());
        orig_out_proj_bias_.resize(out_proj_bias_.size());
        load_binary(dense_weight, orig_dense_weight_);
        load_binary(dense_bias, orig_dense_bias_);
        load_binary(out_weight, orig_out_proj_weight_);
        load_binary(out_bias, orig_out_proj_bias_);
    }

    // Loads the frozen spam anchor set and, on first load only, computes and
    // persists p0 (each anchor's spam-side probability under the ORIGINAL
    // weights). Must run after load_or_initialize_anchor(), which is what
    // guarantees orig_dense_weight_ etc. are the true immutable origin by the
    // time this executes. function_space_budget_ must already be set (the
    // constructor sets it before calling this).
    void load_function_space_anchor(const std::string& anchor_path,
                                    const std::string& model_dir) {
        namespace fs = std::filesystem;
        std::ifstream probe(anchor_path, std::ios::binary | std::ios::ate);
        if (!probe) {
            throw std::runtime_error(
                "TrainableClassifierHead: failed to open function-space anchor "
                + anchor_path);
        }
        const std::streamsize bytes = probe.tellg();
        const std::streamsize per_anchor =
            static_cast<std::streamsize>(hidden_size_) * sizeof(float);
        if (per_anchor <= 0 || bytes <= 0 || bytes % per_anchor != 0) {
            throw std::runtime_error(
                "TrainableClassifierHead: function-space anchor file size "
                + std::to_string(bytes) + " is not a multiple of hidden_size ("
                + std::to_string(hidden_size_) + ") * sizeof(float)");
        }
        anchor_count_ = static_cast<int>(bytes / per_anchor);
        if (anchor_count_ <= 0) {
            throw std::runtime_error(
                "TrainableClassifierHead: function-space anchor set is empty");
        }
        anchor_embeddings_.resize(static_cast<size_t>(anchor_count_) * hidden_size_);
        load_binary(anchor_path, anchor_embeddings_);
        // Content fingerprint (XXH3, already linked via ftrl_classifier.h) so a
        // regenerated or swapped anchor file with the same dimensions can never
        // silently reuse a stale cached p0 -- the loader below only checked
        // existence, not identity, which would measure drift against unrelated
        // vectors (codex review, 2026-08-29).
        const uint64_t anchor_fingerprint = XXH3_64bits(
            anchor_embeddings_.data(), anchor_embeddings_.size() * sizeof(float));

        const int spam_index = label_index("spam");
        if (spam_index < 0) {
            throw std::runtime_error(
                "TrainableClassifierHead: function-space anchor requires a "
                "'spam' label, which this model's label_map does not declare");
        }

        const std::string p0_path = model_dir + "/classifier_function_space_p0.bin";
        const std::string fingerprint_path = p0_path + ".anchor_xxh3";
        anchor_p0_.resize(static_cast<size_t>(anchor_count_));
        bool have_cached_p0 = false;
        if (fs::exists(p0_path) && fs::exists(fingerprint_path)) {
            std::ifstream fp_file(fingerprint_path);
            uint64_t cached_fingerprint = 0;
            fp_file >> std::hex >> cached_fingerprint;
            if (fp_file && cached_fingerprint == anchor_fingerprint) {
                load_binary(p0_path, anchor_p0_);
                have_cached_p0 = true;
            }
            // Mismatch (or unreadable sidecar): fall through and recompute --
            // the anchor file changed under this p0 cache.
        }
        if (!have_cached_p0) {
            // current weights ARE the origin (load_or_initialize_anchor above
            // just ran, and for a base model with no prior anchor files that
            // means dense_weight_ == orig_dense_weight_ already; for a model
            // that already carries a persisted weight-space anchor, current
            // weights may already have drifted, so compute p0 from orig_*
            // explicitly by swapping it in for the duration of this forward
            // pass — forward() only reads the member weight vectors and,
            // uncached, mutates nothing else, so the swap is safe and
            // self-contained).
            std::swap(dense_weight_, orig_dense_weight_);
            std::swap(dense_bias_, orig_dense_bias_);
            std::swap(out_proj_weight_, orig_out_proj_weight_);
            std::swap(out_proj_bias_, orig_out_proj_bias_);
            anchor_p0_ = anchor_spam_side(spam_index);
            std::swap(dense_weight_, orig_dense_weight_);
            std::swap(dense_bias_, orig_dense_bias_);
            std::swap(out_proj_weight_, orig_out_proj_weight_);
            std::swap(out_proj_bias_, orig_out_proj_bias_);
            save_binary(p0_path, anchor_p0_);
            std::ofstream fp_out(fingerprint_path);
            fp_out << std::hex << anchor_fingerprint;
        }

        // A snapshot loaded here may already have drifted from orig_* (a
        // prior weight-space-only session, or an earlier/looser budget) by
        // more than the NOW-active budget permits. Without this, step()'s
        // bisection treats "no change this step" (alpha=0) as always safe,
        // which is only true if the pre-step state already satisfies the
        // budget -- silently leaving an out-of-budget snapshot unenforced
        // forever, since every future step would just bisect back toward the
        // same violating state (codex review, 2026-08-29). Project current
        // weights back toward orig_* (which has zero drift from p0 by
        // construction) if they're already outside budget. Explicit copies of
        // the possibly-drifted current weights, not references to the members
        // themselves -- same self-aliasing hazard as step()'s call.
        const std::vector<float> loaded_dense_weight = dense_weight_;
        const std::vector<float> loaded_dense_bias = dense_bias_;
        const std::vector<float> loaded_out_proj_weight = out_proj_weight_;
        const std::vector<float> loaded_out_proj_bias = out_proj_bias_;
        project_to_function_space_budget(
            orig_dense_weight_, loaded_dense_weight, orig_dense_bias_, loaded_dense_bias,
            orig_out_proj_weight_, loaded_out_proj_weight, orig_out_proj_bias_, loaded_out_proj_bias,
            spam_index);
    }

    // Spam-side probability of every anchor under the CURRENT weights.
    std::vector<float> anchor_spam_side(int spam_index) {
        std::vector<float> result(static_cast<size_t>(anchor_count_));
        std::vector<float> embedding(hidden_size_);
        for (int i = 0; i < anchor_count_; ++i) {
            std::copy(
                anchor_embeddings_.begin() + static_cast<size_t>(i) * hidden_size_,
                anchor_embeddings_.begin() + static_cast<size_t>(i + 1) * hidden_size_,
                embedding.begin());
            const auto logits = forward(embedding, /*cache_for_backward=*/false);
            result[i] = softmax(logits)[spam_index];
        }
        return result;
    }

    // Shared by load-time snapshot validation (from=orig_*, to=possibly
    // already-drifted current weights) and step()-time projection (from=
    // pre-step, to=post-step): bisects the interpolation factor between `from`
    // and `to` down to the largest alpha whose resulting anchor-set drift from
    // p0 stays within function_space_budget_, then leaves the member weight
    // tensors set to that point. Sound as long as `from` always has drift <=
    // budget already -- true by construction here (orig_* has zero drift from
    // p0; step()'s pre-step state is safe by induction, since every prior call
    // to this function left it that way).
    void project_to_function_space_budget(
        const std::vector<float>& from_dense_weight, const std::vector<float>& to_dense_weight,
        const std::vector<float>& from_dense_bias, const std::vector<float>& to_dense_bias,
        const std::vector<float>& from_out_proj_weight, const std::vector<float>& to_out_proj_weight,
        const std::vector<float>& from_out_proj_bias, const std::vector<float>& to_out_proj_bias,
        int spam_index) {
        const auto set_alpha = [&](float alpha) {
            for (size_t i = 0; i < dense_weight_.size(); ++i) {
                dense_weight_[i] = from_dense_weight[i]
                    + (alpha * (to_dense_weight[i] - from_dense_weight[i]));
            }
            for (size_t i = 0; i < dense_bias_.size(); ++i) {
                dense_bias_[i] = from_dense_bias[i]
                    + (alpha * (to_dense_bias[i] - from_dense_bias[i]));
            }
            for (size_t i = 0; i < out_proj_weight_.size(); ++i) {
                out_proj_weight_[i] = from_out_proj_weight[i]
                    + (alpha * (to_out_proj_weight[i] - from_out_proj_weight[i]));
            }
            for (size_t i = 0; i < out_proj_bias_.size(); ++i) {
                out_proj_bias_[i] = from_out_proj_bias[i]
                    + (alpha * (to_out_proj_bias[i] - from_out_proj_bias[i]));
            }
        };
        const auto drift_at = [&](float alpha) {
            set_alpha(alpha);
            return anchor_drift(anchor_spam_side(spam_index));
        };
        if (drift_at(1.0F) > function_space_budget_) {
            float lo = 0.0F;
            float hi = 1.0F;
            for (int i = 0; i < 8; ++i) {
                const float mid = (lo + hi) * 0.5F;
                if (drift_at(mid) > function_space_budget_) {
                    hi = mid;
                } else {
                    lo = mid;
                }
            }
            set_alpha(lo);
        }
        // else: leave at alpha=1.0 (the full move to `to`), already set by the
        // drift_at(1.0f) probe above as a side effect of set_alpha.
    }

    // Mean absolute drift of the anchor set's spam-side scores vs p0 — the
    // metric TASK-193 AC#9 names: "the change in the head's output on known
    // spam".
    [[nodiscard]] float anchor_drift(const std::vector<float>& candidate) const {
        float sum = 0.0F;
        for (size_t i = 0; i < candidate.size(); ++i) {
            sum += std::abs(candidate[i] - anchor_p0_[i]);
        }
        return sum / static_cast<float>(candidate.size());
    }

    // ‖w - w0‖ / ‖w0‖ for one tensor.
    static float rel_drift_of(const std::vector<float>& param,
                              const std::vector<float>& orig_param) {
        float drift_sq = 0.0F;
        float orig_sq = 0.0F;
        for (size_t i = 0; i < param.size(); ++i) {
            const float d = param[i] - orig_param[i];
            drift_sq += d * d;
            orig_sq += orig_param[i] * orig_param[i];
        }
        if (orig_sq == 0.0F) { return 0.0F;
}
        return std::sqrt(drift_sq / orig_sq);
    }

    // The trust-region budget for one tensor: `max_drift_steps` Adam steps.
    // Adam's first update after bias correction is exactly ±lr per coordinate,
    // so one step has norm lr*sqrt(n) — and later steps are bounded by it, since
    // |m̂/(sqrt(v̂)+eps)| <= 1 whenever the gradient sign is consistent.
    [[nodiscard]] float trust_budget(size_t n) const {
        return max_drift_steps_ * learning_rate_ *
               std::sqrt(static_cast<float>(n));
    }

    [[nodiscard]] float saturation_of(const std::vector<float>& param,
                        const std::vector<float>& orig_param) const {
        const float budget = trust_budget(param.size());
        if (budget <= 0.0F) { return 0.0F;
}
        float drift_sq = 0.0F;
        for (size_t i = 0; i < param.size(); ++i) {
            const float d = param[i] - orig_param[i];
            drift_sq += d * d;
        }
        return std::sqrt(drift_sq) / budget;
    }

    // Project `param` back onto the ball of radius `trust_budget(n)` centred on
    // the frozen origin weights. max_drift_steps_ <= 0 disables the cap.
    void project_to_trust_region(std::vector<float>& param,
                                 const std::vector<float>& orig_param) {
        if (max_drift_steps_ <= 0.0F) { return;
}
        float drift_sq = 0.0F;
        for (size_t i = 0; i < param.size(); ++i) {
            const float d = param[i] - orig_param[i];
            drift_sq += d * d;
        }
        const float budget = trust_budget(param.size());
        const float drift = std::sqrt(drift_sq);
        if (drift <= budget || drift == 0.0F) { return;
}
        const float scale = budget / drift;
        for (size_t i = 0; i < param.size(); ++i) {
            param[i] = orig_param[i] + ((param[i] - orig_param[i]) * scale);
        }
    }

    static void load_binary(const std::string& path, std::vector<float>& data) {
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            throw std::runtime_error("TrainableClassifierHead: failed to open " + path);
        }
        const auto bytes = static_cast<std::streamsize>(data.size() * sizeof(float));
        file.read(reinterpret_cast<char*>(data.data()), bytes);
        if (file.gcount() != bytes || file.fail()) {
            throw std::runtime_error("TrainableClassifierHead: short read from " + path);
        }
    }

    static void save_binary(const std::string& path, const std::vector<float>& data) {
        std::ofstream file(path, std::ios::binary);
        if (!file) {
            throw std::runtime_error("TrainableClassifierHead: failed to open " + path + " for writing");
        }
        file.write(reinterpret_cast<const char*>(data.data()), data.size() * sizeof(float));
        if (!file) {
            throw std::runtime_error("TrainableClassifierHead: failed to write " + path);
        }
    }

    int hidden_size_;
    int num_labels_;
    std::vector<std::string> label_names_;
    std::string source_model_;
    bool uses_raw_input_ = false;
    bool uses_structural_markers_ = false;
    bool uses_attachment_context_ = false;
    double spam_side_calibration_knot_ = 0.0;
    float learning_rate_;
    float l2_lambda_;
    float max_grad_norm_;
    float max_drift_steps_;
    int timestep_ = 0;

    // Weights
    std::vector<float> dense_weight_;
    std::vector<float> dense_bias_;
    std::vector<float> out_proj_weight_;
    std::vector<float> out_proj_bias_;

    // Original weights (reference for L2 regularization to prevent forgetting)
    std::vector<float> orig_dense_weight_;
    std::vector<float> orig_dense_bias_;
    std::vector<float> orig_out_proj_weight_;
    std::vector<float> orig_out_proj_bias_;

    // Gradients
    std::vector<float> dense_weight_grad_;
    std::vector<float> dense_bias_grad_;
    std::vector<float> out_proj_weight_grad_;
    std::vector<float> out_proj_bias_grad_;

    // Adam optimizer state
    std::vector<float> dense_weight_m_, dense_weight_v_;
    std::vector<float> dense_bias_m_, dense_bias_v_;
    std::vector<float> out_proj_weight_m_, out_proj_weight_v_;
    std::vector<float> out_proj_bias_m_, out_proj_bias_v_;

    // Cached values for backprop
    std::vector<float> cached_input_;
    std::vector<float> cached_hidden_pre_activation_;
    std::vector<float> cached_hidden_;
    std::vector<float> cached_logits_;

    // Function-space trust region (TASK-193 AC#8/#9, doc-30 Phase B).
    // Off by default (empty anchor path / budget <= 0): the weight-space
    // ‖w-w0‖ projection above is unchanged in that case. When enabled, this
    // REPLACES that projection rather than adding to it, matching exactly
    // what the offline Phase A screen measured (function_space_experiment.py
    // ran no weight-space bound alongside the projection).
    bool function_space_enabled_ = false;
    float function_space_budget_ = 0.0F;
    int anchor_count_ = 0;
    // Flat: anchor_count_ * hidden_size_ floats, row-major per anchor.
    std::vector<float> anchor_embeddings_;
    // p0: each anchor's spam-side probability under the ORIGINAL (orig_*)
    // weights, computed once and persisted (classifier_function_space_p0.bin)
    // so a reload never recomputes it from already-drifted current weights —
    // the same reasoning that makes orig_dense_weight_ etc. immutable for the
    // model's lifetime (doc-30 finding #2: a rolling reference would let
    // per-step-bounded corrections drift arbitrarily far cumulatively).
    std::vector<float> anchor_p0_;
};
