#pragma once

#include <algorithm>
#include <cmath>
#include <fstream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class TrainableClassifierHead {
public:
    // L2 regularization toward original weights prevents catastrophic forgetting.
    // lr=0.0001, l2=0.1, max_grad_norm=1.0: balances learning vs forgetting.
    //
    // max_drift is a hard trust region around the frozen origin weights: after
    // each step every weight tensor is projected back so ‖w - w0‖ <= max_drift *
    // ‖w0‖. The soft L2 anchor is a *pull* that Adam's momentum overpowers under
    // a one-sided correction stream (e.g. 30 ham / 0 spam in a row), walking the
    // spam/regular boundary across the borderline cluster until a whole class
    // collapses. The cap turns that into a saturating bound: a one-sided stream
    // stalls at the region boundary instead of flipping the class, while
    // balanced corrections stay well inside and learn unimpeded (TASK-193).
    TrainableClassifierHead(const std::string& model_dir,
                            float learning_rate = 0.0001f,
                            float l2_lambda = 0.1f,
                            float max_grad_norm = 1.0f,
                            float max_drift = 0.015f)
        : learning_rate_(learning_rate), l2_lambda_(l2_lambda),
          max_grad_norm_(max_grad_norm), max_drift_(max_drift) {
        std::ifstream config_file(model_dir + "/classifier_config.json");
        json config;
        config_file >> config;

        hidden_size_ = config["hidden_size"];
        num_labels_ = config["num_labels"];

        // classifier_config.json is model-supplied; reject implausible dims
        // before they drive allocations and loop bounds (int overflow in
        // hidden_size_*hidden_size_, or OOB indexing on a too-small num_labels_).
        if (hidden_size_ <= 0 || hidden_size_ > 8192 ||
            num_labels_ <= 0 || num_labels_ > 64) {
            throw std::runtime_error(
                "classifier_config.json: implausible hidden_size/num_labels");
        }

        dense_weight_.resize(static_cast<size_t>(hidden_size_) * hidden_size_);
        dense_bias_.resize(hidden_size_);
        out_proj_weight_.resize(static_cast<size_t>(num_labels_) * hidden_size_);
        out_proj_bias_.resize(num_labels_);

        load_binary(model_dir + "/classifier_dense_weight.bin", dense_weight_);
        load_binary(model_dir + "/classifier_dense_bias.bin", dense_bias_);
        load_binary(model_dir + "/classifier_out_proj_weight.bin", out_proj_weight_);
        load_binary(model_dir + "/classifier_out_proj_bias.bin", out_proj_bias_);

        // Store original weights for L2 regularization (anti-forgetting)
        orig_dense_weight_ = dense_weight_;
        orig_dense_bias_ = dense_bias_;
        orig_out_proj_weight_ = out_proj_weight_;
        orig_out_proj_bias_ = out_proj_bias_;

        // Initialize gradient accumulators
        dense_weight_grad_.resize(dense_weight_.size(), 0.0f);
        dense_bias_grad_.resize(dense_bias_.size(), 0.0f);
        out_proj_weight_grad_.resize(out_proj_weight_.size(), 0.0f);
        out_proj_bias_grad_.resize(out_proj_bias_.size(), 0.0f);

        // For Adam optimizer
        dense_weight_m_.resize(dense_weight_.size(), 0.0f);
        dense_weight_v_.resize(dense_weight_.size(), 0.0f);
        dense_bias_m_.resize(dense_bias_.size(), 0.0f);
        dense_bias_v_.resize(dense_bias_.size(), 0.0f);
        out_proj_weight_m_.resize(out_proj_weight_.size(), 0.0f);
        out_proj_weight_v_.resize(out_proj_weight_.size(), 0.0f);
        out_proj_bias_m_.resize(out_proj_bias_.size(), 0.0f);
        out_proj_bias_v_.resize(out_proj_bias_.size(), 0.0f);
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
                sum += cls_embedding[j] * dense_weight_[i * hidden_size_ + j];
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
                sum += hidden[j] * out_proj_weight_[i * hidden_size_ + j];
            }
            logits[i] = sum;
        }

        if (cache_for_backward) {
            cached_logits_ = logits;
        }

        return logits;
    }

    std::vector<float> softmax(const std::vector<float>& logits) {
        std::vector<float> result(logits.size());
        float max_val = *std::max_element(logits.begin(), logits.end());
        float sum = 0.0f;

        for (size_t i = 0; i < logits.size(); ++i) {
            result[i] = std::exp(logits[i] - max_val);
            sum += result[i];
        }

        for (size_t i = 0; i < result.size(); ++i) {
            result[i] /= sum;
        }

        return result;
    }

    // Backward pass - computes gradients given the true label
    // Returns the cross-entropy loss
    float backward(int true_label) {
        // Compute softmax probabilities
        std::vector<float> probs = softmax(cached_logits_);

        // Cross-entropy loss
        float loss = -std::log(probs[true_label] + 1e-10f);

        // Gradient of cross-entropy loss w.r.t. logits
        // d_loss/d_logits = probs - one_hot(true_label)
        std::vector<float> d_logits(num_labels_);
        for (int i = 0; i < num_labels_; ++i) {
            d_logits[i] = probs[i] - (i == true_label ? 1.0f : 0.0f);
        }

        // Gradient w.r.t. out_proj weights and bias
        for (int i = 0; i < num_labels_; ++i) {
            out_proj_bias_grad_[i] += d_logits[i];
            for (int j = 0; j < hidden_size_; ++j) {
                out_proj_weight_grad_[i * hidden_size_ + j] += d_logits[i] * cached_hidden_[j];
            }
        }

        // Gradient w.r.t. hidden layer output
        std::vector<float> d_hidden(hidden_size_, 0.0f);
        for (int j = 0; j < hidden_size_; ++j) {
            for (int i = 0; i < num_labels_; ++i) {
                d_hidden[j] += d_logits[i] * out_proj_weight_[i * hidden_size_ + j];
            }
        }

        // Gradient through tanh: d_tanh/d_x = 1 - tanh(x)^2
        std::vector<float> d_pre_activation(hidden_size_);
        for (int i = 0; i < hidden_size_; ++i) {
            float tanh_val = cached_hidden_[i];
            d_pre_activation[i] = d_hidden[i] * (1.0f - tanh_val * tanh_val);
        }

        // Gradient w.r.t. dense weights and bias
        for (int i = 0; i < hidden_size_; ++i) {
            dense_bias_grad_[i] += d_pre_activation[i];
            for (int j = 0; j < hidden_size_; ++j) {
                dense_weight_grad_[i * hidden_size_ + j] += d_pre_activation[i] * cached_input_[j];
            }
        }

        return loss;
    }

    // Apply gradients with Adam optimizer + L2 regularization + gradient clipping
    void step(int batch_size = 1) {
        timestep_++;
        float beta1 = 0.9f;
        float beta2 = 0.999f;
        float epsilon = 1e-8f;

        // Gradient clipping: compute global gradient norm and clip if > max_grad_norm_
        float grad_norm_sq = 0.0f;
        for (float g : dense_weight_grad_) grad_norm_sq += g * g;
        for (float g : dense_bias_grad_) grad_norm_sq += g * g;
        for (float g : out_proj_weight_grad_) grad_norm_sq += g * g;
        for (float g : out_proj_bias_grad_) grad_norm_sq += g * g;
        
        float grad_norm = std::sqrt(grad_norm_sq);
        float clip_coef = (grad_norm > max_grad_norm_) ? (max_grad_norm_ / grad_norm) : 1.0f;

        // Bias correction
        float bc1 = 1.0f - std::pow(beta1, timestep_);
        float bc2 = 1.0f - std::pow(beta2, timestep_);

        // Adam update with L2 regularization toward original weights (anti-forgetting)
        // + gradient clipping to prevent catastrophic updates
        auto adam_update_with_l2 = [&](std::vector<float>& param,
                                       const std::vector<float>& orig_param,
                                       std::vector<float>& grad,
                                       std::vector<float>& m,
                                       std::vector<float>& v) {
            for (size_t i = 0; i < param.size(); ++i) {
                // Clip gradient
                float clipped_grad = (grad[i] / batch_size) * clip_coef;
                // Add L2 gradient: d/dw (lambda * ||w - w0||^2) = 2 * lambda * (w - w0)
                float l2_grad = 2.0f * l2_lambda_ * (param[i] - orig_param[i]);
                float g = clipped_grad + l2_grad;

                m[i] = beta1 * m[i] + (1.0f - beta1) * g;
                v[i] = beta2 * v[i] + (1.0f - beta2) * g * g;
                float m_hat = m[i] / bc1;
                float v_hat = v[i] / bc2;
                param[i] -= learning_rate_ * m_hat / (std::sqrt(v_hat) + epsilon);
                grad[i] = 0.0f;  // Reset gradient
            }
        };

        adam_update_with_l2(dense_weight_, orig_dense_weight_,
                            dense_weight_grad_, dense_weight_m_, dense_weight_v_);
        adam_update_with_l2(dense_bias_, orig_dense_bias_,
                            dense_bias_grad_, dense_bias_m_, dense_bias_v_);
        adam_update_with_l2(out_proj_weight_, orig_out_proj_weight_,
                            out_proj_weight_grad_, out_proj_weight_m_, out_proj_weight_v_);
        adam_update_with_l2(out_proj_bias_, orig_out_proj_bias_,
                            out_proj_bias_grad_, out_proj_bias_m_, out_proj_bias_v_);

        // Hard trust region: project each tensor back into the ‖w - w0‖ ball so a
        // one-sided correction stream saturates instead of collapsing a class.
        project_to_trust_region(dense_weight_, orig_dense_weight_);
        project_to_trust_region(dense_bias_, orig_dense_bias_);
        project_to_trust_region(out_proj_weight_, orig_out_proj_weight_);
        project_to_trust_region(out_proj_bias_, orig_out_proj_bias_);
    }

    // Save updated weights
    void save(const std::string& model_dir) {
        save_binary(model_dir + "/classifier_dense_weight.bin", dense_weight_);
        save_binary(model_dir + "/classifier_dense_bias.bin", dense_bias_);
        save_binary(model_dir + "/classifier_out_proj_weight.bin", out_proj_weight_);
        save_binary(model_dir + "/classifier_out_proj_bias.bin", out_proj_bias_);
    }

    void set_learning_rate(float lr) { learning_rate_ = lr; }
    float get_learning_rate() const { return learning_rate_; }

    // Expected CLS-embedding length (n_embd): the public boundary validates
    // embedding.size() == input_size() to reject a wrong-length vector before it
    // reaches the head, and load() asserts it equals the encoder's n_embd
    // (C4, TASK-251).
    int input_size() const { return hidden_size_; }

private:
    // Project `param` back onto the ball {w : ‖w - w0‖ <= max_drift_ * ‖w0‖}
    // centred on the frozen origin weights. max_drift_ <= 0 disables the cap.
    void project_to_trust_region(std::vector<float>& param,
                                 const std::vector<float>& orig_param) {
        if (max_drift_ <= 0.0f) return;
        float drift_sq = 0.0f, orig_sq = 0.0f;
        for (size_t i = 0; i < param.size(); ++i) {
            const float d = param[i] - orig_param[i];
            drift_sq += d * d;
            orig_sq += orig_param[i] * orig_param[i];
        }
        const float budget = max_drift_ * std::sqrt(orig_sq);
        const float drift = std::sqrt(drift_sq);
        if (drift <= budget || drift == 0.0f) return;
        const float scale = budget / drift;
        for (size_t i = 0; i < param.size(); ++i) {
            param[i] = orig_param[i] + (param[i] - orig_param[i]) * scale;
        }
    }

    void load_binary(const std::string& path, std::vector<float>& data) {
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            throw std::runtime_error("TrainableClassifierHead: failed to open " + path);
        }
        const std::streamsize bytes = static_cast<std::streamsize>(data.size() * sizeof(float));
        file.read(reinterpret_cast<char*>(data.data()), bytes);
        if (file.gcount() != bytes || file.fail()) {
            throw std::runtime_error("TrainableClassifierHead: short read from " + path);
        }
    }

    void save_binary(const std::string& path, const std::vector<float>& data) {
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
    float learning_rate_;
    float l2_lambda_;
    float max_grad_norm_;
    float max_drift_;
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
};
