#pragma once

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#define XXH_INLINE_ALL
#include <xxhash.h>

/**
 * FTRL-Proximal online spam classifier (v2).
 *
 * Algorithm: McMahan et al. 2013 "Ad Click Prediction: a View from the Trenches"
 * Feature engineering: prefixed token types, signed hashing, word stemming.
 *
 * == How it works ==
 *
 * The classifier is a logistic regression model with online learning.
 *
 * 1. FEATURE HASHING: Words from the email are hashed to indices in a
 *    fixed-size weight array. "viagra" → hash → index 847291 → weights[847291].
 *    The array never grows — new words just map to existing slots. Collisions
 *    (two words sharing a slot) add noise but L1 regularization tolerates it.
 *
 * 2. PREDICTION: For each word in the email, look up its weight. Sum them all
 *    (plus a bias term), apply sigmoid → P(spam) in [0, 1].
 *
 * 3. LEARNING: When the user marks an email as spam/ham, compute how wrong the
 *    prediction was (gradient), then nudge each word's weight to be more correct
 *    next time. The FTRL update rule stores two accumulators per feature:
 *      z[i] — tracks cumulative gradient direction
 *      n[i] — tracks cumulative gradient magnitude (adaptive learning rate)
 *    The actual weight is computed on-the-fly:
 *      w[i] = -(z[i] - sign(z[i]) * lambda1) / ((beta + sqrt(n[i])) / alpha + lambda2)
 *    If |z[i]| < lambda1, the weight is forced to exactly zero (L1 sparsity).
 *    This means unused/irrelevant features cost zero — constant effective memory.
 *
 * == Feature types (prefixed to avoid cross-contamination) ==
 *
 *   "b:" — body words and bigrams (lowercased, max 16 chars)
 *   "s:" — subject words and bigrams
 *   "f:" — sender: full email, domain, TLD
 *   "u:" — URLs: full domain, domain parts, URL count
 *   "e:" — email addresses found in body (domain only)
 *   "x:" — structural: allcaps, exclamation count, dollar signs
 *
 * Feature values use ln(1+count) weighting so that repeated words contribute
 * diminishing returns (a word appearing 10 times isn't 10x more spammy).
 *
 * == Storage ==
 *
 * Flat binary file: header + z[] + n[] arrays. Same format in C++ and Python.
 * The file ships in the app bundle (pre-trained on public corpora) and gets
 * updated in the user's App Group container as corrections accumulate.
 *
 * == References ==
 *
 * - McMahan et al. 2013: FTRL-Proximal algorithm
 * - Weinberger et al. 2009: Feature hashing for large-scale multitask learning
 */
class FTRLClassifier {
public:
    struct Config {
        uint32_t hash_bits = 20;     // 2^20 = 1,048,576 slots (~8MB for z[]+n[])
        float alpha = 2.0f;          // Learning rate (calibrated default)
        float beta = 1.0f;           // Learning rate smoothing
        float lambda1 = 0.001f;      // L1 regularization — drives unused weights to zero
        float lambda2 = 0.0001f;     // L2 regularization — prevents any single weight from exploding
        // Cuckoo slot-selection picks the less-utilized of two candidate slots by
        // reading model state (z_), which makes a feature's bucket DEVICE-SPECIFIC.
        // Default true = the shipped behavior. Set false for an index space that is
        // state-independent / portable across devices — required end-to-end if
        // centrally-retrained weights are ever deployed (data flywheel, TASK-134).
        bool cuckoo = true;
    };

    FTRLClassifier()
        : FTRLClassifier(Config{}) {}

    explicit FTRLClassifier(const Config& config)
        : config_(config),
          num_features_(1u << config.hash_bits),
          z_(num_features_, 0.0f),    // z accumulator per slot (gradient direction)
          n_(num_features_, 0.0f),    // n accumulator per slot (gradient magnitude, for adaptive LR)
          bias_z_(0.0f),              // Bias z accumulator (intercept term)
          bias_n_(0.0f),              // Bias n accumulator
          spam_learns_(0),
          ham_learns_(0) {}

    /// A single feature: an index into the weight array, plus its value.
    /// The value is ln(1+count) — how many times this word/pattern appeared.
    struct Feature {
        uint32_t idx;     // Slot index in the weight array (from hash)
        float weight;     // Feature value: ln(1 + occurrence_count)
    };

    // --- Hashing ---

    /// Hash a prefixed feature string (e.g. "b:viagra") to a slot index.
    /// Uses xxHash3 (64-bit) for speed and low collision rate.
    uint32_t hash_to_idx(const std::string& feature) const {
        uint64_t h = XXH3_64bits(feature.data(), feature.size());
        return static_cast<uint32_t>(h) & (num_features_ - 1);  // Mask to array bounds
    }

    /// Signed cuckoo hash: returns (index, sign).
    /// Two candidate slots computed; picks the less-utilized one (smaller |z|).
    /// Sign from MSB reduces collision bias.
    std::pair<uint32_t, float> hash_signed(const std::string& feature) const {
        uint64_t h1 = XXH3_64bits(feature.data(), feature.size());
        float sign = (h1 >> 63) == 0 ? 1.0f : -1.0f;
        uint32_t idx1 = static_cast<uint32_t>(h1) & (num_features_ - 1);
        // State-independent (portable) mode: primary slot only, never reads z_.
        if (!config_.cuckoo) return {idx1, sign};
        // Cuckoo: second hash with different seed
        uint64_t h2 = XXH3_64bits_withSeed(feature.data(), feature.size(), 0x9E3779B97F4A7C15ULL);
        uint32_t idx2 = static_cast<uint32_t>(h2) & (num_features_ - 1);
        // Pick less-utilized slot
        uint32_t idx = (std::abs(z_[idx1]) <= std::abs(z_[idx2])) ? idx1 : idx2;
        return {idx, sign};
    }

    /// State-independent signed hash for the flywheel CONTRIBUTION path (TASK-134).
    /// Never reads model state (z_), so the same feature maps to the same bucket on
    /// every device — the property the server needs to aggregate across users.
    /// `key != 0` switches to keyed (HMAC-style) bucketing: it drops dictionary
    /// membership-oracle recovery ~100%→0.1% (de-risk E14). The key is shipped in
    /// the binary, so this raises the bar, it is not a cryptographic guarantee.
    std::pair<uint32_t, float> portable_hash(const std::string& feature, uint64_t key = 0) const {
        uint64_t h = key ? XXH3_64bits_withSeed(feature.data(), feature.size(), key)
                         : XXH3_64bits(feature.data(), feature.size());
        float sign = (h >> 63) == 0 ? 1.0f : -1.0f;
        uint32_t idx = static_cast<uint32_t>(h) & (num_features_ - 1);
        return {idx, sign};
    }

    // --- Stemming ---

    /// Minimal suffix-stripping stemmer (Porter-lite).
    /// Good enough for spam features — no external dependency needed.
    static std::string stem(const std::string& word) {
        if (word.size() <= 3) return word;
        struct Rule { const char* suffix; const char* replacement; };
        static const Rule rules[] = {
            {"ational", "ate"}, {"tional", "tion"}, {"enci", "ence"}, {"anci", "ance"},
            {"izer", "ize"}, {"ising", "ise"}, {"izing", "ize"}, {"ating", "ate"},
            {"ation", "ate"}, {"ness", ""}, {"ment", ""}, {"ling", ""},
            {"ally", "al"}, {"ibly", "ible"}, {"ably", "able"},
            {"ing", ""}, {"tion", "t"}, {"sion", "s"},
            {"ful", ""}, {"ous", ""}, {"ive", ""}, {"ble", ""},
            {"ies", "y"}, {"ied", "y"}, {"ers", ""}, {"er", ""},
            {"ed", ""}, {"ly", ""}, {"es", ""}, {"s", ""},
        };
        for (const auto& rule : rules) {
            size_t suf_len = std::strlen(rule.suffix);
            size_t rep_len = std::strlen(rule.replacement);
            if (word.size() >= suf_len &&
                word.compare(word.size() - suf_len, suf_len, rule.suffix) == 0 &&
                word.size() - suf_len + rep_len >= 3) {
                return word.substr(0, word.size() - suf_len) + rule.replacement;
            }
        }
        return word;
    }

    // --- Unicode helpers ---

    /// Check if a Unicode codepoint is a word character (matches Python's _WORD_RE).
    /// Covers: ASCII alnum + Latin Extended + Cyrillic + Arabic + CJK + Japanese
    static bool is_word_char(uint32_t cp) {
        if (cp < 128) return std::isalnum(static_cast<unsigned char>(cp));
        return (cp >= 0x00C0 && cp <= 0x024F)   // Latin Extended (accents)
            || (cp >= 0x0400 && cp <= 0x04FF)    // Cyrillic
            || (cp >= 0x0600 && cp <= 0x06FF)    // Arabic
            || (cp >= 0x4E00 && cp <= 0x9FFF)    // CJK Unified Ideographs
            || (cp >= 0x3040 && cp <= 0x30FF);   // Japanese Hiragana + Katakana
    }

    /// Decode one UTF-8 codepoint from a string at position i.
    /// Advances i past the decoded character. Returns the codepoint.
    static uint32_t decode_utf8(const std::string& s, size_t& i) {
        auto b = static_cast<unsigned char>(s[i]);
        uint32_t cp;
        int extra;
        if (b < 0x80)      { cp = b; extra = 0; }
        else if (b < 0xC0) { cp = b; extra = 0; }  // continuation byte (error)
        else if (b < 0xE0) { cp = b & 0x1F; extra = 1; }
        else if (b < 0xF0) { cp = b & 0x0F; extra = 2; }
        else               { cp = b & 0x07; extra = 3; }
        for (int j = 0; j < extra && i + 1 < s.size(); ++j) {
            i++;
            cp = (cp << 6) | (static_cast<unsigned char>(s[i]) & 0x3F);
        }
        i++;
        return cp;
    }

    /// Lowercase a UTF-8 codepoint. Handles ASCII + basic Latin Extended.
    static uint32_t tolower_cp(uint32_t cp) {
        if (cp < 128) return static_cast<uint32_t>(std::tolower(static_cast<int>(cp)));
        // Basic Latin Extended uppercase → lowercase (À-Ö → à-ö, etc.)
        if (cp >= 0x00C0 && cp <= 0x00D6) return cp + 32;
        if (cp >= 0x00D8 && cp <= 0x00DE) return cp + 32;
        // Cyrillic uppercase → lowercase (А-Я → а-я)
        if (cp >= 0x0410 && cp <= 0x042F) return cp + 32;
        return cp;
    }

    /// Encode a codepoint to UTF-8 and append to a string.
    static void encode_utf8(std::string& out, uint32_t cp) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    // --- Feature extraction ---

    /// Extract weighted features from text with optional sender email.
    /// Returns features as (index, signed ln(1+|count|)) pairs.
    /// Uses signed hashing, word stemming, and character 3-grams.
    std::vector<Feature> extract_features(
        const std::string& text,
        const std::string& sender_email = "",
        // Flywheel contribution path (TASK-134): when portable (or the classifier
        // is configured cuckoo-off), every feature is bucketed state-independently
        // so indices are identical across devices; `hash_key` keys those buckets.
        // Defaults reproduce the shipped behavior exactly.
        bool portable = false,
        uint64_t hash_key = 0
    ) const {
        const bool use_portable = portable || !config_.cuckoo;
        // Count raw feature occurrences with signed hashing
        std::unordered_map<uint32_t, float> counts;
        counts.reserve(512);

        auto add = [&](const std::string& prefix, const std::string& token) {
            auto [idx, sign] = use_portable ? portable_hash(prefix + token, hash_key)
                                            : hash_signed(prefix + token);
            counts[idx] += sign;
        };

        // --- Split subject from body ---
        std::string subject;
        std::string body = text;
        auto nl = text.find('\n');
        if (nl != std::string::npos) {
            std::string first_line = text.substr(0, nl);
            // Check for "Subject:" prefix
            if (first_line.size() > 8) {
                std::string prefix8 = first_line.substr(0, 8);
                for (auto& c : prefix8) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (prefix8 == "subject:") {
                    subject = first_line.substr(8);
                    // Trim leading whitespace
                    auto start = subject.find_first_not_of(" \t");
                    if (start != std::string::npos) subject = subject.substr(start);
                    body = text.substr(nl + 1);
                } else {
                    subject = first_line;
                    body = text.substr(nl + 1);
                }
            } else {
                subject = first_line;
                body = text.substr(nl + 1);
            }
        }

        // --- Tokenize words with stemming (Unicode-aware) ---
        auto tokenize_with_prefix = [&](const std::string& prefix, const std::string& input) {
            std::string word;
            std::string prev;
            auto flush = [&]() {
                if (word.empty()) return;
                if (word.size() > 16) word.resize(16);
                std::string stemmed = stem(word);
                add(prefix, stemmed);                        // Stemmed unigram
                if (stemmed != word) add(prefix, word);      // Original too
                if (!prev.empty()) add(prefix, prev + "_" + stemmed);  // Stemmed bigram
                prev = std::move(stemmed);
                word.clear();
            };
            size_t i = 0;
            while (i < input.size()) {
                size_t start = i;
                uint32_t cp = decode_utf8(input, i);
                if (is_word_char(cp)) {
                    encode_utf8(word, tolower_cp(cp));
                } else {
                    flush();
                }
            }
            flush();
        };

        tokenize_with_prefix("b:", body);
        tokenize_with_prefix("s:", subject);

        // --- Character 3-grams (prefix "c:") ---
        // Catches obfuscation ("vi agra" → "via","iag","agr") and partial matches.
        // Unicode-aware: lowercases codepoints and checks is_word_char.
        {
            // Decode body to codepoints, lowercase, re-encode to UTF-8
            std::string body_lower;
            body_lower.reserve(body.size());
            {
                size_t bi = 0;
                while (bi < body.size()) {
                    uint32_t cp = decode_utf8(body, bi);
                    encode_utf8(body_lower, tolower_cp(cp));
                }
            }
            // Generate trigrams over the lowered UTF-8 string
            // We iterate by codepoints, not bytes, to handle multi-byte correctly
            std::vector<uint32_t> cps;
            cps.reserve(body_lower.size());
            std::vector<size_t> cp_offsets;  // byte offset of each codepoint
            cp_offsets.reserve(body_lower.size());
            {
                size_t bi = 0;
                while (bi < body_lower.size()) {
                    cp_offsets.push_back(bi);
                    cps.push_back(decode_utf8(body_lower, bi));
                }
            }
            for (size_t ci = 0; ci + 2 < cps.size(); ++ci) {
                if (is_word_char(cps[ci]) && is_word_char(cps[ci + 2])) {
                    // Extract 3-codepoint substring from body_lower
                    size_t start = cp_offsets[ci];
                    size_t end = (ci + 3 < cp_offsets.size()) ? cp_offsets[ci + 3] : body_lower.size();
                    add("c:", body_lower.substr(start, end - start));
                }
            }
        }

        // --- URL features ---
        {
            size_t pos = 0;
            int url_count = 0;
            while ((pos = text.find("http", pos)) != std::string::npos) {
                // Find URL end
                size_t start = pos;
                while (pos < text.size() && !std::isspace(static_cast<unsigned char>(text[pos]))
                       && text[pos] != '"' && text[pos] != '\'' && text[pos] != '<' && text[pos] != '>') {
                    pos++;
                }
                std::string url = text.substr(start, pos - start);
                // Extract domain (between :// and first /)
                auto scheme_end = url.find("://");
                if (scheme_end != std::string::npos) {
                    std::string after = url.substr(scheme_end + 3);
                    auto slash = after.find('/');
                    std::string domain = (slash != std::string::npos) ? after.substr(0, slash) : after;
                    for (auto& c : domain) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    add("u:", domain);
                    // Domain parts
                    size_t dpos = 0;
                    while (dpos < domain.size()) {
                        auto dot = domain.find('.', dpos);
                        std::string part = (dot != std::string::npos) ? domain.substr(dpos, dot - dpos) : domain.substr(dpos);
                        if (part.size() > 1) add("u:", part);
                        dpos = (dot != std::string::npos) ? dot + 1 : domain.size();
                    }
                }
                url_count++;
            }
            if (url_count > 0) {
                add("u:", "count:" + std::to_string(std::min(url_count, 10)));
            }
        }

        // --- Sender features ---
        if (!sender_email.empty()) {
            std::string email_lower = sender_email;
            for (auto& c : email_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            add("f:", email_lower);
            auto at = email_lower.find('@');
            if (at != std::string::npos) {
                std::string domain = email_lower.substr(at + 1);
                add("f:", domain);
                auto dot = domain.rfind('.');
                if (dot != std::string::npos) {
                    add("f:", "tld:" + domain.substr(dot + 1));
                }
            }
        }

        // --- Email addresses in body ---
        {
            size_t pos = 0;
            int found = 0;
            while (pos < text.size() && found < 5) {
                auto at = text.find('@', pos);
                if (at == std::string::npos || at == 0) break;
                // Find domain end
                size_t end = at + 1;
                while (end < text.size() && (std::isalnum(static_cast<unsigned char>(text[end]))
                       || text[end] == '.' || text[end] == '-')) {
                    end++;
                }
                if (end > at + 2) {
                    std::string domain = text.substr(at + 1, end - at - 1);
                    for (auto& c : domain) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    add("e:", domain);
                    found++;
                }
                pos = end;
            }
        }

        // --- Structural features ---
        {
            int alpha_count = 0, upper_count = 0;
            int excl_count = 0;
            bool has_dollar = false;
            for (char c : body) {
                if (std::isalpha(static_cast<unsigned char>(c))) {
                    alpha_count++;
                    if (std::isupper(static_cast<unsigned char>(c))) upper_count++;
                }
                if (c == '!') excl_count++;
                if (c == '$') has_dollar = true;
            }
            if (alpha_count > 20) {
                float ratio = static_cast<float>(upper_count) / static_cast<float>(alpha_count);
                if (ratio > 0.7f) add("x:", "allcaps");
                else if (ratio > 0.3f) add("x:", "mixedcaps");
            }
            if (excl_count >= 3) {
                add("x:", "excl:" + std::to_string(std::min(excl_count, 10)));
            }
            if (has_dollar) add("x:", "has_dollar");
        }

        // --- Number/amount patterns (prefix "n:") ---
        // "$99.99" → "n:$DD.DD", "100%" → "n:DDD%". Shape not value.
        {
            for (size_t i = 0; i < body.size(); ++i) {
                char c = body[i];
                if (std::isdigit(static_cast<unsigned char>(c)) ||
                    c == '$' || c == '\xe2') {  // € starts with 0xe2 in UTF-8
                    // Found start of a potential number. Collect the pattern.
                    std::string pattern = "n:";
                    size_t j = i;
                    if (c == '$' || c == '\xe2') { pattern += c; j++; }
                    while (j < body.size()) {
                        char d = body[j];
                        if (std::isdigit(static_cast<unsigned char>(d))) { pattern += 'D'; j++; }
                        else if (d == '.' || d == ',' || d == '%') { pattern += d; j++; }
                        else break;
                    }
                    if (pattern.size() > 3) {  // At least "n:DD"
                        add("", pattern);
                        i = j - 1;  // Skip past the number
                    }
                }
            }
        }

        // --- Alphanumeric classification (prefix "a:") ---
        // "V1AGRA" → "a:U7", "FR33" → "a:U4". Composition + length.
        {
            std::string token;
            for (size_t i = 0; i <= body.size(); ++i) {
                char c = (i < body.size()) ? body[i] : ' ';
                if (std::isalnum(static_cast<unsigned char>(c))) {
                    token += c;
                } else if (!token.empty()) {
                    if (token.size() >= 3) {
                        bool has_alpha = false, has_digit = false;
                        int upper = 0, lower = 0, digit = 0;
                        for (char t : token) {
                            if (std::isalpha(static_cast<unsigned char>(t))) {
                                has_alpha = true;
                                if (std::isupper(static_cast<unsigned char>(t))) upper++;
                                else lower++;
                            } else if (std::isdigit(static_cast<unsigned char>(t))) {
                                has_digit = true;
                                digit++;
                            }
                        }
                        if (has_alpha && has_digit) {
                            char comp;
                            if (digit > static_cast<int>(token.size()) / 2) comp = 'D';
                            else if (upper > lower) comp = 'U';
                            else comp = 'L';
                            int len = std::min(static_cast<int>(token.size()), 16);
                            add("", "a:" + std::string(1, comp) + std::to_string(len));
                        }
                    }
                    token.clear();
                }
            }
        }

        // Convert counts to signed ln(1+|count|) weighted features.
        // Sign from hashing is preserved; magnitude uses log scaling.
        std::vector<Feature> features;
        features.reserve(counts.size());
        for (auto& [idx, count] : counts) {
            if (count == 0.0f) continue;
            float sign = count > 0.0f ? 1.0f : -1.0f;
            features.push_back({idx, sign * std::log1p(std::abs(count))});
        }
        return features;
    }

    // --- Flywheel contribution (TASK-134) ---

    /// Extract a PORTABLE, state-independent contribution bag from a message:
    /// `{ bucket -> signed ln(1+count) }`, the exact same derived representation the
    /// FTRL model trains on — but bucketed independently of this device's model
    /// state, so the server can aggregate the same feature across users. This is
    /// the only thing the flywheel ever uploads: hash buckets + weights, no raw
    /// text. `hash_key != 0` keys the buckets.
    ///
    /// Inert by construction: this just computes a value. It does not transmit
    /// anything and nothing in the shipped classify/learn path calls it.
    std::map<uint32_t, float> extract_contribution(
        const std::string& text,
        const std::string& sender_email = "",
        uint64_t hash_key = 0
    ) const {
        const auto features = extract_features(text, sender_email, /*portable=*/true, hash_key);
        std::map<uint32_t, float> bag;  // ordered → deterministic serialization
        for (const auto& f : features) bag[f.idx] = f.weight;
        return bag;
    }

    // --- Prediction ---

    /// Compute P(spam) from a feature vector.
    /// Sums weight[i] * feature_value[i] for all features, adds bias, applies sigmoid.
    float predict(const std::vector<Feature>& features) const {
        float wtx = compute_bias();
        for (const auto& f : features) {
            wtx += compute_weight(f.idx) * f.weight;
        }
        return sigmoid(wtx);
    }

    /// Convenience: extract features from text and predict in one call.
    float predict_text(const std::string& text, const std::string& sender_email = "") const {
        return predict(extract_features(text, sender_email));
    }

    // --- Learning ---

    /// Update weights from one labeled example (online learning).
    ///
    /// The FTRL-Proximal update rule per feature i:
    ///   1. Compute gradient: g_i = (prediction - label) * feature_value
    ///   2. Update adaptive learning rate: n[i] += g_i^2
    ///   3. Update gradient accumulator: z[i] += g_i - sigma * w[i]
    ///      where sigma adjusts for the changing learning rate
    ///   4. Next prediction computes w[i] from z[i] and n[i], applying
    ///      L1 sparsity (w=0 if |z| < lambda1)
    ///
    /// This is called once per user correction (spam→ham or ham→spam).
    void learn(const std::vector<Feature>& features, bool is_spam) {
        float p = predict(features);
        float grad = p - (is_spam ? 1.0f : 0.0f);  // Log-loss gradient

        for (const auto& f : features) {
            float g_i = grad * f.weight;             // Gradient scaled by feature value
            float w_i = compute_weight(f.idx);
            float sigma_i = (std::sqrt(n_[f.idx] + g_i * g_i) - std::sqrt(n_[f.idx])) / config_.alpha;
            z_[f.idx] += g_i - sigma_i * w_i;       // Update gradient direction
            n_[f.idx] += g_i * g_i;                  // Update gradient magnitude
        }

        // Bias update (same rule, no feature value scaling)
        float b = compute_bias();
        float sigma_b = (std::sqrt(bias_n_ + grad * grad) - std::sqrt(bias_n_)) / config_.alpha;
        bias_z_ += grad - sigma_b * b;
        bias_n_ += grad * grad;

        if (is_spam) spam_learns_++;
        else ham_learns_++;
    }

    /// Convenience: extract features and learn in one call.
    void learn_text(const std::string& text, bool is_spam, const std::string& sender_email = "") {
        auto features = extract_features(text, sender_email);
        learn(features, is_spam);
    }

    /// Train on a batch of texts. Multiple passes improve convergence on small datasets.
    void train_batch(const std::vector<std::string>& texts, const std::vector<bool>& labels,
                     int passes = 3) {
        for (int pass = 0; pass < passes; ++pass) {
            for (size_t i = 0; i < texts.size(); ++i) {
                learn_text(texts[i], labels[i]);
            }
        }
    }

    // --- Persistence ---
    //
    // Binary format v2 (compatible with Python classifiers/ftrl.py):
    //   Header: magic(4) + version(4) + hash_bits(4) + spam_learns(4) + ham_learns(4)
    //   Config: alpha(4) + beta(4) + lambda1(4) + lambda2(4)
    //   Bias:   bias_z(4) + bias_n(4)  [v2 only]
    //   Data:   z[num_features](4*N) + n[num_features](4*N)
    //
    // Total: 44 + 8*num_features bytes (e.g. 8,388,652 bytes for 2^20 slots)

    /// Save weights to a flat binary file.
    bool save(const std::string& path) const {
        std::ofstream f(path, std::ios::binary);
        if (!f) return false;

        uint32_t magic = 0x4654524Cu;  // "FTRL"
        uint32_t version = 2;
        f.write(reinterpret_cast<const char*>(&magic), 4);
        f.write(reinterpret_cast<const char*>(&version), 4);
        f.write(reinterpret_cast<const char*>(&config_.hash_bits), 4);
        f.write(reinterpret_cast<const char*>(&spam_learns_), 4);
        f.write(reinterpret_cast<const char*>(&ham_learns_), 4);

        f.write(reinterpret_cast<const char*>(&config_.alpha), 4);
        f.write(reinterpret_cast<const char*>(&config_.beta), 4);
        f.write(reinterpret_cast<const char*>(&config_.lambda1), 4);
        f.write(reinterpret_cast<const char*>(&config_.lambda2), 4);

        // v2: bias
        f.write(reinterpret_cast<const char*>(&bias_z_), 4);
        f.write(reinterpret_cast<const char*>(&bias_n_), 4);

        f.write(reinterpret_cast<const char*>(z_.data()), num_features_ * sizeof(float));
        f.write(reinterpret_cast<const char*>(n_.data()), num_features_ * sizeof(float));
        return f.good();
    }

    bool load(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return false;

        uint32_t magic, version, hash_bits;
        f.read(reinterpret_cast<char*>(&magic), 4);
        f.read(reinterpret_cast<char*>(&version), 4);
        f.read(reinterpret_cast<char*>(&hash_bits), 4);
        f.read(reinterpret_cast<char*>(&spam_learns_), 4);
        f.read(reinterpret_cast<char*>(&ham_learns_), 4);

        if (magic != 0x4654524Cu) return false;

        // hash_bits comes straight from the file header (corruption- or
        // attacker-controlled). 1u<<hash_bits is undefined for >=32, and large
        // values request multi-GB allocations below — bound it (default is 20).
        if (hash_bits < 4 || hash_bits > 26) return false;

        if (hash_bits != config_.hash_bits) {
            config_.hash_bits = hash_bits;
            num_features_ = 1u << hash_bits;
            z_.resize(num_features_);
            n_.resize(num_features_);
        }

        f.read(reinterpret_cast<char*>(&config_.alpha), 4);
        f.read(reinterpret_cast<char*>(&config_.beta), 4);
        f.read(reinterpret_cast<char*>(&config_.lambda1), 4);
        f.read(reinterpret_cast<char*>(&config_.lambda2), 4);

        if (version >= 2) {
            f.read(reinterpret_cast<char*>(&bias_z_), 4);
            f.read(reinterpret_cast<char*>(&bias_n_), 4);
        }

        f.read(reinterpret_cast<char*>(z_.data()), num_features_ * sizeof(float));
        f.read(reinterpret_cast<char*>(n_.data()), num_features_ * sizeof(float));
        return f.good();
    }

    // --- Stats ---
    uint32_t spam_learns() const { return spam_learns_; }
    uint32_t ham_learns() const { return ham_learns_; }
    uint32_t total_learns() const { return spam_learns_ + ham_learns_; }
    uint32_t num_features() const { return num_features_; }

    uint32_t active_features() const {
        uint32_t count = 0;
        for (uint32_t i = 0; i < num_features_; ++i) {
            if (std::abs(z_[i]) > config_.lambda1) count++;
        }
        return count;
    }

    size_t memory_bytes() const {
        return num_features_ * 2 * sizeof(float) + 8;  // z[] + n[] + bias
    }

private:
    /// Compute the effective weight for slot i from its FTRL accumulators.
    /// This is the "lazy weight" trick: we never store w[i] directly.
    /// Instead we compute it on-the-fly from z[i] and n[i].
    /// If |z[i]| <= lambda1, the weight is exactly zero (L1 sparsity).
    float compute_weight(uint32_t i) const {
        if (std::abs(z_[i]) <= config_.lambda1) return 0.0f;  // L1 prunes this feature
        float sign_z = z_[i] > 0 ? 1.0f : -1.0f;
        return -(z_[i] - sign_z * config_.lambda1) /
               ((config_.beta + std::sqrt(n_[i])) / config_.alpha + config_.lambda2);
    }

    /// Compute the bias (intercept) weight. Same formula without L1 sparsity.
    float compute_bias() const {
        if (bias_n_ <= 0.0f) return 0.0f;
        return -bias_z_ / ((config_.beta + std::sqrt(bias_n_)) / config_.alpha + config_.lambda2);
    }

    /// Numerically stable sigmoid. Clamped to prevent exp() overflow.
    static float sigmoid(float x) {
        if (x > 35.0f) return 1.0f;
        if (x < -35.0f) return 0.0f;
        return 1.0f / (1.0f + std::exp(-x));
    }

    Config config_;
    uint32_t num_features_;        // = 2^hash_bits, the size of the weight arrays
    std::vector<float> z_;         // FTRL z accumulator per slot (gradient direction)
    std::vector<float> n_;         // FTRL n accumulator per slot (sum of squared gradients)
    float bias_z_;                 // Bias z accumulator
    float bias_n_;                 // Bias n accumulator
    uint32_t spam_learns_;         // Count of spam examples trained on
    uint32_t ham_learns_;          // Count of ham examples trained on
};
