#include "config.h"
#include "model_runtime.h"
#include "policy.h"
#include <fstream>
#include <sstream>
#include <chrono>
#include <cstring>
#include <cstdio>

#ifndef KLAR_VERSION
#define KLAR_VERSION "1.0.0"
#endif

#ifndef KLAR_GIT_SHA
#define KLAR_GIT_SHA "unknown"
#endif

static void print_usage(const char* argv0) {
    fprintf(stderr,
        "Usage:\n"
        "  %s --config <path> --eml <path> --json\n"
        "    Classify an .eml file and output JSON.\n"
        "\n"
        "Options:\n"
        "  --version         Print version and exit\n"
        "  --help            Print this help and exit\n",
        argv0);
}

// Extract the email address from a From: header line.
static std::string extract_from_email(const std::string& raw) {
    std::istringstream stream(raw);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) break;

        if (line.size() >= 5 &&
            (line[0] == 'F' || line[0] == 'f') &&
            (line[1] == 'R' || line[1] == 'r') &&
            (line[2] == 'O' || line[2] == 'o') &&
            (line[3] == 'M' || line[3] == 'm') &&
            line[4] == ':') {

            std::string value = line.substr(5);
            size_t start = value.find_first_not_of(" \t");
            if (start == std::string::npos) continue;
            value = value.substr(start);

            size_t lt = value.find('<');
            size_t gt = value.find('>', lt != std::string::npos ? lt : 0);
            if (lt != std::string::npos && gt != std::string::npos && gt > lt) {
                return value.substr(lt + 1, gt - lt - 1);
            }
            return value;
        }
    }
    return "";
}

static std::string escape_json_string(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:   out += c; break;
        }
    }
    return out;
}

// ---- classify ----

static int cmd_classify(int argc, char* argv[]) {
    std::string config_path;
    std::string eml_path;
    bool json_output = false;

    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "--eml") == 0 && i + 1 < argc) {
            eml_path = argv[++i];
        } else if (strcmp(argv[i], "--json") == 0) {
            json_output = true;
        }
    }

    if (config_path.empty()) {
        fprintf(stderr, "error: --config is required\n");
        return 2;
    }
    if (eml_path.empty()) {
        fprintf(stderr, "error: --eml is required\n");
        return 2;
    }
    if (!json_output) {
        fprintf(stderr, "error: --json is required\n");
        return 2;
    }

    // Load config
    klar::Config cfg;
    try {
        cfg = klar::load_config(config_path);
    } catch (const std::exception& e) {
        fprintf(stderr, "error: failed to load config %s: %s\n",
                config_path.c_str(), e.what());
        return 2;
    }

    std::string err = klar::validate_config(cfg);
    if (!err.empty()) {
        fprintf(stderr, "error: invalid config: %s\n", err.c_str());
        return 2;
    }

    // Load model
    klar::ModelRuntime runtime;
    if (!runtime.load(cfg)) {
        fprintf(stderr, "error: failed to load model from %s\n",
                cfg.model_dir.c_str());
        return 3;
    }

    // Read .eml file
    std::ifstream ifs(eml_path, std::ios::binary);
    if (!ifs.is_open()) {
        fprintf(stderr, "error: cannot open eml file: %s\n", eml_path.c_str());
        return 2;
    }
    std::ostringstream ss;
    ss << ifs.rdbuf();
    std::string raw_email = ss.str();
    ifs.close();

    if (raw_email.empty()) {
        fprintf(stderr, "error: eml file is empty: %s\n", eml_path.c_str());
        return 2;
    }

    // Extract From header for policy evaluation
    std::string sender_email = extract_from_email(raw_email);

    // Classify
    auto t0 = std::chrono::steady_clock::now();
    klar::ClassifyResult cr = runtime.classify_rfc822(raw_email, "", sender_email);
    auto t1 = std::chrono::steady_clock::now();
    double latency_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    // Evaluate policy
    std::vector<std::string> rcpt = {"inbox@example.org"};
    klar::PolicyResult pr = klar::evaluate_policy(
        cfg, cr, sender_email, rcpt, !cr.ok, false);

    // Build JSON output
    char score_spam[32], score_regular[32], score_marketing[32], score_gibberish[32];
    char score_spam_adjusted[32];
    char latency_buf[32];
    snprintf(score_spam, sizeof(score_spam), "%.6f", (double)pr.score_spam);
    snprintf(score_regular, sizeof(score_regular), "%.6f", (double)pr.score_regular);
    snprintf(score_marketing, sizeof(score_marketing), "%.6f", (double)pr.score_marketing);
    snprintf(score_gibberish, sizeof(score_gibberish), "%.6f", (double)pr.score_gibberish);
    snprintf(score_spam_adjusted, sizeof(score_spam_adjusted), "%.6f", (double)pr.score_spam_adjusted);
    snprintf(latency_buf, sizeof(latency_buf), "%.2f", latency_ms);

    std::string action_str = klar::action_to_string(pr.action);
    std::string error_str = (pr.status != "ok") ? pr.error_code : "";

    printf("{\n"
           "  \"message_path\": \"%s\",\n"
           "  \"mode\": \"%s\",\n"
           "  \"threshold_profile\": \"%s\",\n"
           "  \"score_spam\": %s,\n"
           "  \"score_regular\": %s,\n"
           "  \"score_marketing\": %s,\n"
           "  \"score_gibberish\": %s,\n"
           "  \"score_spam_adjusted\": %s,\n"
           "  \"label\": \"%s\",\n"
           "  \"action\": \"%s\",\n"
           "  \"latency_ms\": %s,\n"
           "  \"status\": \"%s\",\n"
           "  \"error\": \"%s\"\n"
           "}\n",
           escape_json_string(eml_path).c_str(),
           escape_json_string(cfg.mode).c_str(),
           escape_json_string(cfg.profile).c_str(),
           score_spam, score_regular, score_marketing, score_gibberish, score_spam_adjusted,
           escape_json_string(pr.label).c_str(),
           escape_json_string(action_str).c_str(),
           latency_buf,
           escape_json_string(pr.status).c_str(),
           escape_json_string(error_str).c_str());

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 2;
    }

    // Check for global flags first
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("klar-policy-cli %s (%s)\n", KLAR_VERSION, KLAR_GIT_SHA);
            return 0;
        }
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    return cmd_classify(argc - 1, argv + 1);
}
