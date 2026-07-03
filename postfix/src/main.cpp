#include "config.h"
#include "model_runtime.h"
#include "event_store.h"
#include "health_server.h"
#include "milter_server.h"
#include <libmilter/mfapi.h>
#include <csignal>
#include <iostream>
#include <memory>
#include <string>
#include <cstring>
#include <thread>
#include <chrono>
#include <cmath>

#ifndef KLAR_VERSION
#define KLAR_VERSION "1.0.0"
#endif

#ifndef KLAR_GIT_SHA
#define KLAR_GIT_SHA "unknown"
#endif

static volatile sig_atomic_t g_reload_requested = 0;
static volatile sig_atomic_t g_shutdown_requested = 0;

static void handle_sighup(int) {
    g_reload_requested = 1;
}

static void handle_sigterm(int) {
    g_shutdown_requested = 1;
    smfi_stop();
}

static void log_msg(bool json, const std::string& level, const std::string& msg) {
    if (json) {
        fprintf(stderr, "{\"level\":\"%s\",\"msg\":\"%s\"}\n", level.c_str(), msg.c_str());
    } else {
        fprintf(stderr, "[%s] %s\n", level.c_str(), msg.c_str());
    }
}

static void print_usage(const char* argv0) {
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  --config <path>   Config file (default: /etc/klar/postfix.toml)\n"
        "  --version         Print version and exit\n"
        "  --help            Print this help and exit\n",
        argv0);
}

int main(int argc, char* argv[]) {
    std::string config_path = "/etc/klar/postfix.toml";

    // --- Parse CLI args ---
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("klar-milterd %s (%s)\n", KLAR_VERSION, KLAR_GIT_SHA);
            return 0;
        }
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "error: --config requires a path argument\n");
                return 2;
            }
            config_path = argv[++i];
            continue;
        }
        fprintf(stderr, "error: unknown option: %s\n", argv[i]);
        print_usage(argv[0]);
        return 2;
    }

    // --- Load and validate config ---
    auto cfg = std::make_shared<klar::Config>();
    try {
        *cfg = klar::load_config(config_path);
    } catch (const std::exception& e) {
        fprintf(stderr, "error: failed to load config %s: %s\n",
                config_path.c_str(), e.what());
        return 2;
    }

    std::string err = klar::validate_config(*cfg);
    if (!err.empty()) {
        fprintf(stderr, "error: invalid config: %s\n", err.c_str());
        return 2;
    }

    log_msg(cfg->log_json, "info", "config loaded from " + config_path);

    // --- Load model ---
    klar::ModelRuntime runtime;
    if (!runtime.load(*cfg)) {
        if (!cfg->fail_open) {
            log_msg(cfg->log_json, "error", "model load failed and fail_open=false, exiting");
            return 1;
        }
        log_msg(cfg->log_json, "warn", "model load failed but fail_open=true, continuing");
    } else {
        log_msg(cfg->log_json, "info",
                "model loaded, version=" + runtime.loaded_model_version());
    }

    // --- Smoke inference ---
    if (runtime.is_loaded()) {
        const char* smoke_email =
            "From: smoke@test.local\r\n"
            "To: check@test.local\r\n"
            "Subject: smoke test\r\n"
            "\r\n"
            "This is a smoke test email.\r\n";

        auto result = runtime.classify_rfc822(smoke_email, "", "smoke@test.local");
        if (!result.ok) {
            log_msg(cfg->log_json, "error",
                    "smoke inference failed: " + result.error);
            if (!cfg->fail_open) return 1;
        } else {
            // Per-score [0,1] sanity + a sum LOWER bound. NOT sum≈1: in ensemble
            // mode scores.spam is the escalate-only spam side (max of neural and
            // the FTRL blend), so the four values are intentionally not a
            // normalized softmax and can sum above 1 when a warm FTRL escalates
            // (TASK-38). But the non-spam classes stay a raw-neural softmax, so a
            // valid result always sums to >= ~1; the `sum < 0.5` floor catches a
            // dead/zeroed model ({0,0,0,0}) that the per-score bounds would pass.
            const float sum = result.spam + result.regular + result.marketing + result.gibberish;
            auto bad = [](float x) { return !std::isfinite(x) || x < -0.01f || x > 1.01f; };
            if (bad(result.spam) || bad(result.regular) ||
                bad(result.marketing) || bad(result.gibberish) || sum < 0.5f) {
                char buf[256];
                snprintf(buf, sizeof(buf),
                         "smoke inference scores not sane: spam=%.4f regular=%.4f "
                         "marketing=%.4f gibberish=%.4f sum=%.4f",
                         result.spam, result.regular, result.marketing,
                         result.gibberish, sum);
                log_msg(cfg->log_json, "error", buf);
                if (!cfg->fail_open) return 1;
            } else {
                log_msg(cfg->log_json, "info", "smoke inference passed");
            }
        }
    }

    // --- Open event store ---
    klar::EventStore store;
    if (!store.open(cfg->event_store_path)) {
        log_msg(cfg->log_json, "warn",
                "failed to open event store at " + cfg->event_store_path);
    } else {
        log_msg(cfg->log_json, "info",
                "event store opened at " + cfg->event_store_path);
    }

    // --- Set global state for milter callbacks ---
    klar::ServerState state;
    klar::set_global_state(cfg, &runtime, &store, &state);

    // --- Start health server ---
    klar::HealthServer health;
    if (cfg->health_enabled) {
        bool ok = health.start(
            cfg->health_listen,
            [&runtime]() -> bool { return runtime.is_loaded(); },
            [&state, &runtime]() -> std::string {
                return klar::generate_metrics(state, runtime);
            });
        if (ok) {
            log_msg(cfg->log_json, "info",
                    "health server listening on " + cfg->health_listen);
        } else {
            log_msg(cfg->log_json, "warn",
                    "failed to start health server on " + cfg->health_listen);
        }
    }

    // --- Install signal handlers ---
    struct sigaction sa_hup = {};
    sa_hup.sa_handler = handle_sighup;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = SA_RESTART;
    sigaction(SIGHUP, &sa_hup, nullptr);

    struct sigaction sa_term = {};
    sa_term.sa_handler = handle_sigterm;
    sigemptyset(&sa_term.sa_mask);
    sa_term.sa_flags = 0;
    sigaction(SIGTERM, &sa_term, nullptr);
    sigaction(SIGINT, &sa_term, nullptr);

    // --- SIGHUP reload watcher thread ---
    // Capture listen address — changing it requires restart, not reload.
    std::string frozen_listen = cfg->listen;
    std::thread reload_thread([&cfg, &runtime, &config_path, frozen_listen]() {
        while (!g_shutdown_requested) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            if (g_reload_requested) {
                g_reload_requested = 0;
                log_msg(cfg->log_json, "info", "SIGHUP received, reloading config and model");

                try {
                    auto new_cfg = std::make_shared<klar::Config>(
                        klar::load_config(config_path));
                    std::string verr = klar::validate_config(*new_cfg);
                    if (!verr.empty()) {
                        log_msg(cfg->log_json, "error",
                                "reload: invalid config: " + verr);
                        continue;
                    }
                    // Reload model if needed
                    if (runtime.reload_if_needed(*new_cfg)) {
                        log_msg(cfg->log_json, "info",
                                "model reloaded, version=" + runtime.loaded_model_version());
                    }
                    // Preserve listen address (requires restart to change)
                    // const_cast is safe: we own this object and haven't published it yet
                    const_cast<klar::Config&>(*new_cfg).listen = frozen_listen;

                    // Atomically swap — in-flight callbacks keep their snapshot
                    klar::swap_global_config(new_cfg);
                    cfg = std::move(new_cfg);
                    log_msg(cfg->log_json, "info", "config reloaded successfully");
                } catch (const std::exception& e) {
                    log_msg(cfg->log_json, "error",
                            std::string("reload failed: ") + e.what());
                }
            }
        }
    });
    reload_thread.detach();

    // --- Start milter ---
    int rc = klar::milter_setup(*cfg);
    if (rc != MI_SUCCESS) {
        log_msg(cfg->log_json, "error", "milter_setup failed");
        return 1;
    }

    log_msg(cfg->log_json, "info",
            "klar-milterd starting on " + cfg->listen);

    rc = smfi_main();

    // --- Shutdown drain ---
    log_msg(cfg->log_json, "info", "klar-milterd shutting down");
    g_shutdown_requested = 1;
    state.shutting_down.store(true, std::memory_order_release);

    int drain_timeout_ms = cfg->shutdown_drain_timeout_ms;
    int exit_code = (rc == MI_SUCCESS) ? 0 : 1;

    if (state.inflight_sessions.load(std::memory_order_relaxed) > 0 && drain_timeout_ms > 0) {
        log_msg(cfg->log_json, "info",
                "waiting up to " + std::to_string(drain_timeout_ms) + "ms for in-flight sessions to drain");

        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(drain_timeout_ms);
        while (state.inflight_sessions.load(std::memory_order_relaxed) > 0) {
            if (std::chrono::steady_clock::now() >= deadline) {
                log_msg(cfg->log_json, "warn",
                        "drain timeout expired with " +
                        std::to_string(state.inflight_sessions.load(std::memory_order_relaxed)) +
                        " sessions still in flight");
                exit_code = 124;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        if (exit_code != 124) {
            log_msg(cfg->log_json, "info", "all sessions drained");
        }
    }

    health.stop();
    store.close();

    return exit_code;
}
