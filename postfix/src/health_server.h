#pragma once
#include <atomic>
#include <functional>
#include <string>
#include <thread>

namespace klar {

class HealthServer {
public:
    using ReadyChecker = std::function<bool()>;
    using MetricsProvider = std::function<std::string()>;

    HealthServer();
    ~HealthServer();

    bool start(const std::string& listen_addr, ReadyChecker ready_fn, MetricsProvider metrics_fn);
    void stop();

private:
    std::atomic<bool> running_{false};
    std::thread thread_;
    int server_fd_ = -1;
    ReadyChecker ready_fn_;
    MetricsProvider metrics_fn_;

    void serve_loop();
    void handle_connection(int client_fd);
};

} // namespace klar
