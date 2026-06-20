#include "health_server.h"

#include "config.h"

#include <arpa/inet.h>
#include <cstring>
#include <netdb.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace klar {

HealthServer::HealthServer() = default;

HealthServer::~HealthServer() { stop(); }

// ---------------------------------------------------------------------------
// start / stop
// ---------------------------------------------------------------------------

bool HealthServer::start(const std::string& listen_addr,
                         ReadyChecker ready_fn,
                         MetricsProvider metrics_fn) {
    if (running_.load()) return false;

    ready_fn_ = std::move(ready_fn);
    metrics_fn_ = std::move(metrics_fn);

    // Parse "host:port" via the shared splitter (same rule the config validator
    // uses, so validation and binding can't disagree). No port component means a
    // bare port — bind all interfaces (validate_config rejects this form, so it
    // should not reach here).
    std::string host;
    std::string port;
    if (!split_host_port(listen_addr, host, port)) {
        host = "0.0.0.0";
        port = listen_addr;
    }

    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;  // allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo* res = nullptr;
    int gai = getaddrinfo(host.empty() ? nullptr : host.c_str(),
                          port.c_str(), &hints, &res);
    if (gai != 0 || !res) return false;

    server_fd_ = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (server_fd_ < 0) {
        freeaddrinfo(res);
        return false;
    }

    int opt = 1;
    setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Set a 1-second accept timeout so the serve loop can check running_.
    struct timeval tv{};
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(server_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (bind(server_fd_, res->ai_addr, res->ai_addrlen) < 0) {
        freeaddrinfo(res);
        ::close(server_fd_);
        server_fd_ = -1;
        return false;
    }
    freeaddrinfo(res);

    if (listen(server_fd_, 8) < 0) {
        ::close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    running_.store(true);
    thread_ = std::thread(&HealthServer::serve_loop, this);
    return true;
}

void HealthServer::stop() {
    if (!running_.load()) return;

    running_.store(false);

    // Close the listening socket to unblock accept().
    if (server_fd_ >= 0) {
        ::close(server_fd_);
        server_fd_ = -1;
    }

    if (thread_.joinable()) thread_.join();
}

// ---------------------------------------------------------------------------
// serve_loop / handle_connection
// ---------------------------------------------------------------------------

void HealthServer::serve_loop() {
    while (running_.load()) {
        struct sockaddr_storage client_addr{};  // IPv4 or IPv6
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd_,
                               reinterpret_cast<struct sockaddr*>(&client_addr),
                               &addr_len);
        if (client_fd < 0) {
            // Timeout or interrupted -- just loop and recheck running_.
            continue;
        }
        handle_connection(client_fd);
        ::close(client_fd);
    }
}

static void send_response(int fd, int code, const char* reason,
                          const std::string& body) {
    std::ostringstream resp;
    resp << "HTTP/1.1 " << code << " " << reason << "\r\n"
         << "Content-Length: " << body.size() << "\r\n"
         << "Content-Type: text/plain\r\n"
         << "\r\n"
         << body;
    std::string s = resp.str();
    // Best-effort write; ignore partial sends for this internal endpoint.
    ::write(fd, s.data(), s.size());
}

void HealthServer::handle_connection(int client_fd) {
    // Read enough of the request to determine the method and path.
    char buf[1024];
    ssize_t n = ::read(client_fd, buf, sizeof(buf) - 1);
    if (n <= 0) return;
    buf[n] = '\0';

    // Parse the request line: "METHOD /path HTTP/1.x\r\n..."
    std::string request(buf, static_cast<size_t>(n));
    std::string method;
    std::string path;

    auto sp1 = request.find(' ');
    if (sp1 != std::string::npos) {
        method = request.substr(0, sp1);
        auto sp2 = request.find(' ', sp1 + 1);
        if (sp2 != std::string::npos) {
            path = request.substr(sp1 + 1, sp2 - sp1 - 1);
        }
    }

    if (method != "GET") {
        send_response(client_fd, 404, "Not Found", "not found");
        return;
    }

    if (path == "/livez") {
        send_response(client_fd, 200, "OK", "ok");
    } else if (path == "/readyz") {
        bool ready = ready_fn_ ? ready_fn_() : false;
        if (ready) {
            send_response(client_fd, 200, "OK", "ok");
        } else {
            send_response(client_fd, 503, "Service Unavailable", "not ready");
        }
    } else if (path == "/metrics") {
        std::string body = metrics_fn_ ? metrics_fn_() : "";
        send_response(client_fd, 200, "OK", body);
    } else {
        send_response(client_fd, 404, "Not Found", "not found");
    }
}

} // namespace klar
