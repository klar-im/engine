#pragma once
#include <mutex>
#include <string>

struct sqlite3;

namespace klar {

struct DecisionEvent {
    std::string ts;              // RFC3339
    std::string queue_id;
    std::string mail_from;
    int rcpt_count = 0;
    int64_t bytes_seen = 0;
    bool truncated = false;
    std::string model_version;
    float score_spam = 0;
    float score_regular = 0;
    float score_marketing = 0;
    float score_gibberish = 0;
    std::string label;           // "spam" or "regular"
    std::string action;          // "tag", "reject", "bypass"
    double latency_ms = 0;
    std::string status;          // "ok" or "error"
    std::string error_code;      // "E_NONE", "E_ENGINE_LOAD", etc.
    std::string message_id_header;
    std::string event_id;        // UUIDv4
    std::string policy_reason;   // "ml", "allowlist_sender", etc.
};

struct FeedbackEvent {
    std::string ts;
    std::string event_id;    // references DecisionEvent.event_id
    std::string verdict;     // "spam" or "ham"
    std::string source;      // "sieve", "cli", "api"
    std::string reporter;    // IMAP username or empty
};

class EventStore {
public:
    EventStore();
    ~EventStore();

    bool open(const std::string& path);
    bool record(const DecisionEvent& event);
    bool record_feedback(const FeedbackEvent& fb);
    void close();
    bool is_open() const;

private:
    sqlite3* db_ = nullptr;
    mutable std::mutex mutex_;
    bool ensure_schema();
};

// Generate a UUIDv4 string
std::string generate_uuid();

// Get current time as RFC3339 string with millis
std::string now_rfc3339();

// Format a DecisionEvent as JSON for stdout logging
std::string event_to_json(const DecisionEvent& event);

} // namespace klar
