#include "event_store.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>

#include <sqlite3.h>

namespace klar {

// ---------------------------------------------------------------------------
// EventStore
// ---------------------------------------------------------------------------

EventStore::EventStore() = default;

EventStore::~EventStore() { close(); }

bool EventStore::open(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_) return false;

    int rc = sqlite3_open(path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return false;
    }

    // Enable WAL mode for better concurrent read performance.
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);

    if (!ensure_schema()) {
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }

    return true;
}

bool EventStore::ensure_schema() {
    const char* ddl = R"SQL(
CREATE TABLE IF NOT EXISTS events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ts               TEXT    NOT NULL,
    queue_id         TEXT    NOT NULL,
    mail_from        TEXT    NOT NULL,
    rcpt_count       INTEGER NOT NULL,
    bytes_seen       INTEGER NOT NULL,
    truncated        INTEGER NOT NULL,
    model_version    TEXT    NOT NULL,
    score_spam       REAL    NOT NULL,
    score_regular    REAL    NOT NULL,
    score_marketing  REAL    NOT NULL,
    score_gibberish  REAL    NOT NULL,
    label            TEXT    NOT NULL,
    action           TEXT    NOT NULL,
    latency_ms       REAL    NOT NULL,
    status           TEXT    NOT NULL,
    error_code       TEXT    NOT NULL,
    message_id_header TEXT   NOT NULL,
    event_id         TEXT    NOT NULL,
    policy_reason    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts            ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_action        ON events(action);
CREATE INDEX IF NOT EXISTS idx_events_status        ON events(status);
CREATE INDEX IF NOT EXISTS idx_events_policy_reason ON events(policy_reason);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id);

CREATE TABLE IF NOT EXISTS feedback (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    event_id  TEXT NOT NULL,
    verdict   TEXT NOT NULL,
    source    TEXT NOT NULL,
    reporter  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_feedback_event_id ON feedback(event_id);
CREATE INDEX IF NOT EXISTS idx_feedback_ts       ON feedback(ts);
)SQL";

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, ddl, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        if (err_msg) sqlite3_free(err_msg);
        return false;
    }
    return true;
}

bool EventStore::record(const DecisionEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return false;

    const char* sql = R"SQL(
INSERT INTO events (
    ts, queue_id, mail_from, rcpt_count, bytes_seen, truncated,
    model_version, score_spam, score_regular, score_marketing, score_gibberish,
    label, action, latency_ms, status, error_code,
    message_id_header, event_id, policy_reason
) VALUES (
    ?1, ?2, ?3, ?4, ?5, ?6,
    ?7, ?8, ?9, ?10, ?11,
    ?12, ?13, ?14, ?15, ?16,
    ?17, ?18, ?19
);
)SQL";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, event.ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, event.queue_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, event.mail_from.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, event.rcpt_count);
    sqlite3_bind_int64(stmt, 5, event.bytes_seen);
    sqlite3_bind_int(stmt, 6, event.truncated ? 1 : 0);
    sqlite3_bind_text(stmt, 7, event.model_version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 8, static_cast<double>(event.score_spam));
    sqlite3_bind_double(stmt, 9, static_cast<double>(event.score_regular));
    sqlite3_bind_double(stmt, 10, static_cast<double>(event.score_marketing));
    sqlite3_bind_double(stmt, 11, static_cast<double>(event.score_gibberish));
    sqlite3_bind_text(stmt, 12, event.label.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 13, event.action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 14, event.latency_ms);
    sqlite3_bind_text(stmt, 15, event.status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 16, event.error_code.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 17, event.message_id_header.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 18, event.event_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 19, event.policy_reason.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE;
}

bool EventStore::record_feedback(const FeedbackEvent& fb) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return false;

    const char* sql = R"SQL(
INSERT INTO feedback (ts, event_id, verdict, source, reporter)
VALUES (?1, ?2, ?3, ?4, ?5);
)SQL";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, fb.ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, fb.event_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, fb.verdict.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, fb.source.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, fb.reporter.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

void EventStore::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool EventStore::is_open() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return db_ != nullptr;
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

std::string generate_uuid() {
    unsigned char buf[16];

    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom.read(reinterpret_cast<char*>(buf), sizeof(buf))) {
        // Fallback (urandom unavailable): never emit the degenerate all-zero
        // UUID — it collides on the events table's unique index and silently
        // stops event logging. Seed from the high-res clock (so it is never
        // constant) and mix in whatever entropy random_device offers.
        uint64_t hi = static_cast<uint64_t>(
            std::chrono::high_resolution_clock::now().time_since_epoch().count());
        uint64_t lo = hi * 0x9E3779B97F4A7C15ull;
        try {
            std::random_device rd;
            hi ^= (static_cast<uint64_t>(rd()) << 32) ^ rd();
            lo ^= (static_cast<uint64_t>(rd()) << 32) ^ rd();
        } catch (...) {
            // random_device unavailable too — clock seed alone still avoids zero.
        }
        std::memcpy(buf, &hi, sizeof(hi));
        std::memcpy(buf + 8, &lo, sizeof(lo));
    }

    // Set version 4 (bits 12-15 of time_hi_and_version).
    buf[6] = (buf[6] & 0x0F) | 0x40;
    // Set variant 1 (bits 6-7 of clock_seq_hi_and_reserved).
    buf[8] = (buf[8] & 0x3F) | 0x80;

    char out[37];
    std::snprintf(out, sizeof(out),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  buf[0], buf[1], buf[2], buf[3],
                  buf[4], buf[5],
                  buf[6], buf[7],
                  buf[8], buf[9],
                  buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);

    return std::string(out);
}

std::string now_rfc3339() {
    using namespace std::chrono;

    auto now = system_clock::now();
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    auto tt = system_clock::to_time_t(now);

    std::tm utc{};
    gmtime_r(&tt, &utc);

    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                  utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
                  utc.tm_hour, utc.tm_min, utc.tm_sec,
                  static_cast<int>(ms.count()));

    return std::string(buf);
}

// Escape a string for embedding in a JSON value.
static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char hex[8];
                std::snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned>(c));
                out += hex;
            } else {
                out += c;
            }
            break;
        }
    }
    return out;
}

std::string event_to_json(const DecisionEvent& e) {
    std::ostringstream o;
    o << std::fixed;
    o << "{";
    o << "\"ts\":\"" << json_escape(e.ts) << "\"";
    o << ",\"queue_id\":\"" << json_escape(e.queue_id) << "\"";
    o << ",\"mail_from\":\"" << json_escape(e.mail_from) << "\"";
    o << ",\"rcpt_count\":" << e.rcpt_count;
    o << ",\"bytes_seen\":" << e.bytes_seen;
    o << ",\"truncated\":" << (e.truncated ? "true" : "false");
    o << ",\"model_version\":\"" << json_escape(e.model_version) << "\"";
    o << std::setprecision(6);
    o << ",\"score_spam\":" << e.score_spam;
    o << ",\"score_regular\":" << e.score_regular;
    o << ",\"score_marketing\":" << e.score_marketing;
    o << ",\"score_gibberish\":" << e.score_gibberish;
    o << ",\"label\":\"" << json_escape(e.label) << "\"";
    o << ",\"action\":\"" << json_escape(e.action) << "\"";
    o << std::setprecision(3);
    o << ",\"latency_ms\":" << e.latency_ms;
    o << ",\"status\":\"" << json_escape(e.status) << "\"";
    o << ",\"error_code\":\"" << json_escape(e.error_code) << "\"";
    o << ",\"message_id_header\":\"" << json_escape(e.message_id_header) << "\"";
    o << ",\"event_id\":\"" << json_escape(e.event_id) << "\"";
    o << ",\"policy_reason\":\"" << json_escape(e.policy_reason) << "\"";
    o << "}";
    return o.str();
}

} // namespace klar
