// Unit tests for the event store's schema migration and the structural-offset
// column (TASK-388). Links event_store.cpp + sqlite3 only — no engine, no milter.
//
// The migration is the part that needs proving: before TASK-388 the schema was
// CREATE TABLE IF NOT EXISTS and nothing else, so a new column would have broken
// every already-deployed database. The tests below open a database written by the
// OLD code and require it to keep working.

#include "event_store.h"

#include <sqlite3.h>

#include <cstdio>
#include <string>

namespace {
int g_fail = 0, g_checks = 0;
void check(bool c, const char* what) {
  ++g_checks;
  if (!c) { ++g_fail; std::printf("  [FAIL] %s\n", what); }
}

// Exactly the schema the pre-migration code created: no fired_offsets, and
// user_version left at its default 0.
const char* kLegacyDdl = R"SQL(
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
CREATE TABLE IF NOT EXISTS feedback (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    event_id  TEXT NOT NULL,
    verdict   TEXT NOT NULL,
    source    TEXT NOT NULL,
    reporter  TEXT NOT NULL
);
INSERT INTO events (ts, queue_id, mail_from, rcpt_count, bytes_seen, truncated,
    model_version, score_spam, score_regular, score_marketing, score_gibberish,
    label, action, latency_ms, status, error_code, message_id_header, event_id,
    policy_reason)
VALUES ('2026-01-01T00:00:00Z', 'OLD1', 'a@b.test', 1, 100, 0, 'v0',
        0.1, 0.9, 0.0, 0.0, 'regular', 'tag', 1.0, 'ok', '', '', 'old-event-1', 'ml');
)SQL";

void write_legacy_db(const std::string& path) {
  std::remove(path.c_str());
  sqlite3* db = nullptr;
  sqlite3_open(path.c_str(), &db);
  sqlite3_exec(db, kLegacyDdl, nullptr, nullptr, nullptr);
  sqlite3_close(db);
}

// Single-value query helpers, so the tests read as assertions rather than sqlite.
int int_query(const std::string& path, const char* sql) {
  sqlite3* db = nullptr;
  sqlite3_open(path.c_str(), &db);
  sqlite3_stmt* stmt = nullptr;
  int out = -1;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK &&
      sqlite3_step(stmt) == SQLITE_ROW) {
    out = sqlite3_column_int(stmt, 0);
  }
  sqlite3_finalize(stmt);
  sqlite3_close(db);
  return out;
}

std::string text_query(const std::string& path, const char* sql) {
  sqlite3* db = nullptr;
  sqlite3_open(path.c_str(), &db);
  sqlite3_stmt* stmt = nullptr;
  std::string out;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK &&
      sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char* t = sqlite3_column_text(stmt, 0);
    if (t != nullptr) out = reinterpret_cast<const char*>(t);
  }
  sqlite3_finalize(stmt);
  sqlite3_close(db);
  return out;
}

klar::DecisionEvent sample_event(const std::string& id, const std::string& fired,
                                 const std::string& reason) {
  klar::DecisionEvent ev;
  ev.ts = "2026-07-30T12:00:00Z";
  ev.queue_id = "QID";
  ev.mail_from = "spammer@evil.test";
  ev.rcpt_count = 1;
  ev.bytes_seen = 2048;
  ev.model_version = "v1";
  ev.score_spam = 0.02f;      // the case that motivates the whole task:
  ev.score_regular = 0.90f;   // content says ham, a structural offset condemned
  ev.label = "spam";
  ev.action = "tag";
  ev.latency_ms = 12.5;
  ev.status = "ok";
  ev.event_id = id;
  ev.policy_reason = reason;
  ev.fired_offsets = fired;
  return ev;
}
}  // namespace

int main() {
  const std::string legacy = "/tmp/klar_event_store_legacy.sqlite3";
  const std::string fresh = "/tmp/klar_event_store_fresh.sqlite3";

  // 1. A database written by the OLD code must upgrade in place, keep its rows,
  //    and accept writes that use the new column.
  write_legacy_db(legacy);
  check(int_query(legacy, "PRAGMA user_version;") == 0, "legacy db starts at version 0");
  {
    klar::EventStore store;
    check(store.open(legacy), "legacy db opens");
    check(store.record(sample_event("new-event-1", "connect_ip_drop!", "structural")),
          "a post-migration write succeeds against an upgraded legacy db");
  }
  check(int_query(legacy, "PRAGMA user_version;") == 1, "legacy db is migrated to version 1");
  check(int_query(legacy, "SELECT COUNT(*) FROM events;") == 2,
        "the pre-existing row survived the migration");
  check(text_query(legacy,
        "SELECT fired_offsets FROM events WHERE event_id='old-event-1';").empty(),
        "a historical row reads as empty, not NULL");
  check(text_query(legacy,
        "SELECT fired_offsets FROM events WHERE event_id='new-event-1';") ==
        "connect_ip_drop!", "the new row records which offset fired and that it flipped");

  // 2. Re-opening an already-migrated database is a no-op, not a second ALTER.
  {
    klar::EventStore store;
    check(store.open(legacy), "an already-migrated db re-opens");
    check(store.record(sample_event("new-event-2", "", "ml")), "and still accepts writes");
  }
  check(int_query(legacy, "PRAGMA user_version;") == 1, "version is unchanged on re-open");

  // 2b. A crash between the ALTER and the version bump must not wedge startup.
  //     Simulate it: apply the ALTER by hand, leave user_version at 0, and require
  //     the next open to recover rather than die on "duplicate column".
  const std::string crashed = "/tmp/klar_event_store_crashed.sqlite3";
  write_legacy_db(crashed);
  {
    sqlite3* db = nullptr;
    sqlite3_open(crashed.c_str(), &db);
    sqlite3_exec(db, "ALTER TABLE events ADD COLUMN fired_offsets TEXT NOT NULL DEFAULT '';",
                 nullptr, nullptr, nullptr);
    sqlite3_close(db);
  }
  check(int_query(crashed, "PRAGMA user_version;") == 0,
        "the half-applied db still reads as version 0");
  {
    klar::EventStore store;
    const bool opened = store.open(crashed);
    check(opened, "a half-applied migration does not wedge startup");
    if (opened) {
      check(store.record(sample_event("post-crash", "connect_ip_drop!", "structural")),
            "and the store works afterwards");
    }
  }

  // 3. A fresh database must land on the SAME schema by the SAME path, so the two
  //    cannot drift.
  std::remove(fresh.c_str());
  {
    klar::EventStore store;
    check(store.open(fresh), "fresh db opens");
    check(store.record(sample_event("fresh-1", "sender_auth!", "structural")),
          "fresh db accepts a write");
  }
  check(int_query(fresh, "PRAGMA user_version;") == 1, "fresh db is at the current version");
  check(text_query(fresh, "SELECT fired_offsets FROM events WHERE event_id='fresh-1';") ==
        "sender_auth!", "fresh db records the offset");

  // 4. A DROP-driven junk is reconstructible from the event store alone: the
  //    scores say ham, so without these two columns the row is inexplicable.
  const std::string reason = text_query(legacy,
      "SELECT policy_reason FROM events WHERE event_id='new-event-1';");
  const std::string fired = text_query(legacy,
      "SELECT fired_offsets FROM events WHERE event_id='new-event-1';");
  const std::string label = text_query(legacy,
      "SELECT label FROM events WHERE event_id='new-event-1';");
  check(label == "spam" && reason == "structural" && fired == "connect_ip_drop!",
        "junked-at-score-0.02 row explains itself: structural, connect_ip_drop, flipped");

  // 5. The JSON log line carries it too, and only when something fired.
  const std::string json_fired = klar::event_to_json(
      sample_event("j1", "connect_ip_drop!", "structural"));
  check(json_fired.find("\"fired_offsets\":\"connect_ip_drop!\"") != std::string::npos,
        "json line carries fired_offsets");
  check(json_fired.find("\"policy_reason\":\"structural\"") != std::string::npos,
        "json line carries the structural policy_reason");
  const std::string json_plain = klar::event_to_json(sample_event("j2", "", "ml"));
  check(json_plain.find("fired_offsets") == std::string::npos,
        "no offset fired -> the key is omitted, the common line stays terse");

  std::printf("\n%d checks, %d failures\n", g_checks, g_fail);
  return g_fail == 0 ? 0 : 1;
}
