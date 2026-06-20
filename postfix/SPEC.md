# Postfix Milter Specification

Status: v1 — implemented and tested
Last updated: 2026-03-13
Primary deliverables: `klar-milterd` (milter daemon), `klar-policy-cli` (offline CLI)

## 1. Product statement

`klar-milterd` is an inbound SMTP filter for Postfix that classifies each RFC822 message with `spam_engine_classify_rfc822(...)` and applies one of two actions: `tag` or `reject`.

Messages are delivered via LMTP to Dovecot. Dovecot Sieve files spam to Junk based on `X-Klar-Label` header. User feedback (moving messages to/from Junk) is captured via Dovecot imapsieve and recorded in the shared event store.

There is no quarantine. We are not an antivirus product. Messages are either delivered (with classification headers) or rejected at SMTP time.

## 2. Terminology

1. `score.spam`: `result.scores.spam` from C ABI.
2. `label`: binary decision (`spam` or `regular`).
3. `profile`: threshold preset:
   - `cautious=0.70`,
   - `standard=0.50`,
   - `aggressive=0.30`.
4. `fail-open`: accept mail when scoring path fails.
5. `allowlist`: sender/domain override that forces `TAG`.
6. `blocklist`: sender/domain override that forces `REJECT`.
7. `domain policy`: recipient-domain-specific policy override.

## 3. Exact behavior definitions

### 3.1 `mode=tag` (default)

1. Message is always accepted.
2. Headers added:
   - `X-Klar-Label` (`spam` or `regular`),
   - `X-Klar-Score-Spam`,
   - `X-Klar-Score-Regular`,
   - `X-Klar-Score-Marketing`,
   - `X-Klar-Score-Gibberish`,
   - `X-Klar-Action` (`tag`, `reject`, or `bypass`),
   - `X-Klar-Model-Version`,
   - `X-Klar-Event-ID` (UUIDv4).
3. Dovecot Sieve files messages with `X-Klar-Label: spam` to Junk folder.

### 3.2 `mode=reject`

1. Message classified at `xxfi_eom`.
2. If `score.spam >= reject_threshold`:
   - call `smfi_setreply(ctx, "550", "5.7.1", "Message rejected by spam policy")`,
   - return `SMFIS_REJECT`.
3. Else: return `SMFIS_ACCEPT` with headers.

### 3.3 Failure behavior

If engine/classification fails:

1. `fail_open=true`:
   - return `SMFIS_ACCEPT`,
   - add `X-Klar-Action: bypass`,
   - log error reason.
2. `fail_open=false`:
   - call `smfi_setreply(ctx, "451", "4.7.1", "Temporary filtering failure")`,
   - return `SMFIS_TEMPFAIL`.

Launch default: `fail_open=true`.

## 4. Code architecture

### 4.1 Source files

```text
postfix/
  src/
    main.cpp            # Daemon entry point, signal handling, config reload
    main_cli.cpp        # CLI: offline classify for replay testing
    milter_server.cpp/h # libmilter callbacks, header injection
    session_context.h   # Per-connection state
    config.cpp/h        # TOML parsing, validation
    policy.cpp/h        # Allowlist/blocklist, domain policy, thresholds
    model_runtime.cpp/h # Engine C API wrapper, hot-reload
    health_server.cpp/h # HTTP /livez /readyz /metrics
    event_store.cpp/h   # SQLite decision log + feedback table
  config/
    example.toml        # Documented production config template
  docker/
    docker-compose.yml  # E2E stack: milter + Postfix + Dovecot
    Dockerfile.milter
    Dockerfile.postfix
    Dockerfile.dovecot
    dovecot/            # Dovecot config, Sieve scripts, feedback handler
  scripts/
    e2e_lib.sh          # Shared E2E test library
    test_e2e.sh         # Full pipeline E2E test
    test_stress.sh      # Stress test with leak detection
    test_replay.sh      # Offline replay test
    train_from_imap.py  # Batch training from IMAP folders
    prepare_e2e_staging.sh
    build.sh, setup.sh, ...
  tests/
    scripts/
      send_fixture.py
      check_imap.py
      stress_milter.py
      run_policy_replay.py
      score_fixtures.py
    config/
      tag.toml, runtime.toml, domain_policy.toml
    fixtures/
      stable_manifest.csv
```

### 4.2 Runtime objects

`SessionContext`:

1. `std::string queue_id`
2. `std::string mail_from`
3. `std::string from_header_name` (display name from `From:` header)
4. `std::string from_header_email` (address from `From:` header)
5. `std::vector<std::string> rcpt_to`
6. `std::string raw_rfc822`
7. `bool truncated`
8. `uint64_t started_ns`
9. `uint64_t buffered_bytes`

`ModelRuntime`:

1. `spam_engine_handle_t* handle`
2. `std::mutex handle_mutex`
3. `std::string loaded_model_version`
4. `std::atomic<uint64_t> generation`
5. Methods:
   - `bool load(const Config&)`
   - `bool reload_if_needed(const Config&)`
   - `ClassifyResult classify_rfc822(...)`
   - `std::string last_error()`

`Policy`:

1. Inputs: config, classifier result, failure state.
2. Output:
   - action enum (`TAG`, `REJECT`, `BYPASS`, `TEMPFAIL`),
   - SMTP/milter return status,
   - SMTP reply tuple or null.

`ServerState` (process global):

1. `std::atomic<uint32_t> inflight_sessions`
2. `std::atomic<uint64_t> inflight_bytes`
3. `std::atomic<bool> shutting_down`
4. Decision counters: `decisions_tag`, `decisions_reject`, `decisions_bypass`
5. `std::atomic<uint64_t> errors_total`

Config is held as `std::shared_ptr<const Config>` with `std::atomic_load`/`std::atomic_store` for thread-safe reload. Each callback snapshots the config at entry.

### 4.3 C ABI usage

The engine C API (`engine/spam_engine_c_api.h`):

```c
spam_engine_status_t spam_engine_classify_rfc822(
    spam_engine_handle_t* handle,
    const char* raw_email, size_t raw_email_len,
    const char* sender_name, const char* sender_email,
    spam_engine_result_t* out_result);
```

Startup: `spam_engine_create()` + `spam_engine_load(handle, model_path, /*learning_rate=*/0.0f, /*ftrl_path=*/nullptr)`.
Per message: `spam_engine_classify_rfc822(...)`.
Shutdown: `spam_engine_unload(handle)` + `spam_engine_destroy(handle)`.

### 4.4 Milter callback contract

1. `xxfi_connect`: enforce `max_inflight_sessions`, allocate `SessionContext`.
2. `xxfi_envfrom`: store sender, reset per-transaction state.
3. `xxfi_envrcpt`: append recipient.
4. `xxfi_header`: append to `raw_rfc822`, parse `From:` header.
5. `xxfi_eoh`: append `"\r\n"`.
6. `xxfi_body`: append chunk, track `buffered_bytes` and `inflight_bytes`, enforce `max_message_bytes`.
7. `xxfi_eom`: classify, apply policy, add headers, release `buffered_bytes`, return status.
8. `xxfi_abort`: release `buffered_bytes`, reset session state.
9. `xxfi_close`: safety-net release of `buffered_bytes`, free context, decrement `inflight_sessions`.

`inflight_bytes` decrement uses CAS loop to prevent underflow:

```cpp
uint64_t cur = state->inflight_bytes.load(std::memory_order_relaxed);
while (true) {
    uint64_t next = (cur >= bytes) ? cur - bytes : 0;
    if (state->inflight_bytes.compare_exchange_weak(cur, next, ...)) break;
}
```

### 4.5 libmilter API calls

1. `smfi_setconn(config.listen.c_str())`
2. `smfi_settimeout(...)`
3. `smfi_register(&smfilter)` — flags: `SMFIF_ADDHDRS`
4. `smfi_main()`
5. `smfi_stop()` on shutdown signal
6. `smfi_addheader(ctx, key, value)` for `X-Klar-*` headers
7. `smfi_setreply(ctx, code, xcode, reason)` for reject/tempfail

### 4.6 Process lifecycle

Signal handling:

1. `SIGHUP`: create new `shared_ptr<const Config>`, swap atomically, attempt model reload.
2. `SIGTERM`/`SIGINT`: set `shutting_down=true`, call `smfi_stop()`, drain for `shutdown_drain_timeout_ms`.

The listen address is frozen at startup — config reloads cannot change it.

Threading: libmilter thread pool, session data thread-confined, model classify path serialized by mutex.

## 5. Policy algorithm

Action decision (in order):

1. If `bypass_due_overload=true`: `BYPASS`.
2. Else if blocklist matched: `REJECT`.
3. Else if allowlist matched: `TAG`.
4. Else if scoring failed and `fail_open=true`: `BYPASS`.
5. Else if scoring failed and `fail_open=false`: `TEMPFAIL`.
6. Else if `mode=reject` and `score.spam >= reject_threshold`: `REJECT`.
7. Else: `TAG`.

Labels: blocklist → `spam`, allowlist → `regular`, ML → `spam` when `score.spam >= threshold`.

Header `X-Klar-Action` is one of: `tag`, `reject`, `bypass`.

## 6. Configuration

Config path: `/etc/klar/postfix.toml`. See `config/example.toml` for documented template.

```toml
listen = "inet:127.0.0.1:8891"
mode = "tag"                          # tag | reject
fail_open = true
timeout_ms = 1500
max_message_bytes = 5242880
max_inflight_sessions = 128
max_inflight_bytes = 268435456

profile = "standard"                  # cautious | standard | aggressive
spam_threshold_override = -1.0
reject_threshold = 0.995

model_dir = "/var/lib/klar/model/current"
model_version_file = "/var/lib/klar/model/current/VERSION"

health_enabled = true
health_listen = "127.0.0.1:8892"

event_store_path = "/var/lib/klar/events.sqlite3"

blocklist_action = "reject"

[[domain_policy]]
recipient_domain = "bank.example"
mode = "reject"
profile = "cautious"
reject_threshold = 0.80
```

Validation:

1. `mode` is `tag` or `reject`.
2. `profile` is `cautious`, `standard`, or `aggressive`.
3. Thresholds in `[0,1]`.
4. `timeout_ms` in `[100,10000]`.
5. `max_message_bytes` in `[65536,26214400]`.
6. `max_inflight_sessions` in `[1,1024]`.
7. `max_inflight_bytes` in `[1048576,2147483648]`.
8. `blocklist_action` is `reject`.
9. Allow/block list entries: lowercase, unique, no wildcards.
10. Domain policy entries pass same validation.

## 7. Event store

SQLite with two tables:

```sql
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL, queue_id TEXT NOT NULL, mail_from TEXT NOT NULL,
  rcpt_count INTEGER NOT NULL, bytes_seen INTEGER NOT NULL,
  truncated INTEGER NOT NULL, model_version TEXT NOT NULL,
  score_spam REAL NOT NULL, score_regular REAL NOT NULL,
  score_marketing REAL NOT NULL, score_gibberish REAL NOT NULL,
  label TEXT NOT NULL, action TEXT NOT NULL,
  latency_ms REAL NOT NULL, status TEXT NOT NULL,
  error_code TEXT NOT NULL, message_id_header TEXT NOT NULL,
  event_id TEXT NOT NULL, policy_reason TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL, event_id TEXT NOT NULL,
  verdict TEXT NOT NULL, source TEXT NOT NULL,
  reporter TEXT NOT NULL
);
```

JSON log line emitted to stdout for every decision.

## 8. Health endpoint

`GET /livez`: `200 ok` (always).
`GET /readyz`: `200` when model loaded, `503` otherwise.
`GET /metrics`: Prometheus text format.

Metrics:
- `klar_inflight_sessions` (gauge)
- `klar_inflight_bytes` (gauge)
- `klar_decisions_total` (counter)
- `klar_decisions{action="tag|reject|bypass"}` (counter)
- `klar_errors_total` (counter)
- `klar_model_loaded` (gauge)
- `klar_model_generation` (counter)

## 9. Postfix integration

```conf
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:127.0.0.1:8891
non_smtpd_milters = inet:127.0.0.1:8891
milter_data_macros = i
milter_end_of_data_macros = i
milter_connect_timeout = 5s
milter_command_timeout = 30s
milter_content_timeout = 120s
```

`milter_default_action = accept` is mandatory — if milter is down, mail still flows.

## 10. Dovecot integration

Dovecot handles LMTP delivery from Postfix, IMAP access for users, and feedback capture.

### 10.1 Mail delivery

Postfix delivers via LMTP: `virtual_transport = lmtp:inet:dovecot:24`.
Dovecot stores in Maildir: `mail_location = maildir:/var/mail/%d/%n`.

### 10.2 Sieve filing

Global LMTP delivery script (`sieve_before`):

```sieve
require ["fileinto"];
if header :is "X-Klar-Label" "spam" {
    fileinto "Junk";
}
```

### 10.3 Feedback via imapsieve

When a user moves a message to Junk (IMAP COPY/APPEND), imapsieve triggers a pipe to `klar-feedback`, which extracts `X-Klar-Event-ID` from the message headers and writes a feedback record to the shared SQLite event store.

When a user moves a message out of Junk (IMAP COPY from Junk), the script records a "ham" feedback.

```
User moves to Junk → imapsieve → pipe klar-feedback "spam"
                                      → extract X-Klar-Event-ID
                                      → INSERT INTO feedback
```

### 10.4 Training

`train_from_imap.py` reads INBOX (ham) and Junk (spam) via IMAP and trains the engine's classifier head using the batch training API (`spam_engine_add_training_sample` + `spam_engine_train_incremental`). The folders are the ground truth.

## 11. E2E test topology

```
SMTP client → Postfix (:2525) → milter (:8891) → classify
                ↓                                     ↓
              LMTP → Dovecot (:1143 IMAP, :24 LMTP)  headers
                       ↓
                  Sieve: spam → Junk
                  imapsieve: move → feedback → SQLite
```

All containers on `docker_default` network. Health at `:8892`.

`make postfix/test-e2e` runs the full pipeline:
1. Build and start stack
2. Send ham + spam fixtures
3. Verify via IMAP: ham in INBOX, spam in Junk, correct headers
4. Move message to Junk, verify feedback recorded in SQLite
5. Teardown

`make postfix/test-stress` runs random SMTP scenarios (normal, large, abort, reuse, empty, RSET) and verifies `inflight_bytes=0` and `inflight_sessions=0` after completion via `/metrics`.

## 12. Build and targets

```bash
make postfix/setup        # Install deps, build engine
make postfix/build        # Build klar-milterd + klar-policy-cli
make postfix/test         # Replay + E2E tests
make postfix/test-replay  # Offline fixture scoring
make postfix/test-e2e     # Full Docker pipeline test
make postfix/test-stress  # Random SMTP stress test
make postfix/train        # Retrain from IMAP folders
make postfix/e2e-up       # Start Docker stack
make postfix/e2e-down     # Teardown Docker stack
```

## 13. Deployment (Linux)

```bash
# Install daemon
sudo useradd --system --home /var/lib/klar --shell /usr/sbin/nologin klarmilter
sudo install -d -o klarmilter -g klarmilter /etc/klar /var/lib/klar
sudo install -m 0755 klar-milterd /usr/local/bin/klar-milterd
sudo install -m 0640 -o root -g klarmilter config/example.toml /etc/klar/postfix.toml
# Edit /etc/klar/postfix.toml for your setup

# Install model
sudo install -d -o klarmilter -g klarmilter /var/lib/klar/model/current
# Copy model files to /var/lib/klar/model/current/

# Configure Postfix
sudo postconf -e 'milter_default_action = accept'
sudo postconf -e 'milter_protocol = 6'
sudo postconf -e 'smtpd_milters = inet:127.0.0.1:8891'
sudo postconf -e 'non_smtpd_milters = inet:127.0.0.1:8891'
sudo postconf -e 'milter_data_macros = i'
sudo postconf -e 'milter_end_of_data_macros = i'
sudo postfix reload

# Start milter (or use systemd unit from packaging/)
sudo -u klarmilter klar-milterd --config /etc/klar/postfix.toml

# Verify
curl -fsS http://127.0.0.1:8892/readyz
```

## 14. Rollback

Hard rollback (remove milter):

```bash
sudo postconf -X smtpd_milters non_smtpd_milters
sudo postfix reload
```

Soft rollback (tag-only, keep observability):

1. Set `mode="tag"` in config.
2. `kill -HUP $(pidof klar-milterd)`.
