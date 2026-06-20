# Klar Postfix Milter

Inbound SMTP filter for Postfix that classifies RFC822 messages using the Klar spam engine and applies tag/reject policy. Integrates with Dovecot for IMAP delivery, Sieve-based spam filing, and user feedback loop.

## Architecture

```
  SMTP client ──▶ Postfix ──milter──▶ klar-milterd ──▶ engine C API
                    │                      │
                    │                  X-Klar-* headers
                    │                      │
                    ▼                      ▼
                  LMTP ──▶ Dovecot    SQLite events
                             │
                        Sieve: spam → Junk
                        imapsieve: move → feedback
```

### Components

| Component | File(s) | Role |
|-----------|---------|------|
| Config | `config.cpp/.h` | TOML parsing, validation, profile thresholds |
| Model Runtime | `model_runtime.cpp/.h` | Engine C API wrapper, hot-reload via SIGHUP |
| Policy | `policy.cpp/.h` | Allowlist/blocklist, domain policy, threshold decisions |
| Milter Server | `milter_server.cpp/.h` | libmilter callbacks, header injection |
| Event Store | `event_store.cpp/.h` | SQLite decision log, JSON stdout logging |
| Health Server | `health_server.cpp/.h` | HTTP /livez /readyz /metrics endpoints |
| CLI | `main_cli.cpp` | klar-policy-cli for offline scoring and replay testing |

### Data Flow

1. Postfix receives SMTP, invokes milter callbacks
2. `xxfi_header` / `xxfi_body` accumulate raw RFC822
3. `xxfi_eom` triggers classification via engine C API
4. Policy engine applies allowlist/blocklist, domain policy, thresholds
5. `X-Klar-Label`, `X-Klar-Score-Spam`, `X-Klar-Event-ID` headers added
6. Postfix delivers via LMTP to Dovecot
7. Dovecot Sieve files spam to Junk based on `X-Klar-Label` header
8. User moves message to/from Junk → imapsieve records feedback

### Two Modes

- **tag** (default): Accept all mail, add headers. Dovecot Sieve handles filing.
- **reject**: Also reject high-confidence spam at SMTP time (550).

## Quick Start

```bash
make postfix/setup    # Install deps, build engine
make postfix/build    # Build klar-milterd + klar-policy-cli
make postfix/test     # Replay tests + E2E (if Docker available)
```

## Testing

```bash
make postfix/test-replay    # Offline: classify fixtures, verify scores
make postfix/test-e2e       # Docker: full Postfix + Dovecot + milter pipeline
make postfix/test-stress    # Docker: random SMTP sessions, leak detection
```

### Training

```bash
make postfix/train    # Retrain classifier from IMAP INBOX/Junk folders
```

## Configuration

See `config/example.toml` for a documented production config. Key settings:

| Key | Default | Description |
|-----|---------|-------------|
| `mode` | `tag` | tag / reject |
| `profile` | `standard` | cautious (0.70) / standard (0.50) / aggressive (0.30) |
| `fail_open` | `true` | Accept mail on engine failure |
| `reject_threshold` | `0.995` | Score above which to reject (reject mode only) |

## Monitoring

The milter exposes Prometheus metrics at `/metrics` (default port 8892):

- `klar_inflight_sessions` — active milter sessions
- `klar_inflight_bytes` — buffered bytes across sessions
- `klar_decisions_total` — total classifications
- `klar_errors_total` — total errors
- `klar_model_loaded` — model readiness

Health probes: `/livez` (liveness), `/readyz` (readiness).
