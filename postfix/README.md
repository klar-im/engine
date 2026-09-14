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
| Event Store | `event_store.cpp/.h` | SQLite decision log (versioned schema), JSON stdout logging |
| Health Server | `health_server.cpp/.h` | HTTP /livez /readyz /metrics endpoints |
| CLI | `main_cli.cpp` | klar-policy-cli for offline scoring and replay testing |

### Data Flow

1. Postfix receives SMTP, invokes milter callbacks
2. `xxfi_header` / `xxfi_body` accumulate raw RFC822
3. `xxfi_eom` triggers classification via engine C API
4. Policy engine applies allowlist/blocklist, domain policy, thresholds
5. `X-Klar-Label`, `X-Klar-Class`, `X-Klar-Score-*`, `X-Klar-Event-ID` headers added
6. Postfix delivers via LMTP to Dovecot
7. Dovecot Sieve files spam to Junk (`X-Klar-Label`) and marketing to
   Marketing (`X-Klar-Class`, 4-class argmax; spam label wins)
8. User moves message to/from Junk → imapsieve records feedback

### Two Modes

- **tag** (default): Accept all mail, add headers. Dovecot Sieve handles filing.
- **reject**: Also reject high-confidence spam at SMTP time (550).

### Filing: headers → folders

The milter only stamps headers; it never moves mail. Filing is Dovecot's job,
driven by two headers:

- `X-Klar-Label` (`spam`|`regular`) → spam to Junk.
- `X-Klar-Class` (`regular`|`marketing`|`gibberish`|`spam`, the 4-class
  argmax) → non-spam marketing to a Marketing folder, so users get a
  Gmail-style "Promotions" split without losing anything to Junk. The spam
  label wins: a spam-labelled message goes to Junk even if its class was
  marketing.

Ship `packaging/klar.sieve` as a `sieve_before` script and create the `Junk`
and `Marketing` mailboxes in the inbox namespace (both auto-subscribed). The
header approach means a deployment can file, tag, or ignore any class without
touching the milter: change the Sieve, not the engine.

### Required ordering: authenticate BEFORE this milter

The engine's sender-auth signals (DKIM/DMARC alignment, the brand-impersonation
exoneration) are PARSED from the message's `Authentication-Results` header; the
engine does not verify DKIM/DMARC itself. So this milter MUST run after a filter
that authenticates the message and stamps a trusted `Authentication-Results`,
and strips client-supplied ones (in practice OpenDMARC/OpenDKIM ahead of
`klar-milterd` in `smtpd_milters`). Two failure modes if you don't:

- A message with NO `Authentication-Results` leaves DMARC `Unknown`, and the brand
  layer then exonerates a direct From-forgery of a KB-canonical brand domain (it
  assumes an upstream MTA already rejected the forgery).
- The topmost `Authentication-Results` is trusted, so an attacker who reaches this
  milter first can inject a forged `dkim=pass; dmarc=pass`.

Behind iCloud/Gmail (the Apple Mail deployment) the provider has already done this;
a standalone Postfix relay has not. See `engine/ARCHITECTURE.md` ("Trust boundary:
the sender-auth layer reads, it does not verify").

**When the MTA does not put its own AR in front of the milter, set
`auth_results = "ignore"`.** Stalwart is one such MTA: it verifies DKIM, SPF
and DMARC itself and adds its `Authentication-Results` to the queued message
after the milters have run (`crates/smtp/src/inbound/data.rs`, 0.16.18 `:504`
and `:602`, 0.16.22 `:501` and `:595`), so at DATA a milter sees the message
as the sender delivered it. `ignore` drops every `Authentication-Results` and
`ARC-Authentication-Results` header before the engine parses the message;
`postfix/scripts/test_auth_results.sh` shows the same phish delivered as
regular under the default and labelled spam under `ignore`. What `ignore`
gives up is the AR-derived condemn on a *failing* DMARC, which Stalwart
enforces at SMTP time with `SenderAuth.dmarcVerify = "strict"`. The full
Stalwart setup, including the Sieve that files on `X-Klar-Label`, is in
`stalwart/README.md`.

## Quick Start

```bash
make postfix/setup    # Install deps, build engine
make postfix/build    # Build klar-milterd + klar-policy-cli
make postfix/test     # Replay tests + E2E (if Docker available)
```

On macOS only `klar-policy-cli` is built: `klar-milterd` needs libmilter, a Linux
server library. The daemon builds and runs in the Docker E2E stack and in CI
(`linux-gate.yml`, a thin wrapper around `make ci`), which covers build, unit, replay, risk validation and E2E
on every PR/push touching `postfix/**` or `engine/**`.

## Testing

```bash
make postfix/test-replay    # Offline: classify fixtures, verify scores
make postfix/test-e2e       # Docker: full Postfix + Dovecot + milter pipeline
make postfix/test-stress    # Docker: random SMTP sessions, leak detection
```

### Staging MX (postfix.klar.im): real internet mail, continuously

The Docker E2E is hermetic: canned fixtures, no DNS/MX hop, and the
Authentication-Results the engine trusts are fixture-carried, never computed.
The staging MX closes that gap with real mail on the prod VPS:

```
  internet ──▶ Stalwart :25 (owns the port) ──relay postfix.klar.im──▶ pod 10.88.0.200:25
                                                                          │
                                              klar-staging podman pod: Postfix
                                              (+ OpenDKIM/OpenDMARC verify+stamp)
                                              ──▶ klar-milterd ──▶ Dovecot
```

- DNS: `postfix.klar.im` A record → the VPS (implicit MX). Stalwart accepts
  the domain at RCPT and relays it to the pod (`infra/scripts/
  stalwart-setup.sh` section 2.9).
- The pod's Postfix strips inbound `Authentication-Results` and runs
  OpenDKIM + OpenDMARC ahead of klar-milterd, so the AR chain the engine
  reads is computed on the box: the "Required ordering" above, for real.
- An hourly probe (a systemd timer on the staging box; the rig is ours and
  not in this tree) runs five
  legs: a signed ham must land in INBOX with `dkim=pass` computed here; a
  KB-brand From-forgery with no DKIM must land in Junk with `dmarc=fail`; a
  promo-shaped message must be filed to Marketing via `X-Klar-Class`; a
  blocklisted envelope sender must be refused 550 at end-of-data; and moving
  the ham to Junk must record an imapsieve feedback row in the event store.
  Success pings healthchecks.io (`klar-postfix-probe`); a silent stack pages
  within two beats.
- Known fidelity artifact: the relay hop connects from the podman bridge
  gateway (10.88.0.1), so `spf=` at our hop reflects that hop, not the
  original client. DMARC still evaluates correctly via DKIM alignment.
  (The pod has a static bridge IP because Stalwart's outbound relay refuses
  loopback targets.)

```bash
make postfix/staging-deploy   # rsync + build on the VPS + (re)start pod + timer
make postfix/staging-probe    # run one probe now, print the journal
```

PR CI stays hermetic and credential-free (`linux-gate.yml`); the staging
box tests deployment truth on a schedule instead of per-PR.

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
| `reject_threshold` | `0.99` | Calibrated spam side (the artifact's knot on the 0.99 gate, before offsets) at or above which reject mode may bounce, together with a structural condemn. 0.99 is the gate itself; a label-smoothed head never reads above 0.9906 here |
| `ip_blocklist_path` | `/var/lib/klar/model/ip_blocklist.bin` | Spamhaus DROP netblocks; empty disables the origin-IP signal |
| `ip_blocklist_max_age_days` | `14` | Age past which the loaded list is reported stale |
| `trusted_relay_cidrs` | `[]` | Relay hops you operate; enables reading the origin from `Received` |
| `auth_results` | `trust-topmost` | `ignore` drops every `Authentication-Results` before classification; required behind Stalwart (see below) |

### Origin-IP reputation (Spamhaus DROP)

The one input no amount of message parsing can produce: who actually connected.
`xxfi_connect` records the peer address, `xxfi_eom` checks it against the bundled
DROP netblocks (`OriginIpBlocklist`) and hands the engine the answer, offline — no per-message DNS lookup, so nothing about the
mail leaves the machine. A hit adds a condemn-capable spam-ward offset and stamps
`X-Klar-Origin-IP: drop-listed`.

Measured on the real corpus (`make model-lab/measure-ip-blocklist`): **3.25% of spam
with an origin IP hit DROP, and 0 of 3,994 real ham messages did**. That number is
a floor for live mail, since the corpus spans 2018-2026 while DROP lists what is
hijacked today.

A hit alone junks, it does not bounce: the reject gate still needs the content
model above `reject_threshold` as well. Only the address the MTA OBSERVED may
feed this — never one parsed out of a `Received` header, which an attacker below
the accepting hop can write at will.

#### Behind a relay

A milter behind a relay never sees the internet: our own staging MX is exactly
that shape (Stalwart owns `:25` and relays into the Postfix pod, so
`xxfi_connect` reports the podman bridge gateway `10.88.0.1`) and the check above
is inert there. Set `trusted_relay_cidrs` to the ranges you operate and the daemon
walks the `Received` chain instead: skip hops that are yours, take the first that
is not. That hop was written by a host you trust; everything below it is
attacker-writable and is never read, which is what stops a forged `Received` line
on a reply or a list post from condemning someone else's mail. A sender-chosen
HELO that looks like an IP does not count either — only the bracketed address the
receiving MTA wrote.

The resulting offset is 0.30, not 0.99: same evidence, weaker provenance (it is
only as good as your CIDR list), so it corroborates a model-side suspicion and
never junks a clean message on its own. The header records which one fired:
`X-Klar-Origin-IP: drop-listed` for an observed peer, `drop-listed-via-relay` for
a chain-derived one.

Build and refresh the artifact with `make model-lab/build-ip-blocklist` (~14 kB) and
ship it to `ip_blocklist_path`. The daemon re-reads it on **SIGHUP**, so a refresh
cron must end with one — dropping the file alone changes nothing until the next
restart. A failed re-read keeps the previous list and logs an error rather than
losing the signal; the builder likewise refuses to overwrite a good artifact with
a truncated one. A missing or malformed file disables the signal and never blocks
startup. Watch `klar_ip_blocklist_ranges`, `klar_ip_blocklist_stale` and
`klar_origin_ip_blocked_total` — a list that loads, stays fresh and never matches
looks healthy on the first two alone. Reproduce the milter's per-connection behaviour offline
with `klar-policy-cli --connect-ip <addr>`, which is how it is tested on macOS
where `klar-milterd` cannot be built.

### Why a message was junked

`policy_reason` distinguishes a content-model verdict (`ml`) from one a structural
offset flipped (`structural`), and `fired_offsets` names the offsets that fired,
with `!` marking the one credited with the flip — straight from the engine fold,
not re-derived. Without them a DROP-driven junk reads as `score_spam=0.02,
label=spam, policy_reason=ml`, which is unanswerable when a sender disputes it:

```console
$ klar-policy-cli --config /etc/klar/klar-milterd.toml --eml m.eml --json --connect-ip 1.10.16.1
  "score_spam": 0.000315,
  "label": "spam",
  "policy_reason": "structural",
  "fired_offsets": "connect_ip_drop!",
```

The same two fields land in the SQLite event row and in the JSON log line
(`fired_offsets` is omitted from the log when nothing fired). The events table
carries `PRAGMA user_version`; an older database is migrated in place on open, so
upgrading the daemon does not need a manual schema step or a fresh store.

### Verifying a deployment is live (GTUBE)

Send a message whose body or subject contains the GTUBE test string — the
anti-spam equivalent of EICAR, which every filter agrees to treat as spam — and
the milter condemns it regardless of what the model thinks of the surrounding
text:

```console
$ printf 'Subject: liveness\n\nXJS*C4JDBQADN1.NSBN3*2IDNEN*%s\n' \
    'GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X' > /tmp/gtube.eml
$ klar-policy-cli --config /etc/klar/klar-milterd.toml --eml /tmp/gtube.eml --json
  "label": "spam",
  "fired_offsets": "gtube_test",
```

`fired_offsets` may read `gtube_test!` instead: the `!` marks the offset that
FLIPPED the verdict, so it appears only when the model did not already call the
message spam on its own. Either form means the check passed.

Use this rather than "send something spammy and see": a test that relies on the
model scoring high stops testing the moment the model changes its mind. The match
is exact and case-sensitive, so mail *discussing* the test (this page, your own
setup thread) is unaffected.

## Sizing and overload behavior

Classification is CPU-bound and serialized: Postfix runs many `smtpd`
processes (default `default_process_limit = 100`), and each opens its own
libmilter thread, so the daemon happily accepts concurrent sessions. But they
all funnel through one classify mutex around a single llama.cpp context (the
context is not thread-safe), so scoring is effectively one-at-a-time per
daemon. This is by design, not a Postfix limitation: the milter protocol is
synchronous (Postfix waits for the verdict at end-of-data), and the serial
point is ours, not Postfix's. Measured wall-clock per message: ~0.6s on an
Apple-silicon core, ~4s on a shared 2-vCPU cloud instance. Plan capacity as
messages/hour ≈ 3600 / seconds-per-message, per daemon. There is no async
single-context path, because the bottleneck is model inference, not I/O. The
planned way to use more cores is a pool of llama.cpp contexts over one shared
model (the model is ~400 MB read-only and shared; each extra context is only
~10 MB of KV/compute buffers), which beats running multiple daemons that each
reload the model (TASK-295). Until that lands, scale by running multiple
daemons behind separate sockets and splitting traffic.

Under a burst, sessions queue behind the mutex. Two timeouts bound the wait:
`timeout_ms` sets libmilter's socket I/O timeout (seconds granularity), and
Postfix's `milter_content_timeout` (we ship 120s) caps the whole DATA-stage
wait. When either expires, `milter_default_action = accept` plus
`fail_open = true` mean the message is DELIVERED UNCLASSIFIED with no
X-Klar headers rather than bounced. That is the intended failure mode (never
lose mail), but it means overload silently degrades filtering: alert on
`klar_decisions{action="bypass"}` and `klar_errors_total`. Note Postfix's
default `milter_default_action` is `tempfail` (fail-closed, defer the mail):
we deliberately ship `accept` to fail open. Pick fail-closed only if losing
filtering is worse for you than deferring delivery.

Guidance:

- Set `max_inflight_sessions` to roughly 4x the vCPUs actually available to
  the milter; the default 128 assumes a dedicated multi-core server.
- Rate-limit upstream of the milter (postscreen, `smtpd_client_*_rate_limit`,
  or your edge MTA's limits) so a spam blast queues at the SMTP layer, not
  inside the milter.
- The engine memory-maps the encoder (~400 MB for q4_k_m); leave that much
  page-cache headroom or classification latency degrades sharply.

## Monitoring

The milter exposes Prometheus metrics at `/metrics` (default port 8892):

- `klar_inflight_sessions` — active milter sessions
- `klar_inflight_bytes` — buffered bytes across sessions
- `klar_decisions_total` — total classifications
- `klar_errors_total` — total errors
- `klar_model_loaded` — model readiness

Health probes: `/livez` (liveness), `/readyz` (readiness).

## Licence

The milter and the engine it embeds are AGPLv3 (`LICENSE` at the repository
root; the network-use clause means a hosted service built on modifications
must publish them, and a commercial licence without that obligation is
available from hello@klar.im). The model is a separate artifact under
CC-BY-NC-4.0 (`LICENSE-MODEL.md`): `scripts/fetch_model.sh` downloads it after
`KLAR_ACCEPT_MODEL_LICENSE=1` records that you accept it, and no release
artifact carries it. `klar-milterd` links `libmilter` from your distribution's
package and never bundles it; `THIRD_PARTY_LICENSES.md` explains why that
matters for the Sendmail License and lists every other dependency.
