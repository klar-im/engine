# Postfix + Dovecot + Klar Architecture

## Mail Flow

```
                          SMTP                    LMTP
  Sender ──────► Postfix ──────► klar-milterd ──────► Dovecot ──────► Maildir
                  :25            :8891               :24           /var/mail/
                                   │
                                   ├─ classify (engine)
                                   ├─ add X-Klar-* headers
                                   └─ action: tag or reject
                                                      │
                                              Dovecot Sieve checks
                                              X-Klar-Label header:
                                                spam → Junk/
                                                regular → INBOX/
```

There is no quarantine. We are not an antivirus product. Messages are either
delivered (spam goes to Junk, regular to Inbox) or rejected at SMTP time
(high-confidence spam in reject mode). Users self-service via their Junk
folder like they do with Gmail, Fastmail, etc.

## Feedback Flow

```
  User moves message to Junk (any IMAP client)
       │
       ▼
  Dovecot imapsieve detects folder move
       │
       ▼
  Sieve pipes message to:
    klar-feedback spam|ham  (shell script using sqlite3)
       │
       ▼
  Script extracts X-Klar-Event-ID from headers → writes to feedback table (SQLite)
```

Same flow in reverse when user moves OUT of Junk (verdict = ham).

## Retraining Flow

```
  Cron / admin runs:
    python3 train_from_imap.py --imap-host <host> --model-dir <path>
       │
       ├─ reads INBOX (label=regular) and Junk (label=spam) via IMAP
       ├─ loads engine + training C API (libspam_engine_*_c_api.so)
       ├─ queues samples with spam_engine_add_training_sample()
       ├─ trains with spam_engine_train_incremental()
       ├─ saves updated classifier weights
       └─ SIGHUP to klar-milterd → hot-reloads model
```

The engine supports online learning: a trainable 2-layer classifier
head on top of the frozen XLM-RoBERTa encoder, with Adam optimizer.
Same architecture as the Apple Mail nightly training.

## Components

### 1. Postfix (existing, modified)

Delivers to Dovecot via LMTP instead of relaying externally.
Milter integration unchanged — classify before delivery.

### 2. klar-milterd (existing, simplified)

Actions:
- **tag**: always deliver, add X-Klar-* headers. Dovecot Sieve sorts.
- **reject**: reject above reject_threshold at SMTP time. Deliver rest.

No quarantine action. No smfi_quarantine(). Headers added to every message:
- X-Klar-Event-ID (links back to event store for feedback)
- X-Klar-Label (spam | regular — used by Sieve for filing)
- X-Klar-Score-* (4 scores)
- X-Klar-Action, X-Klar-Model-Version

### 3. Dovecot (new)

- **LMTP**: accepts mail from Postfix, writes to Maildir
- **IMAP**: users connect with any mail client
- **Sieve**: global script files spam to Junk based on X-Klar-Label header
- **imapsieve**: fires on folder moves, pipes message to CLI for feedback

### 4. klar-feedback (shell script)

```
klar-feedback spam|ham < message.eml
```

Self-contained shell script (no engine dependency) that reads RFC822 from stdin,
extracts X-Klar-Event-ID via header parsing, writes to feedback table using sqlite3.
If no X-Klar-Event-ID found (pre-klar message moved to Junk), exits 0 silently.

### 5. Event Store (existing, extended)

New table:
```sql
CREATE TABLE IF NOT EXISTS feedback (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    event_id  TEXT NOT NULL,
    verdict   TEXT NOT NULL,
    source    TEXT NOT NULL,
    reporter  TEXT NOT NULL
);
```

## Docker E2E Test Stack

```yaml
services:
  klar-milterd:    # classifier milter on :8891
  postfix:         # SMTP on :25, delivers via LMTP to dovecot
  dovecot:         # LMTP on :24, IMAP on :143, sieve + imapsieve

volumes:
  klar-data:       # shared SQLite event store
```

E2E test verifies:
1. Send ham → arrives in INBOX with X-Klar-Label: regular
2. Send spam → arrives in Junk with X-Klar-Label: spam
3. Move message between Junk ↔ INBOX → feedback recorded in SQLite
