#!/bin/sh
set -e

# Wait for the events.sqlite3 to be created by the milter (via shared volume),
# then fix ownership so vmail user can write feedback records.
# The milter typically creates the DB within seconds of startup.
for i in $(seq 1 60); do
    if [ -f /var/lib/klar/events.sqlite3 ]; then
        chown -R vmail:vmail /var/lib/klar
        break
    fi
    sleep 1
done

# Even if DB doesn't exist yet, ensure directory is writable
chown vmail:vmail /var/lib/klar 2>/dev/null || true

exec dovecot -F
