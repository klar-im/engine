#!/bin/bash
# End to end, on the compose stack (stalwart/docker-compose.yml): Stalwart hands
# every inbound message to klar-milterd, the account's Sieve files on the verdict,
# and Stalwart's own filter is out of the decision. Asserts, in order:
#
#   shadow   apply.py --shadow: Stalwart still scores (X-Spam-Result present,
#            KLAR_SHADOW in it, X-Spam-Status No) and the milter stamps X-Klar-*.
#   final    apply.py: no X-Spam-* on new mail at all (filter off);
#            GTUBE to alice  -> Junk, X-Klar-Label spam
#            ham to alice    -> Inbox, X-Klar-Label regular
#            GTUBE to trap   -> Inbox with X-Klar-Label spam (a collection
#                               mailbox: headers, never filing)
#            forged-AR phish from a p=reject brand -> refused 550 at DATA by
#                               dmarcVerify strict (the layer in front of the
#                               milter; auth_results=ignore, the layer behind
#                               it, is scored in postfix/scripts/test_auth_results.sh)
#
# Needs docker compose (or podman compose) and the network for two pulls and the
# model. Skips cleanly (exit 0, says so) where neither runtime works, so
# `make stalwart/test` passes on a machine that cannot run containers; the
# public CI runs it for real.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STALWART_DIR="$(dirname "$HERE")"
COMPOSE_FILE="$STALWART_DIR/docker-compose.yml"

if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose -f "$COMPOSE_FILE")
elif podman compose version >/dev/null 2>&1; then
    COMPOSE=(podman compose -f "$COMPOSE_FILE")
else
    echo "[stalwart/e2e] SKIP: neither 'docker compose' nor 'podman compose' works here; the public CI runs this."
    exit 0
fi

ADMIN_PW="${STALWART_ADMIN_PASSWORD:-klar-e2e}"
export STALWART_ADMIN_PASSWORD="$ADMIN_PW"
export KLAR_ACCEPT_MODEL_LICENSE=1
DOMAIN="e2e.test"
ALICE_PW="alice-e2e-pw"
TRAP_PW="trap-e2e-pw"
STAMP="$(date +%Y%m%d-%H%M%S)"
fail=0

# shellcheck disable=SC2329
cleanup() { "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true; }  # run by the trap
trap cleanup EXIT

say()  { printf '[stalwart/e2e] %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }
flunk() { printf 'FAIL  %s\n' "$*"; fail=1; }
indent() {  # indent "<text>" or a pipe into it: six spaces before every line
    if [ $# -gt 0 ]; then
        while IFS= read -r line; do printf '      %s\n' "$line"; done <<<"$1"
    else
        while IFS= read -r line; do printf '      %s\n' "$line"; done
    fi
}

# stalwart-cli is a separate release (stalwartlabs/cli); upstream's server image
# does not carry it. Fetch the pinned build once (same pin and checksum as
# infra/stalwart-v016/versions.json) and talk to the container's published
# management port. STALWART_CLI overrides for a machine that has one.
CLI_VERSION="1.0.12"
CLI_SHA256="e2bb054509aaac311f13ff4f9e09c38c607195de2e9735cf84cfc6ee4776a5a2"
CLI_BIN="${STALWART_CLI:-}"
if [ -z "$CLI_BIN" ]; then
    CLI_DIR="${TMPDIR:-/tmp}/stalwart-cli-$CLI_VERSION"
    CLI_BIN="$CLI_DIR/stalwart-cli-x86_64-unknown-linux-gnu/stalwart-cli"
    if [ ! -x "$CLI_BIN" ]; then
        mkdir -p "$CLI_DIR"
        curl -fsSL "https://github.com/stalwartlabs/cli/releases/download/v$CLI_VERSION/stalwart-cli-x86_64-unknown-linux-gnu.tar.xz" \
            -o "$CLI_DIR/cli.tar.xz"
        echo "$CLI_SHA256  $CLI_DIR/cli.tar.xz" | sha256sum -c - >/dev/null
        tar -xJf "$CLI_DIR/cli.tar.xz" -C "$CLI_DIR"
    fi
fi
CLI_WRAP="$(mktemp)"
cat > "$CLI_WRAP" <<EOF
#!/bin/bash
exec '$CLI_BIN' --url http://127.0.0.1:18080 --user admin --password '$ADMIN_PW' "\$@"
EOF
chmod +x "$CLI_WRAP"
cli() { "$CLI_WRAP" "$@"; }

say "starting the stack (first run fetches the model, ~400 MB)"
# KLAR_MILTERD_IMAGE set = an image built elsewhere (CI, with a layer cache);
# otherwise compose builds it from this tree.
BUILD_FLAG="--build"
[ -n "${KLAR_MILTERD_IMAGE:-}" ] && BUILD_FLAG="--no-build"
# How long a first start may take is the image's HEALTHCHECK start period (the
# model fetch happens inside it); read it rather than restate it, so the two
# cannot disagree and mark a slow fetch unhealthy before this wait gives up.
START_PERIOD="$(sed -n 's/.*--start-period=\([0-9]*\)s.*/\1/p' "$STALWART_DIR/../postfix/docker/Dockerfile")"
[ -n "$START_PERIOD" ] || { echo "error: no --start-period in postfix/docker/Dockerfile HEALTHCHECK" >&2; exit 1; }
"${COMPOSE[@]}" up -d "$BUILD_FLAG" --wait --wait-timeout "$START_PERIOD"

wait_api() {  # Stalwart's management API answers, or the run stops here, saying why
    for _ in $(seq 1 60); do
        cli query Domain >/dev/null 2>&1 && return 0
        sleep 2
    done
    flunk "Stalwart API never answered. The CLI's last word, the listener, and the container:"
    cli query Domain 2>&1 | indent || true
    curl -sS -o /dev/null -w '      GET /healthz -> HTTP %{http_code}\n' http://127.0.0.1:18080/healthz || true
    "${COMPOSE[@]}" ps 2>&1 | indent || true
    "${COMPOSE[@]}" logs --no-color --tail 60 stalwart 2>&1 | indent || true
    exit 1
}

# A fresh Stalwart 0.16 starts in BOOTSTRAP MODE: only the Bootstrap object
# answers ("forbidden: The server is in bootstrap mode ...") until the setup
# wizard has run. Its one call, `update Bootstrap`, creates the default domain
# (Manual DKIM when generateDkimKeys is off) and every listener, smtp on :25
# included; the server leaves bootstrap mode on the restart after it. The
# recovery admin from STALWART_RECOVERY_ADMIN keeps working across it, and the
# admin@<domain> account the wizard prints is not needed here. A stack whose
# volume already went through this (a re-run) answers Domain queries at once
# and skips the block.
bootstrap_if_fresh() {
    local out
    for _ in $(seq 1 60); do
        out="$(cli query Domain 2>&1)" && return 0
        case "$out" in *"bootstrap mode"*) break ;; esac
        sleep 2
    done
    case "$out" in *"bootstrap mode"*) ;; *) return 0 ;; esac
    say "fresh server: completing Stalwart's bootstrap for $DOMAIN"
    printf '%s' "{\"serverHostname\":\"mail.$DOMAIN\",\"defaultDomain\":\"$DOMAIN\",\"requestTlsCertificate\":false,\"generateDkimKeys\":false}" \
        | cli update Bootstrap singleton --stdin >/dev/null
    "${COMPOSE[@]}" restart stalwart >/dev/null
}
bootstrap_if_fresh
say "waiting for Stalwart's management API"
wait_api

say "domain + two accounts: alice (files) and trap (collection, headers only)"
# The same object shapes infra/scripts/stalwart-setup.sh creates on klar.im
# (Manual DKIM so a fresh domain does not self-generate keys; a User account
# with one Password credential).
cli query Domain --json | grep -q "\"$DOMAIN\"" \
    || printf '%s' "{\"name\":\"$DOMAIN\",\"description\":\"e2e\",\"dkimManagement\":{\"@type\":\"Manual\"}}" | cli create Domain --stdin >/dev/null
DID="$(cli query Domain --json | python3 -c "import sys,json
for l in sys.stdin:
    o=json.loads(l)
    if o.get('name')=='$DOMAIN': print(o['id']); break")"
[ -n "$DID" ] || { flunk "domain $DOMAIN has no id"; exit 1; }
for acct in "alice:$ALICE_PW" "trap:$TRAP_PW"; do
    user="${acct%%:*}"; pw="${acct#*:}"
    cli query Account --json | grep -q "\"$user@$DOMAIN\"" \
        || printf '%s' "{\"@type\":\"User\",\"name\":\"$user\",\"domainId\":\"$DID\",\"description\":\"e2e\",\"credentials\":{\"0\":{\"@type\":\"Password\",\"secret\":\"$pw\"}}}" \
            | cli create Account --stdin >/dev/null
done
# A fresh container also has the default https listener on 443 and the built-in
# spam filter on; only the filter matters here and apply.py owns it.
#
# New account credentials are loaded at startup (infra/stalwart-v016/README.md:
# a fresh account authenticated over the API but not over IMAP/JMAP until a
# restart), so restart once before anything logs in as alice or trap.
"${COMPOSE[@]}" restart stalwart >/dev/null
wait_api

send() {  # send <rcpt> <file> [envelope-from]: prints 0 when accepted, else the SMTP code
    python3 - "$1" "$2" "${3:-probe@sender.example}" <<'PY'
import smtplib, sys
rcpt, path, sender = sys.argv[1], sys.argv[2], sys.argv[3]
raw = open(path, "rb").read()
try:
    with smtplib.SMTP("127.0.0.1", 2525, timeout=60) as s:
        s.ehlo("probe.sender.example")
        s.sendmail(sender, [rcpt], raw)
    print(0)
except smtplib.SMTPRecipientsRefused as exc:
    # Not an SMTPResponseException: the per-recipient dict holds the code.
    print(next(iter(exc.recipients.values()))[0])
except smtplib.SMTPResponseException as exc:
    print(exc.smtp_code)
except (smtplib.SMTPException, OSError) as exc:
    print(f"error: {exc}", file=sys.stderr)
    print(1)
PY
}

accepted() {  # accepted <rcpt> <file>: the probe must get past SMTP, or nothing below means anything
    local code
    code="$(send "$1" "$2")"
    [ "$code" = 0 ] || { flunk "Stalwart refused the probe to $1 with SMTP $code"; exit 1; }
}

# JMAP as the account: where did the message with this subject land, with
# which headers? Prints mailbox-role and the headers we assert on, one per line.
inspect() {  # inspect <user> <password> <subject-marker>
    python3 - "$1" "$2" "$3" <<PY
import sys, time
sys.path.insert(0, "$HERE")
from sieve_activate import Session
user, pw, marker = sys.argv[1], sys.argv[2], sys.argv[3]
s = Session("http://127.0.0.1:18080", f"{user}@e2e.test", pw, capabilities=("urn:ietf:params:jmap:mail",))
roles = {m["id"]: (m.get("role") or m["name"]).lower() for m in s.call("Mailbox/get", {})["list"]}
for _ in range(30):
    ids = s.call("Email/query", {"filter": {"subject": marker}})["ids"]
    if ids: break
    time.sleep(2)
else:
    print("mailbox=NOT-DELIVERED"); sys.exit(0)
e = s.call("Email/get", {"ids": ids, "properties": ["mailboxIds", "headers"]})["list"][0]
print("mailbox=" + ",".join(sorted(roles[m] for m in e["mailboxIds"])))
for h in e["headers"]:
    n = h["name"].lower()
    if n.startswith("x-klar-") or n.startswith("x-spam-"):
        print(f"{n}=" + h["value"].strip().replace("\n", " ").replace("\t", " ")[:200])
PY
}

TMP="$(mktemp -d)"
gtube() {  # gtube <rcpt> <marker>
    printf 'From: Liveness <probe@sender.example>\r\nTo: %s\r\nSubject: liveness %s\r\nMessage-ID: <%s@sender.example>\r\n\r\nXJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n' "$1" "$2" "$2" > "$TMP/$2.eml"
    echo "$TMP/$2.eml"
}
ham() {  # ham <rcpt> <marker>
    printf 'From: Dana <dana@sender.example>\r\nTo: %s\r\nSubject: lunch tomorrow %s\r\nMessage-ID: <%s@sender.example>\r\n\r\nStill on for lunch tomorrow at noon? I booked the usual place.\r\n\r\nDana\r\n' "$1" "$2" "$2" > "$TMP/$2.eml"
    echo "$TMP/$2.eml"
}

# ---------------------------------------------------------------------------
say "phase 1: shadow (Stalwart scores, never files; milter decides)"
STALWART_CLI="$CLI_WRAP" python3 "$HERE/apply.py" --shadow --milter-host klar-milterd --milter-port 8891
STALWART_PASSWORD="$ALICE_PW" python3 "$HERE/sieve_activate.py" --url http://127.0.0.1:18080 --user "alice@$DOMAIN"

accepted "alice@$DOMAIN" "$(ham "alice@$DOMAIN" "ham-shadow-$STAMP")"
out="$(inspect alice "$ALICE_PW" "ham-shadow-$STAMP")"
if grep -q "^x-spam-result=.*KLAR_SHADOW" <<<"$out" && grep -q "^x-spam-status=No" <<<"$out" && grep -q "^x-klar-label=regular" <<<"$out"; then
    pass "shadow: Stalwart scored (KLAR_SHADOW), did not file, milter stamped regular"
else
    flunk "shadow headers wrong:"; indent "$out"
fi

# ---------------------------------------------------------------------------
say "phase 2: final (Stalwart's filter off; the engine decides, Sieve files)"
STALWART_CLI="$CLI_WRAP" python3 "$HERE/apply.py" --milter-host klar-milterd --milter-port 8891

accepted "alice@$DOMAIN" "$(gtube "alice@$DOMAIN" "gtube-alice-$STAMP")"
out="$(inspect alice "$ALICE_PW" "gtube-alice-$STAMP")"
if grep -q "^mailbox=junk" <<<"$out" && grep -q "^x-klar-label=spam" <<<"$out" && ! grep -q "^x-spam-" <<<"$out"; then
    pass "final: GTUBE to alice -> Junk via X-Klar-Label spam, no X-Spam-* header"
else
    flunk "GTUBE to alice:"; indent "$out"
fi

accepted "alice@$DOMAIN" "$(ham "alice@$DOMAIN" "ham-final-$STAMP")"
out="$(inspect alice "$ALICE_PW" "ham-final-$STAMP")"
if grep -q "^mailbox=inbox" <<<"$out" && grep -q "^x-klar-label=regular" <<<"$out"; then
    pass "final: ham to alice -> Inbox, X-Klar-Label regular"
else
    flunk "ham to alice:"; indent "$out"
fi

accepted "trap@$DOMAIN" "$(gtube "trap@$DOMAIN" "gtube-trap-$STAMP")"
out="$(inspect trap "$TRAP_PW" "gtube-trap-$STAMP")"
if grep -q "^mailbox=inbox" <<<"$out" && grep -q "^x-klar-label=spam" <<<"$out"; then
    pass "final: GTUBE to trap (no Sieve) -> stays in Inbox, carries X-Klar-Label spam"
else
    flunk "GTUBE to trap:"; indent "$out"
fi

# The forged-AR phish (stalwart/tests/fixtures, the same file
# postfix/scripts/test_auth_results.sh scores through the CLI): a PayPal phish
# FROM paypal.com carrying a forged dkim=pass. Behind Stalwart it never reaches
# the milter: paypal.com publishes p=reject, the message is unsigned, and
# dmarcVerify strict (applied above) refuses it at DATA with a 550. That is the
# first of the two layers; the second (auth_results=ignore, for a brand that does
# not publish p=reject) is asserted with the real model in test_auth_results.sh.
sed -e "s/^To: .*/To: alice@$DOMAIN/" -e "s/^Subject: /Subject: forged-ar-$STAMP /" \
    "$STALWART_DIR/tests/fixtures/forged-ar-brand-domain.eml" > "$TMP/forged.eml"
code="$(send "alice@$DOMAIN" "$TMP/forged.eml" "service@paypal.com")"
if [ "$code" = 550 ]; then
    pass "final: the forged-AR p=reject phish is refused at SMTP by dmarcVerify strict (550)"
else
    flunk "forged-AR p=reject phish got SMTP $code, expected 550 (dmarcVerify strict not in effect?)"
fi

rm -rf "$TMP" "$CLI_WRAP"
exit $fail
