#!/bin/bash
# The E2E's ham and GTUBE fixtures, scored with the released model through
# klar-policy-cli (a model load each; seconds). The ham must sit FAR from the
# marketing boundary: the first fixture read 0.57 regular / 0.43 marketing on
# one CPU and marketing on the CI runner, and the Sieve filed it to Marketing,
# which the E2E then reported as a filing bug. The fixtures are read out of
# test_e2e.sh itself (its ham() and gtube() functions), never restated here.
#
#   make stalwart/test-fixtures   (part of postfix/test; needs a built engine
#                                  and engine/model, like test_auth_results.sh)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STALWART_DIR="$(dirname "$HERE")"
POSTFIX_DIR="$STALWART_DIR/../postfix"
CLI="$POSTFIX_DIR/build/klar-policy-cli"
CONFIG="$POSTFIX_DIR/tests/config/auth_results_ignore.toml"
[ -x "$CLI" ] || { echo "[test-e2e-fixtures] SKIP: $CLI not built (make postfix/build)"; exit 0; }
# The test config's model_dir is "engine/model", relative to the repo root.
cd "$STALWART_DIR/.."

# Reuse the E2E's own fixture writers.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
eval "$(sed -n '/^gtube() {/,/^}/p; /^ham() {/,/^}/p' "$STALWART_DIR/scripts/test_e2e.sh")"
if ! declare -F ham >/dev/null || ! declare -F gtube >/dev/null; then
    echo "could not read ham()/gtube() out of test_e2e.sh" >&2; exit 1
fi

score() {  # score <eml>: "<label> <class> <regular> <marketing>"
    "$CLI" classify --json --config "$CONFIG" --eml "$1" 2>/dev/null \
        | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["label"], d["class"], d["score_regular"], d["score_marketing"])'
}

fail=0
read -r label cls regular marketing <<<"$(score "$(ham alice@e2e.test fixture-ham)")"
# "Clear of the boundary" is the MARGIN over marketing, not a raw floor on
# regular: a label-smoothed head (gen3-v6, smoothing 0.1 over three classes)
# tops out near 0.84 regular on blatant ham by construction, and the Sieve
# files on the argmax. The first fixture's 0.57 / 0.43 was a 0.14 margin; this
# one reads 0.99 / 0.00 on public-v0 and 0.84 / 0.12 on gen3-v6.
if [ "$label" = regular ] && [ "$cls" = regular ] && python3 -c "import sys; sys.exit(0 if float('$regular') - float('$marketing') >= 0.5 else 1)"; then
    echo "PASS  ham fixture: regular/regular, regular=$regular (marketing=$marketing), clear of the boundary"
else
    echo "FAIL  ham fixture: $label/$cls regular=$regular marketing=$marketing; needs regular to lead marketing by 0.5 or the Sieve may file it to Marketing"; fail=1
fi
read -r label cls regular marketing <<<"$(score "$(gtube alice@e2e.test fixture-gtube)")"
if [ "$label" = spam ]; then
    echo "PASS  GTUBE fixture: label spam"
else
    echo "FAIL  GTUBE fixture: label $label"; fail=1
fi
exit $fail
