#!/bin/bash
# Offline assertion for `auth_results = "ignore"` (TASK-503, config.h): behind an
# MTA whose milters see the client's raw bytes (Stalwart), the message's own
# Authentication-Results is the sender's claim about itself, and the engine
# believes the topmost one. The fixture is a PayPal phish FROM paypal.com carrying
# a forged `dkim=pass header.d=paypal.com; dmarc=pass`:
#   - trust-topmost (the default): the forged AR fires the kb_brand_dmarc rescue
#     (-0.90, engine/spam_engine_c_api.cpp) and the phish is DELIVERED as regular.
#   - ignore: the header never reaches the engine, no rescue, labelled spam.
# Both halves are asserted, so the test is red if the switch stops stripping AND
# red if the engine stops trusting AR (at which point the switch is dead code and
# this test should be retired with it).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POSTFIX_DIR="$(dirname "$SCRIPT_DIR")"
CLI="$POSTFIX_DIR/build/klar-policy-cli"
FIXTURE="$POSTFIX_DIR/../stalwart/tests/fixtures/forged-ar-brand-domain.eml"

verdict() {  # verdict <config>: "<label> <fired_offsets>", one model load per config
    "$CLI" classify --json --config "$POSTFIX_DIR/tests/config/$1.toml" --eml "$FIXTURE" 2>/dev/null \
        | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["label"], d["fired_offsets"])'
}

fail=0

read -r trust_label trust_fired <<<"$(verdict auth_results_trust)"
if [ "$trust_label" = "regular" ] && [[ "$trust_fired" == *kb_brand_dmarc* ]]; then
    echo "PASS  trust-topmost: forged AR buys the kb_brand_dmarc rescue -> '$trust_label' ($trust_fired)"
else
    echo "FAIL  trust-topmost: expected 'regular' with kb_brand_dmarc fired, got '$trust_label' ($trust_fired)."
    echo "      If the engine no longer trusts the topmost AR, retire auth_results with this test."
    fail=1
fi

read -r ignore_label ignore_fired <<<"$(verdict auth_results_ignore)"
if [ "$ignore_label" = "spam" ] && [[ "$ignore_fired" != *kb_brand_dmarc* ]]; then
    echo "PASS  ignore: AR stripped, no rescue -> '$ignore_label' ($ignore_fired)"
else
    echo "FAIL  ignore: expected 'spam' without kb_brand_dmarc, got '$ignore_label' ($ignore_fired)"; fail=1
fi

exit $fail
