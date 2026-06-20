#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POSTFIX_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$POSTFIX_DIR")"

CLI="$POSTFIX_DIR/build/klar-policy-cli"
CONFIG="$POSTFIX_DIR/tests/config/tag.toml"
MANIFEST="$POSTFIX_DIR/tests/fixtures/stable_manifest.csv"
PYTHON="${POSTFIX_DIR}/.venv/bin/python3"
[ -x "$PYTHON" ] || PYTHON="python3"

echo "[validate-risk] R1: Score margin regression..."
cd "$REPO_ROOT"
"$PYTHON" "$POSTFIX_DIR/tests/scripts/score_fixtures.py" \
    --config "$CONFIG" \
    --manifest "$MANIFEST" \
    --policy-cli "$CLI" \
    --out /tmp/klar-risk-scores.json

echo "[validate-risk] All checks passed."
