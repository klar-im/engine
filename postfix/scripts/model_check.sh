#!/bin/bash
# model_check.sh [model-dir]: which model is installed, and is it the released one.
#
# Reads <model-dir>/MANIFEST.json, the file fetch_model.sh writes and the daemon
# reports as model_version (default dir: /var/lib/klar/model, the same default
# as the config). Compares its model_uuid with postfix/model/released-manifest.json,
# the pinned release. Exit 0 when they match, 1 when a different model is
# installed, 2 when nothing is.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_DIR="${1:-/var/lib/klar/model}"
RELEASED="$SCRIPT_DIR/../model/released-manifest.json"

if [ ! -f "$MODEL_DIR/MANIFEST.json" ]; then
    echo "[model-check] no model at $MODEL_DIR (no MANIFEST.json)."
    echo "[model-check] install one: KLAR_ACCEPT_MODEL_LICENSE=1 $SCRIPT_DIR/fetch_model.sh $MODEL_DIR"
    exit 2
fi
uuid_of() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["model_uuid"])' "$1"; }
local_uuid="$(uuid_of "$MODEL_DIR/MANIFEST.json")"
released_uuid="$(uuid_of "$RELEASED")"
echo "[model-check] installed: $local_uuid ($MODEL_DIR)"
echo "[model-check] released:  $released_uuid"
if [ "$local_uuid" = "$released_uuid" ]; then
    echo "[model-check] up to date."
else
    echo "[model-check] a different model is installed; update with: KLAR_ACCEPT_MODEL_LICENSE=1 $SCRIPT_DIR/fetch_model.sh $MODEL_DIR"
    exit 1
fi
