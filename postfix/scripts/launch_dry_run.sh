#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POSTFIX_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$POSTFIX_DIR")"

CLI="$POSTFIX_DIR/build/klar-milterd"
CONFIG="${1:-$POSTFIX_DIR/config/example.toml}"

if [ ! -f "$CLI" ]; then
    echo "Error: klar-milterd not found. Run 'make postfix/build' first." >&2
    exit 1
fi

echo "[launch-dry-run] Config: $CONFIG"
echo "[launch-dry-run] Starting klar-milterd with --version..."
LD_LIBRARY_PATH="$REPO_ROOT/engine/build:$REPO_ROOT/engine/deps/llama-install/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    "$CLI" --version

echo ""
echo "[launch-dry-run] Validating config..."
LD_LIBRARY_PATH="$REPO_ROOT/engine/build:$REPO_ROOT/engine/deps/llama-install/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    "$CLI" --config "$CONFIG" &
PID=$!

# Give it a few seconds to start and load model
sleep 5

if kill -0 "$PID" 2>/dev/null; then
    echo "[launch-dry-run] Process $PID is running."
    echo "[launch-dry-run] Sending SIGTERM..."
    kill "$PID"
    wait "$PID" 2>/dev/null || true
    echo "[launch-dry-run] Clean shutdown."
else
    wait "$PID"
    RC=$?
    echo "[launch-dry-run] Process exited with code $RC" >&2
    exit $RC
fi
