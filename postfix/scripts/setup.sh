#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POSTFIX_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$POSTFIX_DIR")"

echo "[postfix/setup] Checking dependencies..."

# Detect OS
if [[ "$OSTYPE" == darwin* ]]; then
    # macOS
    command -v brew >/dev/null || { echo "Error: Homebrew required" >&2; exit 1; }
    for pkg in cmake pkg-config ninja; do
        brew list "$pkg" >/dev/null 2>&1 || brew install "$pkg"
    done
    # libmilter on macOS - check if available
    if ! pkg-config --exists libmilter 2>/dev/null; then
        echo "[postfix/setup] Note: libmilter not found via pkg-config on macOS."
        echo "[postfix/setup] The build may need manual libmilter setup on macOS."
    fi
else
    # Linux
    echo "[postfix/setup] Ensuring system packages..."
    if command -v apt-get >/dev/null 2>&1; then
        NEEDED=""
        dpkg -l build-essential >/dev/null 2>&1 || NEEDED="$NEEDED build-essential"
        dpkg -l cmake >/dev/null 2>&1 || NEEDED="$NEEDED cmake"
        dpkg -l pkg-config >/dev/null 2>&1 || NEEDED="$NEEDED pkg-config"
        dpkg -l libmilter-dev >/dev/null 2>&1 || NEEDED="$NEEDED libmilter-dev"
        dpkg -l libsqlite3-dev >/dev/null 2>&1 || NEEDED="$NEEDED libsqlite3-dev"
        dpkg -l libgmime-3.0-dev >/dev/null 2>&1 || NEEDED="$NEEDED libgmime-3.0-dev"
        dpkg -l python3-venv >/dev/null 2>&1 || NEEDED="$NEEDED python3-venv"
        if [ -n "$NEEDED" ]; then
            echo "[postfix/setup] Installing: $NEEDED"
            sudo apt-get update -qq && sudo apt-get install -y -qq $NEEDED
        fi
    fi
fi

# Ensure engine artifacts
echo "[postfix/setup] Ensuring engine artifacts..."
bash "$POSTFIX_DIR/scripts/ensure_engine_artifacts.sh"

# Python venv for the E2E test scripts. Those scripts (and their requirements)
# are not part of the open-core publish set, so skip this step when absent.
if [ -f "$POSTFIX_DIR/tests/requirements.txt" ]; then
    echo "[postfix/setup] Setting up Python venv..."
    if [ ! -d "$POSTFIX_DIR/.venv" ]; then
        python3 -m venv "$POSTFIX_DIR/.venv"
    fi
    "$POSTFIX_DIR/.venv/bin/pip" install -q -U pip
    "$POSTFIX_DIR/.venv/bin/pip" install -q -r "$POSTFIX_DIR/tests/requirements.txt"
else
    echo "[postfix/setup] No tests/requirements.txt (open-core build) — skipping Python venv."
fi

echo "[postfix/setup] Done."
