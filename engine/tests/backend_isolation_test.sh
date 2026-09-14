#!/bin/sh
# Regression test: the engine must load its OWN staged ggml backend plugins and
# must not depend on any other directory being readable.
#
# The failure this pins (2026-07-24): libggml carries an absolute compiled-in
# GGML_BACKEND_DIR (/opt/homebrew/Cellar/ggml/<v>/libexec on macOS). The loader
# called ggml_backend_load_all() FIRST, which enumerates that directory. Inside
# the Mail-extension sandbox the path exists but is unreadable, and ggml's
# fs::directory_iterator THROWS instead of skipping it, so model load died before
# our own bundled plugins were ever tried. Every message came back "skipping
# classification (no body or classifier error)" and the shipped extension
# classified nothing at all on any machine with Homebrew ggml installed.
#
# Reproduced here by denying exactly that directory with sandbox-exec. The lib
# directory stays readable because the test binary genuinely links libggml from
# there; only the plugin directory the loader enumerates is denied, which is the
# appex condition.
#
# Usage: backend_isolation_test.sh <spam_classifier> <model_dir> <ggml_backend_dir>
set -eu

BIN=${1:?binary}
MODEL=${2:?model dir}
DENY_DIR=${3:?ggml backend dir}

if [ "$(uname -s)" != "Darwin" ]; then
    echo "SKIP: sandbox-exec is macOS-only"
    exit 0
fi
if ! command -v sandbox-exec >/dev/null 2>&1; then
    echo "SKIP: sandbox-exec unavailable"
    exit 0
fi
if [ ! -d "$DENY_DIR" ]; then
    echo "SKIP: $DENY_DIR does not exist, nothing to deny"
    exit 0
fi
if [ ! -d "$MODEL" ]; then
    echo "SKIP: model not present at $MODEL (make engine/setup downloads it)"
    exit 0
fi

BIN_DIR=$(cd "$(dirname "$BIN")" && pwd)

# Part 1 (always runs, no sandbox needed): the engine must resolve its backends
# from OUR staged directory. This is the assertion that catches the ordering
# regression on its own: with ggml_backend_load_all() called first, ggml reports
# "loaded BLAS backend from /opt/homebrew/Cellar/ggml/<v>/libexec/..." and this
# fails immediately.
OUTPUT=$("$BIN" "$MODEL" 2>&1) || {
    echo "FAIL: engine could not load a model at all."
    printf '%s\n' "$OUTPUT"
    exit 1
}
LOADED=$(printf '%s\n' "$OUTPUT" | grep "loaded .* backend from" || true)
if [ -z "$LOADED" ]; then
    echo "FAIL: no dynamic backend was loaded, so this test proves nothing."
    echo "      (A static-backend ggml build would need this test rethought.)"
    printf '%s\n' "$OUTPUT"
    exit 1
fi
STRAY=$(printf '%s\n' "$LOADED" | grep -v "$BIN_DIR" || true)
if [ -n "$STRAY" ]; then
    echo "FAIL: backends loaded from outside the staged directory '$BIN_DIR'."
    echo "      Load our own plugins by path FIRST; anything else is a directory"
    echo "      the shipped Mail extension cannot read."
    printf '%s\n' "$STRAY"
    exit 1
fi
echo "ok: all backends loaded from $BIN_DIR"

# Part 2: the full appex condition, with the compiled-in plugin directory denied.
# Needs to apply a sandbox profile, which is itself not permitted when this test
# already runs inside a sandbox (agent safehouse), so probe before relying on it.
PROFILE=$(mktemp -t klar_backend_isolation)
trap 'rm -f "$PROFILE"' EXIT
cat > "$PROFILE" <<EOF
(version 1)
(allow default)
(deny file-read* (subpath "$DENY_DIR"))
EOF

if ! sandbox-exec -f "$PROFILE" /usr/bin/true >/dev/null 2>&1; then
    echo "SKIP part 2: cannot apply a nested sandbox in this environment"
    exit 0
fi

set +e
OUTPUT=$(sandbox-exec -f "$PROFILE" "$BIN" "$MODEL" 2>&1)
STATUS=$?
set -e

if [ $STATUS -ne 0 ]; then
    echo "FAIL: engine could not load a model while '$DENY_DIR' was unreadable."
    echo "      This is the Mail-extension sandbox condition: an unreadable search"
    echo "      path must never abort the load."
    printf '%s\n' "$OUTPUT"
    exit 1
fi
if ! printf '%s\n' "$OUTPUT" | grep -q "Model loaded successfully"; then
    echo "FAIL: exit 0 but the model did not report a successful load."
    printf '%s\n' "$OUTPUT"
    exit 1
fi

echo "PASS: model loaded from staged plugins with '$DENY_DIR' denied"
