#!/bin/bash
# Install the built milter as a self-contained tree: `install.sh [PREFIX]`
# (default /opt/klar). After `make postfix/build` (or `make build` in the public
# repo) this copies klar-milterd, klar-policy-cli and every shared library they
# load into PREFIX/bin, one directory, because ggml_backend_load_all() finds its
# CPU-variant plugins next to the executable and the daemon must not depend on
# the build tree staying where it was. Nothing else: no model (fetch_model.sh,
# or point model_dir at one you have), no config (packaging/ has the templates),
# no unit. Idempotent: re-running replaces the files in place.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POSTFIX_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$POSTFIX_DIR")"
PREFIX="${1:-/opt/klar}"
BIN="$PREFIX/bin"

[ -f "$POSTFIX_DIR/build/klar-milterd" ] || { echo "error: postfix/build/klar-milterd not found; build first" >&2; exit 1; }

mkdir -p "$BIN"
install -m 0755 "$POSTFIX_DIR/build/klar-milterd" "$BIN/klar-milterd.new"
[ -f "$POSTFIX_DIR/build/klar-policy-cli" ] && install -m 0755 "$POSTFIX_DIR/build/klar-policy-cli" "$BIN/klar-policy-cli"

# The engine library, its core, and the pinned llama.cpp/ggml it was built
# against (engine/scripts/setup.sh puts those in engine/deps/llama-install).
for lib in "$REPO_ROOT"/engine/build/libspam_engine*.so \
           "$REPO_ROOT"/engine/deps/llama-install/lib/libllama.so* \
           "$REPO_ROOT"/engine/deps/llama-install/lib/libggml*.so*; do
    [ -e "$lib" ] || continue
    if [ -L "$lib" ]; then
        cp -P "$lib" "$BIN/"           # keep the soname symlink chain as is
    else
        install -m 0644 "$lib" "$BIN/"
    fi
done

# Atomic swap of the daemon binary last, so a running service never sees a
# half-written executable and a restart picks up the new one.
mv -f "$BIN/klar-milterd.new" "$BIN/klar-milterd"

echo "[install] $BIN:"
for f in "$BIN"/*; do echo "  ${f##*/}"; done
echo "[install] run with: LD_LIBRARY_PATH=$BIN $BIN/klar-milterd --config <toml>"
