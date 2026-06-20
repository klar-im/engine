#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
ENGINE_DIR="$REPO_ROOT/engine"

# Check if engine shared lib exists (platform-appropriate extension)
if [[ "$OSTYPE" == darwin* ]]; then
    LIB_EXT="dylib"
else
    LIB_EXT="so"
fi

ENGINE_LIB="$ENGINE_DIR/build/libspam_engine_c_api.$LIB_EXT"

if [ -f "$ENGINE_LIB" ]; then
    echo "[ensure_engine] Engine library found: $ENGINE_LIB"
    exit 0
fi

echo "[ensure_engine] Engine library not found. Building engine..."

# Build the engine library directly via its own scripts (works in both the
# monorepo and the open-core repo, which use different make-target namespaces).
# The library links no weights, so a model is not needed here — only at runtime.
if [ ! -f "$ENGINE_DIR/build/CMakeCache.txt" ]; then
    bash "$ENGINE_DIR/scripts/setup.sh"
fi
bash "$ENGINE_DIR/scripts/build.sh"

if [ ! -f "$ENGINE_LIB" ]; then
    echo "[ensure_engine] ERROR: Engine library still not found after build." >&2
    exit 1
fi

echo "[ensure_engine] Engine build complete."
