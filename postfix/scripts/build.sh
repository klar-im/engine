#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POSTFIX_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$POSTFIX_DIR")"
BUILD_DIR="$POSTFIX_DIR/build"

# Verify engine artifacts exist
if [[ "$OSTYPE" == darwin* ]]; then
    LIB_EXT="dylib"
else
    LIB_EXT="so"
fi

ENGINE_LIB="$REPO_ROOT/engine/build/libspam_engine_c_api.$LIB_EXT"
if [ ! -f "$ENGINE_LIB" ]; then
    echo "Error: Engine C API library not found: $ENGINE_LIB" >&2
    echo "Run 'make postfix/setup' first." >&2
    exit 1
fi

# Configure
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [ ! -f CMakeCache.txt ]; then
    echo "[postfix/build] Configuring CMake..."
    cmake "$POSTFIX_DIR" -DCMAKE_BUILD_TYPE=Release
fi

# Build
CPU_COUNT="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
echo "[postfix/build] Building..."
cmake --build . -j"$CPU_COUNT"

echo "[postfix/build] Done. Binaries:"
ls -la klar-milterd klar-policy-cli 2>/dev/null || true
