#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ENGINE_DIR/build"
CPU_COUNT="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 8)"

if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
    echo "Error: CMake not configured. Run 'make engine/setup' first." >&2
    exit 1
fi

# Inside agent-safehouse, xcodebuild is sandboxed off, so clang can't shell
# out to it to locate the SDK. Pin the Command Line Tools toolchain when
# nothing else is set; falls through silently if CLT isn't installed.
if [ -z "${DEVELOPER_DIR:-}" ] && [ -d /Library/Developer/CommandLineTools ]; then
    export DEVELOPER_DIR=/Library/Developer/CommandLineTools
fi
if [ -z "${SDKROOT:-}" ] && [ -d /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk ]; then
    export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
fi

echo "[build] Building..."
cmake --build "$BUILD_DIR" -j"$CPU_COUNT"

echo "[build] Done. Binary at: $BUILD_DIR/spam_classifier"
