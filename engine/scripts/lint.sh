#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ENGINE_DIR/build"

if [ ! -f "$BUILD_DIR/compile_commands.json" ]; then
    echo "compile_commands.json is missing: run make engine/setup" >&2
    exit 1
fi

tidy="${CLANG_TIDY:-}"
if [ -z "$tidy" ]; then
    tidy="$(command -v clang-tidy 2>/dev/null || true)"
fi
if [ -z "$tidy" ] && command -v brew >/dev/null 2>&1; then
    brew_prefix="$(brew --prefix llvm 2>/dev/null || true)"
    if [ -n "$brew_prefix" ] && [ -x "$brew_prefix/bin/clang-tidy" ]; then
        tidy="$brew_prefix/bin/clang-tidy"
    fi
fi
if [ -z "$tidy" ] || [ ! -x "$tidy" ]; then
    echo "clang-tidy is required: run make engine/setup" >&2
    exit 1
fi

runner="${RUN_CLANG_TIDY:-}"
if [ -z "$runner" ]; then
    for candidate in \
        "$(dirname "$tidy")/run-clang-tidy" \
        "$(command -v run-clang-tidy 2>/dev/null || true)"; do
        if [ -n "$candidate" ] && [ -x "$candidate" ]; then
            runner="$candidate"
            break
        fi
    done
fi
if [ -z "$runner" ] || [ ! -x "$runner" ]; then
    echo "run-clang-tidy is required: run make engine/setup" >&2
    exit 1
fi

jobs="${CPU_COUNT:-$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)}"
echo "[engine/lint] $("$tidy" --version | head -1)"
cd "$ENGINE_DIR"
exec "$runner" \
    -p "$BUILD_DIR" \
    -j "$jobs" \
    -clang-tidy-binary "$tidy" \
    -quiet
