#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${1:-$ENGINE_DIR/build}"

if ! command -v swiftc >/dev/null 2>&1; then
  echo "[SKIP] Swift C API smoke: swiftc not found"
  exit 0
fi

if [ ! -f "$ENGINE_DIR/model/gguf/encoder-q4_k_m.gguf" ]; then
  echo "[SKIP] Swift C API smoke: model assets not found"
  exit 0
fi

SWIFT_FILE="$SCRIPT_DIR/swift_c_api_smoke.swift"
MODULE_DIR="$SCRIPT_DIR/swift_c_api_module"
OUTPUT_BIN="$BUILD_DIR/swift_c_api_smoke"
SWIFT_MODULE_CACHE="$BUILD_DIR/swift-module-cache"

mkdir -p "$SWIFT_MODULE_CACHE"

swiftc \
  "$SWIFT_FILE" \
  -I "$MODULE_DIR" \
  -L "$BUILD_DIR" \
  -module-cache-path "$SWIFT_MODULE_CACHE" \
  -lspam_engine_c_api \
  -o "$OUTPUT_BIN"

if [ "$(uname -s)" = "Darwin" ]; then
  export DYLD_LIBRARY_PATH="$BUILD_DIR:$ENGINE_DIR/deps/llama-install/lib:${DYLD_LIBRARY_PATH:-}"
else
  export LD_LIBRARY_PATH="$BUILD_DIR:$ENGINE_DIR/deps/llama-install/lib:${LD_LIBRARY_PATH:-}"
fi

"$OUTPUT_BIN" "$ENGINE_DIR"
