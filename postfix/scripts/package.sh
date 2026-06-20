#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POSTFIX_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$POSTFIX_DIR")"
DIST_DIR="$POSTFIX_DIR/dist"
VERSION="${KLAR_VERSION:-$(git -C "$REPO_ROOT" describe --tags --always 2>/dev/null || echo dev)}"
ARCH="$(uname -m)"

echo "[postfix/package] Building package v${VERSION} for ${ARCH}..."

# Verify binary exists
if [ ! -f "$POSTFIX_DIR/build/klar-milterd" ]; then
    echo "Error: klar-milterd not found. Run 'make postfix/build' first." >&2
    exit 1
fi

# Determine lib extension
if [[ "$OSTYPE" == darwin* ]]; then
    LIB_EXT="dylib"
else
    LIB_EXT="so"
fi

# Create dist structure
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR/bin" "$DIST_DIR/lib" "$DIST_DIR/model" "$DIST_DIR/etc"

# Binary
cp "$POSTFIX_DIR/build/klar-milterd" "$DIST_DIR/bin/"
if [ -f "$POSTFIX_DIR/build/klar-policy-cli" ]; then
    cp "$POSTFIX_DIR/build/klar-policy-cli" "$DIST_DIR/bin/"
fi

# Shared libraries
for lib in libspam_engine.$LIB_EXT libspam_engine_c_api.$LIB_EXT; do
    if [ -f "$REPO_ROOT/engine/build/$lib" ]; then
        cp "$REPO_ROOT/engine/build/$lib" "$DIST_DIR/lib/"
    fi
done

LLAMA_LIB_DIR="$REPO_ROOT/engine/deps/llama-install/lib"
if [ -d "$LLAMA_LIB_DIR" ]; then
    cp "$LLAMA_LIB_DIR"/libllama.so* "$DIST_DIR/lib/" 2>/dev/null || true
    cp "$LLAMA_LIB_DIR"/libggml*.so* "$DIST_DIR/lib/" 2>/dev/null || true
fi

# Model files
mkdir -p "$DIST_DIR/model/gguf"
for f in classifier_config.json classifier_dense_weight.bin classifier_dense_bias.bin \
         classifier_out_proj_weight.bin classifier_out_proj_bias.bin \
         gguf/encoder-q4_k_m.gguf; do
    if [ -f "$REPO_ROOT/engine/model/$f" ]; then
        cp "$REPO_ROOT/engine/model/$f" "$DIST_DIR/model/$f"
    fi
done

if [ -f "$REPO_ROOT/engine/model/VERSION" ]; then
    cp "$REPO_ROOT/engine/model/VERSION" "$DIST_DIR/model/"
else
    echo "$VERSION" > "$DIST_DIR/model/VERSION"
fi

# Config + systemd unit
cp "$POSTFIX_DIR/config/example.toml" "$DIST_DIR/etc/klar-postfix.toml"
cp "$POSTFIX_DIR/packaging/klar-milterd.service" "$DIST_DIR/etc/"
cp "$POSTFIX_DIR/packaging/postfix-main.cf.snippet" "$DIST_DIR/etc/"

# Create tarball
TARBALL="klar-milterd-${VERSION}-linux-${ARCH}.tar.gz"
echo "[postfix/package] Creating $TARBALL..."
tar -czf "$DIST_DIR/$TARBALL" -C "$DIST_DIR" bin/ lib/ model/ etc/

# Summary
echo "[postfix/package] Done."
echo "  Tarball: $DIST_DIR/$TARBALL"
du -sh "$DIST_DIR/$TARBALL"
echo "  Contents:"
tar -tzf "$DIST_DIR/$TARBALL" | head -20
