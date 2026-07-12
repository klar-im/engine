#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$ENGINE_DIR")"
OSX_DEPLOYMENT_TARGET="${OSX_DEPLOYMENT_TARGET:-12.0}"

# =============================================================================
# System dependencies
# =============================================================================

if [[ "$OSTYPE" == darwin* ]]; then
    echo "[setup] Checking Homebrew dependencies..."

    if ! command -v brew >/dev/null 2>&1; then
        echo "Error: Homebrew is required." >&2
        exit 1
    fi

    brew list gmime >/dev/null 2>&1 || brew install gmime
    brew list xxhash >/dev/null 2>&1 || brew install xxhash
    brew list llama.cpp >/dev/null 2>&1 || brew install llama.cpp
    brew list nlohmann-json >/dev/null 2>&1 || brew install nlohmann-json
else
    echo "[setup] Installing system dependencies (apt)..."
    sudo apt-get install -y \
        build-essential \
        cmake \
        pkg-config \
        libgmime-3.0-dev \
        nlohmann-json3-dev \
        libxxhash-dev
fi

# =============================================================================
# llama.cpp (Linux only — macOS uses brew above)
# =============================================================================

if [[ "$OSTYPE" != darwin* ]]; then
    LLAMA_PIN="b8660"
    LLAMA_INSTALL="$ENGINE_DIR/deps/llama-install"

    if [ ! -f "$LLAMA_INSTALL/lib/libllama.so" ]; then
        echo "[setup] Installing llama.cpp $LLAMA_PIN (Linux)..."
        mkdir -p "$LLAMA_INSTALL/lib/pkgconfig" "$LLAMA_INSTALL/include"

        # .so files from pre-built release (~30MB)
        curl -sL "https://github.com/ggml-org/llama.cpp/releases/download/$LLAMA_PIN/llama-$LLAMA_PIN-bin-ubuntu-x64.tar.gz" \
            | tar -xz -C "$LLAMA_INSTALL/lib" --strip-components=1 --wildcards "*/lib*.so*"

        # Headers: stream source archive, extract include dirs only
        curl -sL "https://github.com/ggml-org/llama.cpp/archive/refs/tags/$LLAMA_PIN.tar.gz" \
            | tar -xz -C /tmp "llama.cpp-$LLAMA_PIN/include" "llama.cpp-$LLAMA_PIN/ggml/include"
        cp -r "/tmp/llama.cpp-$LLAMA_PIN/include/." "$LLAMA_INSTALL/include/"
        cp -r "/tmp/llama.cpp-$LLAMA_PIN/ggml/include/." "$LLAMA_INSTALL/include/"
        rm -rf "/tmp/llama.cpp-$LLAMA_PIN"

        # pkg-config files (mirrors brew format)
        VERSION="${LLAMA_PIN#b}"
        cat > "$LLAMA_INSTALL/lib/pkgconfig/llama.pc" <<EOF
prefix=$LLAMA_INSTALL
libdir=\${prefix}/lib
includedir=\${prefix}/include
Name: llama
Version: 0.0.$VERSION
Libs: -L\${libdir} -lggml -lggml-base -lllama
Cflags: -I\${includedir}
EOF
        cat > "$LLAMA_INSTALL/lib/pkgconfig/ggml.pc" <<EOF
prefix=$LLAMA_INSTALL
libdir=\${prefix}/lib
includedir=\${prefix}/include
Name: ggml
Version: 0.0.$VERSION
Libs: -L\${libdir} -lggml
Cflags: -I\${includedir}
EOF
        echo "[setup] llama.cpp installed to $LLAMA_INSTALL"
    else
        echo "[setup] llama.cpp already installed ($LLAMA_INSTALL)"
    fi
fi

# =============================================================================
# Models
# =============================================================================

echo "[setup] Downloading models..."
# infra/scripts/download-models.sh fetches the canonical (closed) weights and is
# NOT part of the open-core publish set. In the public repo it is absent, so we
# skip it: open-core builds get a model via `make import` instead.
if [ -x "$REPO_ROOT/infra/scripts/download-models.sh" ]; then
    "$REPO_ROOT/infra/scripts/download-models.sh" "$ENGINE_DIR/model"
else
    echo "[setup] download-models.sh absent (open-core build); skipping canonical weights. Run 'make import' to fetch the model."
fi

# =============================================================================
# Configure CMake
# =============================================================================

echo "[setup] Configuring CMake..."

CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release)
if [[ "$OSTYPE" == darwin* ]]; then
    CMAKE_ARGS+=(-DCMAKE_OSX_DEPLOYMENT_TARGET="$OSX_DEPLOYMENT_TARGET")
else
    CMAKE_ARGS+=(-DLLAMA_INSTALL="$LLAMA_INSTALL")
fi

cmake -S "$ENGINE_DIR" -B "$ENGINE_DIR/build" "${CMAKE_ARGS[@]}"

echo "[setup] Done. Run 'make engine/build' to compile."
