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
    # Xcode ships clang and clangd but not clang-tidy. Homebrew LLVM supplies
    # clang-tidy + run-clang-tidy; the lint target resolves the keg-only path.
    brew list llvm >/dev/null 2>&1 || brew install llvm
    # Headers for bounded in-memory archive inspection. CMake links macOS's
    # system libarchive; the keg is intentionally not bundled into Klar.
    brew list libarchive >/dev/null 2>&1 || brew install libarchive

    # ggml >= 0.17 is REQUIRED: earlier ggml (0.12) has a Metal residency-set
    # bug that aborts (`GGML_ASSERT([rsets->data count] == 0)`) when some models
    # are unloaded — the engine reloads models (SpamTrainer / SpamEngineClient),
    # so this crashed a Gen-3 (e5) reload. `brew install` above is a no-op on an
    # already-installed old version, so ensure the minimum explicitly. (TASK-367)
    GGML_MIN="0.17.0"
    GGML_VER="$(brew list --versions ggml 2>/dev/null | awk '{print $2}')"
    if [ -z "$GGML_VER" ] || \
       [ "$(printf '%s\n%s\n' "$GGML_MIN" "$GGML_VER" | sort -V | head -1)" != "$GGML_MIN" ]; then
        echo "[setup] ggml ${GGML_VER:-none} < $GGML_MIN; upgrading ggml + llama.cpp (Metal unload fix)..."
        brew upgrade ggml llama.cpp 2>/dev/null || brew install ggml llama.cpp
    fi
elif [ -n "${KLAR_SKIP_APT:-}" ]; then
    # A container build installs these in its own layer, as root, without sudo
    # (postfix/docker/Dockerfile); the setup then only has llama.cpp and the
    # cmake configure left to do.
    echo "[setup] KLAR_SKIP_APT set; assuming build-essential, cmake, pkg-config, gmime, archive, json, xxhash are present"
else
    echo "[setup] Installing system dependencies (apt)..."
    sudo apt-get install -y \
        build-essential \
        cmake \
        clang-tidy \
        pkg-config \
        libgmime-3.0-dev \
        libarchive-dev \
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

        # An overlayfs container build (podman 3.4) refuses tar's final chmod of
        # extracted symlinks and directories with "Cannot change mode", after
        # every file is already in place. That one message is tolerated; any
        # other tar error (a truncated download, a changed archive layout) is
        # still fatal, and curl -f turns a 404 body into a failure instead of
        # an archive that is not one.
        extract() {  # extract <url> <tar args...>: tar's own errors, minus the chmod one
            local url="$1" err; shift
            err="$(mktemp)"
            if ! curl -fsSL "$url" | tar -xz --no-same-permissions "$@" 2>"$err"; then
                if ! bash "$SCRIPT_DIR/tar_chmod_only.sh" "$err"; then
                    cat "$err" >&2; rm -f "$err"
                    echo "error: extracting $url failed" >&2; exit 1
                fi
                echo "[setup] tar could not chmod on this filesystem (overlayfs); files are in place"
            fi
            rm -f "$err"
        }

        # .so files from the pre-built release (~30MB)
        extract "https://github.com/ggml-org/llama.cpp/releases/download/$LLAMA_PIN/llama-$LLAMA_PIN-bin-ubuntu-x64.tar.gz" \
            -C "$LLAMA_INSTALL/lib" --strip-components=1 --wildcards "*/lib*.so*"
        # Every library the engine links (llama.pc below: ggml, ggml-base,
        # llama) plus at least one CPU backend plugin, which ggml loads at
        # runtime by name.
        for lib in libllama.so libggml.so libggml-base.so; do
            [ -f "$LLAMA_INSTALL/lib/$lib" ] \
                || { echo "error: llama.cpp $LLAMA_PIN: $lib did not extract into $LLAMA_INSTALL/lib" >&2; exit 1; }
        done
        ls "$LLAMA_INSTALL"/lib/libggml-cpu*.so >/dev/null 2>&1 \
            || { echo "error: llama.cpp $LLAMA_PIN: no libggml-cpu-*.so plugin extracted into $LLAMA_INSTALL/lib" >&2; exit 1; }

        # Headers: stream the source archive, extract the include dirs only
        extract "https://github.com/ggml-org/llama.cpp/archive/refs/tags/$LLAMA_PIN.tar.gz" \
            -C /tmp "llama.cpp-$LLAMA_PIN/include" "llama.cpp-$LLAMA_PIN/ggml/include"
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

# A BUILD DIRECTORY OUTLIVES THE TOOLCHAIN IT WAS CONFIGURED AGAINST, AND
# CMAKE DOES NOT NOTICE. On 2026-09-13 a `brew upgrade` on the shared runner
# moved llama.cpp, ggml and glib to new Cellar paths at 14:07; the gate at
# 14:09 still "built" and then every classify returned null embeddings, and a
# worktree configured before the upgrade could not compile (`glib.h` not
# found: the pkg-config imported target kept glib 2.88.1's path in the
# cache). Reconfiguring on top of the cache reproduces the stale paths, so
# the only recovery is a fresh build directory. The stamp below is the brew
# versions this build was configured against; when they change, build/ goes.
if [[ "$OSTYPE" == darwin* ]]; then
    STAMP_FILE="$ENGINE_DIR/build/.brew-toolchain"
    STAMP="$(brew list --versions llama.cpp ggml gmime glib nlohmann-json xxhash libarchive 2>/dev/null | sort)"
    if [ -d "$ENGINE_DIR/build" ] && [ "$(cat "$STAMP_FILE" 2>/dev/null)" != "$STAMP" ]; then
        echo "[setup] Homebrew toolchain changed since build/ was configured; starting it fresh."
        rm -rf "$ENGINE_DIR/build"
    fi
    mkdir -p "$ENGINE_DIR/build"
    printf '%s\n' "$STAMP" > "$STAMP_FILE"
fi

CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON)
if [[ "$OSTYPE" == darwin* ]]; then
    # AppleClang discovers the SDK implicitly, but Homebrew clang-tidy does not.
    # Record it in compile_commands.json so both tools parse the same command.
    if [ -z "${SDKROOT:-}" ] && [ -d /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk ]; then
        SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
    fi
    CMAKE_ARGS+=(-DCMAKE_OSX_DEPLOYMENT_TARGET="$OSX_DEPLOYMENT_TARGET")
    if [ -n "${SDKROOT:-}" ]; then
        CMAKE_ARGS+=(-DCMAKE_OSX_SYSROOT="$SDKROOT")
    fi
else
    CMAKE_ARGS+=(-DLLAMA_INSTALL="$LLAMA_INSTALL")
fi

cmake -S "$ENGINE_DIR" -B "$ENGINE_DIR/build" "${CMAKE_ARGS[@]}"

echo "[setup] Done. Run 'make engine/build' to compile."
