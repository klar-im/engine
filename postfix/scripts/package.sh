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

# Create dist structure
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR/model" "$DIST_DIR/etc"

# bin/: the daemon, the CLI and every library they load, staged by install.sh,
# the same tree an operator installs. One list of what the daemon loads; this
# script used to keep a second one (and flattened the soname symlink chain).
bash "$SCRIPT_DIR/install.sh" "$DIST_DIR" >/dev/null

# Model files: the head plus the one encoder the artifact declares in its own
# classifier_config.json (engine/scripts/model_manifest.py owns that list). A
# fixed Q4 name here packaged a Q8_0 artifact with no encoder at all, and the
# `-f` skip made it silent; a missing file is a broken milter, so it fails.
mkdir -p "$DIST_DIR/model/gguf"
for f in $(python3 - "$REPO_ROOT/engine/model" <<'PY'
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]).resolve().parent / "scripts"))
from model_manifest import artifacts_for
config = json.loads((Path(sys.argv[1]) / "classifier_config.json").read_text())
print("\n".join(artifacts_for(config, include_ftrl=False)))
PY
); do
    if [ ! -f "$REPO_ROOT/engine/model/$f" ]; then
        echo "error: engine/model/$f is missing; the artifact declares it" >&2
        exit 1
    fi
    cp "$REPO_ROOT/engine/model/$f" "$DIST_DIR/model/$f"
done

# Origin-IP blocklist (TASK-113): optional, and deliberately copied separately
# from the model files above — it is refreshed on its own cron cadence, not with
# a model release. Absent just means the origin-IP signal is off.
if [ -f "$REPO_ROOT/engine/model/ip_blocklist.bin" ]; then
    cp "$REPO_ROOT/engine/model/ip_blocklist.bin" "$DIST_DIR/model/"
fi

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
tar -czf "$DIST_DIR/$TARBALL" -C "$DIST_DIR" bin/ model/ etc/

# Summary
echo "[postfix/package] Done."
echo "  Tarball: $DIST_DIR/$TARBALL"
du -sh "$DIST_DIR/$TARBALL"
echo "  Contents:"
tar -tzf "$DIST_DIR/$TARBALL" | head -20
