#!/bin/bash
# Container entrypoint: make sure a model is present, then run the daemon.
#
# The image ships no weights (see Dockerfile). The model lives where the daemon's
# own config says (`model_dir` in the toml passed as --config, default
# /var/lib/klar/model on the volume), read from the same file so the fetch and
# the daemon cannot disagree about the directory. A first start fetches it,
# verified against the pinned manifest, and only with KLAR_ACCEPT_MODEL_LICENSE=1.
# A directory that already holds a MANIFEST.json is used as is, so a
# pre-populated volume or a read-only bind mount of your own converted model
# needs no network and no licence flag.
set -euo pipefail

CONFIG=/etc/klar/klar-milterd.toml
prev=""
for arg in "$@"; do
    [ "$prev" = "--config" ] && CONFIG="$arg"
    prev="$arg"
done
MODEL_DIR="$(sed -n 's/^model_dir *= *"\([^"]*\)".*/\1/p' "$CONFIG" | head -1)"
MODEL_DIR="${MODEL_DIR:-/var/lib/klar/model}"

if [ ! -f "$MODEL_DIR/MANIFEST.json" ]; then
    /opt/klar/fetch_model.sh "$MODEL_DIR" /opt/klar/released-manifest.json
fi
exec /opt/klar/bin/klar-milterd "$@"
