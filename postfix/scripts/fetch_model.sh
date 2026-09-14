#!/bin/bash
# Fetch the released Klar model into a directory, verifying every byte against
# a pinned manifest: `fetch_model.sh <dest-dir> [manifest.json]`.
#
# The model is not in the code repository and is licensed separately from it
# (LICENSE-MODEL.md: CC-BY-NC-4.0, free for non-commercial use with attribution,
# a paid licence for commercial use). This script downloads it from Klar's
# public bucket and refuses to run until the licence has been accepted:
#
#     KLAR_ACCEPT_MODEL_LICENSE=1 postfix/scripts/fetch_model.sh /var/lib/klar/model
#
# The manifest (default: postfix/model/released-manifest.json beside this
# script's tree, the same file infra pins releases to) names the model_uuid and
# the sha256 and size of every file; a mismatch on any of them aborts and leaves
# the destination untouched. MODEL_BASE_URL overrides the bucket for a mirror.
# The manifest itself is written as <dest>/MANIFEST.json so the engine can
# report the model_uuid it loaded. Idempotent: files already present and
# matching are not downloaded again.
set -euo pipefail

DEST="${1:-}"
[ -n "$DEST" ] || { echo "usage: fetch_model.sh <dest-dir> [manifest.json]" >&2; exit 2; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${2:-$SCRIPT_DIR/../model/released-manifest.json}"
[ -f "$MANIFEST" ] || { echo "error: manifest not found: $MANIFEST" >&2; exit 2; }

if [ "${KLAR_ACCEPT_MODEL_LICENSE:-}" != "1" ]; then
    cat >&2 <<'EOF'
The Klar model is licensed separately from this code, under CC-BY-NC-4.0:
free for non-commercial use with attribution, a paid licence for commercial
use (hello@klar.im). Read LICENSE-MODEL.md, then run again with

    KLAR_ACCEPT_MODEL_LICENSE=1

set in the environment to record that you accept it.
EOF
    exit 3
fi

MODEL_UUID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["model_uuid"])' "$MANIFEST")"
BASE_URL="${MODEL_BASE_URL:-https://klar-downloads-prod.s3.fr-par.scw.cloud/models/$MODEL_UUID}"
CLIENT="klar-milterd-fetch/1"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

mkdir -p "$DEST"
echo "[fetch_model] $MODEL_UUID -> $DEST"
python3 -c 'import json,sys
for name, meta in json.load(open(sys.argv[1]))["files"].items():
    print(name, meta["sha256"], meta["size"])' "$MANIFEST" | while read -r name sha size; do
    target="$DEST/$name"
    if [ -f "$target" ] && [ "$(sha256_of "$target")" = "$sha" ]; then
        echo "  ok       $name"
        continue
    fi
    mkdir -p "$(dirname "$target")"
    echo "  fetching $name ($size bytes)"
    curl -fsSL --retry 3 -H "User-Agent: $CLIENT" -o "$target.part" "$BASE_URL/$name"
    got_size="$(wc -c < "$target.part" | tr -d ' ')"
    got_sha="$(sha256_of "$target.part")"
    if [ "$got_size" != "$size" ] || [ "$got_sha" != "$sha" ]; then
        rm -f "$target.part"
        echo "error: $name does not match the manifest (size $got_size vs $size, sha256 $got_sha vs $sha)" >&2
        exit 1
    fi
    mv "$target.part" "$target"
done
cp "$MANIFEST" "$DEST/MANIFEST.json"
echo "[fetch_model] done; model_uuid $MODEL_UUID"
