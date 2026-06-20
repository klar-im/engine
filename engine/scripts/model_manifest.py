#!/usr/bin/env python3
"""Generate or verify engine/model/MANIFEST.json — model weight provenance.

The initial weights come from a partner model (classifier_config.json's
source_model) and the training run is not ours to reproduce, but every change
to the shipped artifacts IS trackable: this manifest pins sha256 + size + the
S3-style base64 MD5 (the same value download-models.sh stores in its .md5
sidecars) for each production weight file, and is committed to git. Re-import
or tune the weights → regenerate → the diff shows exactly which artifacts
changed and when. CI verifies the downloaded canonical weights against the
committed manifest, which also catches an S3 re-upload that bypassed a PR.

Usage:
    python3 engine/scripts/model_manifest.py            # regenerate MANIFEST.json
    python3 engine/scripts/model_manifest.py --check    # verify, exit 1 on drift

Covers the production artifact set (what download-models.sh distributes) plus
the FTRL baseline that ships in the app bundle. Local-only intermediates
(encoder-f16/q8_0 gguf) are deliberately excluded.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

ENGINE_DIR = Path(__file__).resolve().parents[1]
MODEL_DIR = ENGINE_DIR / "model"
MANIFEST = MODEL_DIR / "MANIFEST.json"

# Keep in sync with FILES in infra/scripts/download-models.sh (+ ftrl_baseline,
# which ships in the app bundle rather than via the model download).
ARTIFACTS = [
    "classifier_dense_weight.bin",
    "classifier_dense_bias.bin",
    "classifier_out_proj_weight.bin",
    "classifier_out_proj_bias.bin",
    "classifier_config.json",
    "gguf/encoder-q4_k_m.gguf",
    "ftrl_baseline.bin",
]


def digest(path: Path) -> dict:
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            sha.update(chunk)
            md5.update(chunk)
    return {
        "sha256": sha.hexdigest(),
        "md5_b64": base64.b64encode(md5.digest()).decode(),  # download-models.sh format
        "size": path.stat().st_size,
    }


def build() -> dict:
    config = json.loads((MODEL_DIR / "classifier_config.json").read_text())
    files = {}
    for rel in ARTIFACTS:
        p = MODEL_DIR / rel
        if not p.exists():
            sys.exit(f"[manifest] missing artifact: {p} — run `make engine/setup` first")
        files[rel] = digest(p)
    return {"source_model": config.get("source_model"), "files": files}


def main() -> int:
    if "--check" in sys.argv[1:]:
        if not MANIFEST.exists():
            print(f"[manifest] {MANIFEST} missing — run `make engine/model-manifest`")
            return 1
        pinned = json.loads(MANIFEST.read_text())
        actual = build()
        drift = []
        for rel, expected in pinned["files"].items():
            got = actual["files"].get(rel)
            status = "ok" if got == expected else "DRIFT"
            if got != expected:
                drift.append(rel)
            print(f"  [{status}] {rel}  sha256={ (got or expected)['sha256'][:16] }…")
        if pinned.get("source_model") != actual.get("source_model"):
            drift.append("source_model")
            print(f"  [DRIFT] source_model: pinned={pinned.get('source_model')} "
                  f"actual={actual.get('source_model')}")
        if drift:
            print(f"[manifest] DRIFT in {drift} — weights on disk differ from the "
                  f"committed manifest. If intentional (re-import/tune), regenerate "
                  f"with `make engine/model-manifest` and commit the diff.")
            return 1
        print(f"[manifest] all {len(pinned['files'])} artifacts match "
              f"(source_model={pinned.get('source_model')})")
        return 0

    manifest = build()
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"[manifest] wrote {MANIFEST} ({len(manifest['files'])} artifacts, "
          f"source_model={manifest['source_model']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
