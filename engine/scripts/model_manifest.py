#!/usr/bin/env python3
"""Generate or verify engine/model/MANIFEST.json — model weight provenance.

This manifest pins SHA-256, size, and the S3-style base64 MD5 for each
production artifact. `source_model` identifies the lineage; release candidates
also bind it to their exact training-run hash. Re-import or tune the weights,
then regenerate under a new immutable model UUID. CI verifies downloaded bytes
against the committed manifest, catching a stale local set or an object-store
rewrite that bypassed review.

Usage:
    python3 engine/scripts/model_manifest.py            # regenerate MANIFEST.json
    python3 engine/scripts/model_manifest.py --check    # verify, exit 1 on drift

Covers the production artifact set (what download-models.sh distributes) plus
the FTRL baseline that ships in the app bundle. Local-only intermediates (the
f16 gguf and whichever quantization the artifact does not declare) are
deliberately excluded.
"""
from __future__ import annotations

import base64
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ENGINE_DIR = Path(__file__).resolve().parents[1]
MODEL_DIR = ENGINE_DIR / "model"
MANIFEST = MODEL_DIR / "MANIFEST.json"
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

# The one Python owner of which files make up a shipped engine artifact: the
# five head files, exactly one quantized encoder under gguf/, and the FTRL
# baseline. Which encoder is the artifact's own declaration
# (classifier_config.json `gguf_encoder_file`, written by
# engine/export_classifier_weights.py; absent means the historical default,
# so every artifact exported before 2026-09-13 reads unchanged). The C++
# engine (default_gguf_encoder_file) and the Swift ModelStore read the same
# key; model-lab/test_decision_layer_sync.py checks the three agree. Every
# other Python reader (the exporter, model-lab/scripts/model_artifacts.py and
# through it the release scripts) imports from here rather than restating it.
# infra/scripts/download-models.sh's static FILES list is the archaeology
# fallback for pre-manifest downloads and mirrors the historical default.
HEAD_FILES = (
    "classifier_config.json",
    "classifier_dense_weight.bin",
    "classifier_dense_bias.bin",
    "classifier_out_proj_weight.bin",
    "classifier_out_proj_bias.bin",
)
DEFAULT_GGUF_ENCODER_FILE = "encoder-q4_k_m.gguf"
# One path segment, the import-hf naming scheme, no traversal: the engine
# joins it under <model>/gguf/ and the manifest lists it verbatim.
GGUF_ENCODER_FILE_RE = re.compile(r"encoder-[a-z0-9_]+\.gguf")


def gguf_encoder_file(config: dict) -> str:
    """The quantized encoder this artifact ships: classifier_config.json's
    `gguf_encoder_file`, or the historical default when absent. Raises
    ValueError on a declaration outside the scheme; nothing downstream may
    substitute the default for an invalid name, since an import directory
    holds several encoders and the wrong one would measure."""
    name = config.get("gguf_encoder_file", DEFAULT_GGUF_ENCODER_FILE)
    if not isinstance(name, str) or not GGUF_ENCODER_FILE_RE.fullmatch(name):
        raise ValueError(
            f"classifier_config.json gguf_encoder_file must be a bare encoder-*.gguf name, got {name!r}"
        )
    return name


def artifacts_for(config: dict, *, include_ftrl: bool = True) -> list[str]:
    """The artifact's file list in the order every digest hashes it."""
    names = [*HEAD_FILES, f"gguf/{gguf_encoder_file(config)}"]
    if include_ftrl:
        names.append("ftrl_baseline.bin")
    return names


def shipped_gguf_entry(files) -> str | None:
    """The one `gguf/<encoder>` entry a manifest's files list, or None when it
    lists zero, several, or a name outside the scheme."""
    entries = [name for name in files if name.startswith("gguf/")]
    if len(entries) != 1 or GGUF_ENCODER_FILE_RE.fullmatch(entries[0][len("gguf/"):]) is None:
        return None
    return entries[0]


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


def build(model_dir: Path) -> dict:
    config = json.loads((model_dir / "classifier_config.json").read_text())
    files = {}
    try:
        artifacts = artifacts_for(config)
    except ValueError as error:
        sys.exit(f"[manifest] {error}")
    for rel in artifacts:
        p = model_dir / rel
        if not p.exists():
            sys.exit(f"[manifest] missing artifact: {p} — run `make engine/setup` first")
        files[rel] = digest(p)
    return {"source_model": config.get("source_model"), "files": files}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--model-dir", type=Path, default=MODEL_DIR)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--model-uuid", default="",
                        help="immutable distribution UUID to record when generating")
    args = parser.parse_args()
    model_dir = args.model_dir.resolve()
    manifest_path = args.manifest.resolve()

    if args.check:
        if not manifest_path.exists():
            print(f"[manifest] {manifest_path} missing — run `make engine/model-manifest`")
            return 1
        pinned = json.loads(manifest_path.read_text())
        actual = build(model_dir)
        drift = []
        model_uuid = pinned.get("model_uuid")
        if not isinstance(model_uuid, str) or UUID_RE.fullmatch(model_uuid) is None:
            drift.append("model_uuid")
            print(f"  [DRIFT] model_uuid: invalid or missing ({model_uuid!r})")
        if set(pinned.get("files", {})) != set(actual["files"]):
            drift.append("artifact_set")
            print(
                "  [DRIFT] artifact set: "
                f"pinned={sorted(pinned.get('files', {}))} expected={sorted(actual['files'])}"
            )
        for rel, expected in pinned.get("files", {}).items():
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

    manifest = build(model_dir)
    if args.model_uuid:
        if UUID_RE.fullmatch(args.model_uuid) is None:
            parser.error("--model-uuid must be a canonical lowercase RFC 4122 UUID")
        manifest["model_uuid"] = args.model_uuid
    elif manifest_path.exists():
        previous = json.loads(manifest_path.read_text())
        previous_uuid = previous.get("model_uuid")
        if previous_uuid:
            if not isinstance(previous_uuid, str) or UUID_RE.fullmatch(previous_uuid) is None:
                parser.error(
                    f"existing manifest has invalid model_uuid {previous_uuid!r}"
                )
            previous_content = {
                "source_model": previous.get("source_model"),
                "files": previous.get("files"),
            }
            if previous_content != manifest:
                print(
                    "[manifest] artifact bytes changed under an immutable model UUID; "
                    "rerun with --model-uuid <new-uuid>",
                    file=sys.stderr,
                )
                return 1
            manifest["model_uuid"] = previous_uuid
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"[manifest] wrote {manifest_path} ({len(manifest['files'])} artifacts, "
          f"source_model={manifest['source_model']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
