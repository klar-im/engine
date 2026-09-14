#!/usr/bin/env python3
"""Regression tests for immutable model-manifest UUID handling."""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE / "model_manifest.py"
ARTIFACTS = (
    "classifier_dense_weight.bin",
    "classifier_dense_bias.bin",
    "classifier_out_proj_weight.bin",
    "classifier_out_proj_bias.bin",
    "ftrl_baseline.bin",
)
FIRST_UUID = "11111111-1111-4111-8111-111111111111"
SECOND_UUID = "22222222-2222-4222-8222-222222222222"


def run(model: Path, manifest: Path, uuid: str = "") -> subprocess.CompletedProcess:
    command = [
        "python3", str(TOOL), "--model-dir", str(model),
        "--manifest", str(manifest),
    ]
    if uuid:
        command.extend(("--model-uuid", uuid))
    return subprocess.run(command, text=True, capture_output=True)


def fixture(root: Path) -> tuple[Path, Path]:
    model = root / "model"
    (model / "gguf").mkdir(parents=True)
    for name in ARTIFACTS:
        (model / name).write_bytes(name.encode())
    (model / "classifier_config.json").write_text(
        json.dumps({
            "hidden_size": 1,
            "input_format": "raw",
            "num_labels": 4,
            "source_model": "fixture",
        }) + "\n"
    )
    (model / "gguf/encoder-q4_k_m.gguf").write_bytes(b"encoder")
    return model, root / "MANIFEST.json"


def main() -> int:
    with tempfile.TemporaryDirectory() as temp:
        model, manifest = fixture(Path(temp))
        first = run(model, manifest, FIRST_UUID)
        assert first.returncode == 0, first.stderr

        unchanged = run(model, manifest)
        assert unchanged.returncode == 0, unchanged.stderr
        assert json.loads(manifest.read_text())["model_uuid"] == FIRST_UUID

        (model / "classifier_dense_bias.bin").write_bytes(b"changed")
        drift = run(model, manifest)
        assert drift.returncode != 0
        assert "new-uuid" in drift.stderr
        assert json.loads(manifest.read_text())["model_uuid"] == FIRST_UUID

        replacement = run(model, manifest, SECOND_UUID)
        assert replacement.returncode == 0, replacement.stderr
        assert json.loads(manifest.read_text())["model_uuid"] == SECOND_UUID

        invalid = run(model, manifest, "not-a-uuid")
        assert invalid.returncode != 0

    # An artifact that declares which quantized encoder it ships lists that
    # file, and only that file, in the manifest; a declaration that is not a
    # bare encoder-*.gguf name is refused before anything is hashed.
    with tempfile.TemporaryDirectory() as temp:
        model, manifest = fixture(Path(temp))
        config = json.loads((model / "classifier_config.json").read_text())
        config["gguf_encoder_file"] = "encoder-q8_0.gguf"
        (model / "classifier_config.json").write_text(json.dumps(config) + "\n")
        missing = run(model, manifest, FIRST_UUID)
        assert missing.returncode != 0 and "encoder-q8_0.gguf" in missing.stderr, missing.stderr
        (model / "gguf/encoder-q8_0.gguf").write_bytes(b"encoder8")
        declared = run(model, manifest, FIRST_UUID)
        assert declared.returncode == 0, declared.stderr
        files = json.loads(manifest.read_text())["files"]
        assert "gguf/encoder-q8_0.gguf" in files and "gguf/encoder-q4_k_m.gguf" not in files
        check = subprocess.run(
            ["python3", str(TOOL), "--check", "--model-dir", str(model), "--manifest", str(manifest)],
            text=True, capture_output=True,
        )
        assert check.returncode == 0, check.stdout + check.stderr
        config["gguf_encoder_file"] = "../encoder-q8_0.gguf"
        (model / "classifier_config.json").write_text(json.dumps(config) + "\n")
        refused = run(model, manifest, SECOND_UUID)
        assert refused.returncode != 0 and "bare encoder-*.gguf" in refused.stderr, refused.stderr

    print("[test-model-manifest] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
