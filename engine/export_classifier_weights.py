#!/usr/bin/env python3
"""
Export the classifier head weights from a HuggingFace model into the
raw float32 binary format the C++ engine reads.

Used by `make engine/import-hf MODEL=<repo>` to extract the head from a
freshly downloaded HF model. See docs/MODEL_UPGRADE.md for the full
upgrade procedure and the conversion-parity contract.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from transformers import AutoModelForSequenceClassification

sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))
from model_manifest import DEFAULT_GGUF_ENCODER_FILE, GGUF_ENCODER_FILE_RE

DEFAULT_MODEL = "icosha/spam-xlmr-v1"
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "model"


def export(
    model_name_or_path: str,
    output_dir: Path,
    source_model: str | None = None,
    input_format: str = "legacy_wrapped",
    structural_markers: bool = False,
    attachment_context: bool = False,
    spam_side_calibration_knot: float | None = None,
    gguf_encoder_file: str | None = None,
) -> dict:
    if gguf_encoder_file is not None and not GGUF_ENCODER_FILE_RE.fullmatch(gguf_encoder_file):
        raise ValueError(
            "gguf_encoder_file must be a bare gguf filename under gguf/, "
            f"like encoder-q8_0.gguf; got {gguf_encoder_file!r}"
        )
    print(f"Loading model: {model_name_or_path}")
    model = AutoModelForSequenceClassification.from_pretrained(model_name_or_path)
    classifier = model.classifier

    # XLM-RoBERTa classifier structure:
    #   classifier.dense    (Linear: hidden_size -> hidden_size)
    #   classifier.out_proj (Linear: hidden_size -> num_labels)
    # PyTorch nn.Linear stores weight as [out_features, in_features].
    # tofile() writes in row-major order; the C++ TrainableClassifierHead
    # reads it as weight[i * in_features + j] which matches.
    dense_weight = classifier.dense.weight.detach().numpy().astype(np.float32)
    dense_bias = classifier.dense.bias.detach().numpy().astype(np.float32)
    out_proj_weight = classifier.out_proj.weight.detach().numpy().astype(np.float32)
    out_proj_bias = classifier.out_proj.bias.detach().numpy().astype(np.float32)

    print(f"  Dense weight shape:    {dense_weight.shape}")
    print(f"  Dense bias shape:      {dense_bias.shape}")
    print(f"  Out proj weight shape: {out_proj_weight.shape}")
    print(f"  Out proj bias shape:   {out_proj_bias.shape}")

    output_dir.mkdir(parents=True, exist_ok=True)
    dense_weight.tofile(output_dir / "classifier_dense_weight.bin")
    dense_bias.tofile(output_dir / "classifier_dense_bias.bin")
    out_proj_weight.tofile(output_dir / "classifier_out_proj_weight.bin")
    out_proj_bias.tofile(output_dir / "classifier_out_proj_bias.bin")

    # Pull the label map from the HF model config when available so we
    # don't hardcode "gibberish/marketing/regular/spam" — a future model
    # might use different labels.
    id2label = getattr(model.config, "id2label", None) or {
        0: "gibberish", 1: "marketing", 2: "regular", 3: "spam",
    }
    label_map = {str(k): v for k, v in sorted(id2label.items())}

    metadata = {
        "hidden_size": int(dense_weight.shape[0]),
        "num_labels": int(out_proj_weight.shape[0]),
        "source_model": source_model or model_name_or_path,
        "input_format": input_format,
        "structural_markers": structural_markers,
        "attachment_context": attachment_context,
        "label_map": label_map,
    }
    # Where this artifact's spam side sits, so the engine maps it onto the fixed
    # Standard gate instead of moving the gate and disarming every
    # condemn-capable offset. Omitted entirely when the artifact is already on
    # the product's scale, because the engine reads absent as the identity and
    # writing 0.99 explicitly would only invite someone to "adjust" it. The value
    # comes from select_operating_point.py, never from a hand-tuned guess.
    if spam_side_calibration_knot is not None:
        if not 0.0 < spam_side_calibration_knot < 1.0:
            raise ValueError(
                "spam_side_calibration_knot must be strictly between 0 and 1"
            )
        metadata["spam_side_calibration_knot"] = float(spam_side_calibration_knot)
    # Which quantization of the encoder this artifact ships. The engine, the
    # manifest, the Swift ModelStore and the release compiler all read this
    # key; absent means the historical default (model_manifest.py's
    # DEFAULT_GGUF_ENCODER_FILE, encoder-q4_k_m.gguf), so every artifact
    # exported before 2026-09-13 keeps loading unchanged. The
    # quantization is a candidate-level choice because it is a measured one:
    # gen3-v6's head flips a confident probe at Q4_K_M and agrees with the HF
    # reference at Q8_0 (TRAINING_EXPERIMENT_LOG.md #48).
    if gguf_encoder_file is not None:
        metadata["gguf_encoder_file"] = gguf_encoder_file
    with open(output_dir / "classifier_config.json", "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"Classifier weights saved to {output_dir}/")
    print(f"  Hidden size: {metadata['hidden_size']}, Num labels: {metadata['num_labels']}")
    print(f"  Labels: {label_map}")
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hf-repo", default=DEFAULT_MODEL,
                        help="HuggingFace repo (or local path) for the model to export")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                        help="Where to write classifier_*.bin and classifier_config.json")
    parser.add_argument("--source-model",
                        help="stable provenance id written to classifier_config.json; "
                             "defaults to --hf-repo")
    parser.add_argument("--input-format", choices=("legacy_wrapped", "raw"),
                        default="legacy_wrapped",
                        help="exact text representation used during training")
    parser.add_argument("--structural-markers", action="store_true",
                        help="prepend the structural marker summary at inference")
    parser.add_argument("--attachment-context", action="store_true",
                        help="prepend bounded C++ attachment context at inference")
    parser.add_argument("--spam-side-calibration-knot", type=float, default=None,
                        help="the selected operating point on THIS artifact's spam "
                             "side; the engine maps it onto the product's Standard "
                             "gate. Omit when the artifact needs no calibration.")
    parser.add_argument("--gguf-encoder-file", default=None,
                        help="which quantized encoder this artifact ships, e.g. "
                             f"encoder-q8_0.gguf; omitted = the historical "
                             f"{DEFAULT_GGUF_ENCODER_FILE} default")
    args = parser.parse_args()

    try:
        export(
            args.hf_repo,
            args.output_dir,
            source_model=args.source_model,
            input_format=args.input_format,
            structural_markers=args.structural_markers,
            attachment_context=args.attachment_context,
            spam_side_calibration_knot=args.spam_side_calibration_knot,
            gguf_encoder_file=args.gguf_encoder_file,
        )
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
