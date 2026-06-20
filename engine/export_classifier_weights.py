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

DEFAULT_MODEL = "icosha/spam-xlmr-v1"
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "model"


def export(model_name_or_path: str, output_dir: Path) -> dict:
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
        "source_model": model_name_or_path,
        "label_map": label_map,
    }
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
    args = parser.parse_args()

    try:
        export(args.hf_repo, args.output_dir)
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
