#!/bin/bash
set -e
echo "[model-check] Checking local model version..."
VERSION_FILE="/var/lib/klar/model/current/VERSION"
if [ -f "$VERSION_FILE" ]; then
    echo "Local model version: $(cat "$VERSION_FILE")"
else
    echo "No model version file found at $VERSION_FILE"
    echo "Using development model from engine/model/"
fi
echo "[model-check] Remote manifest check not implemented yet."
