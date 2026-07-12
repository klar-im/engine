# Klar Engine — open-core build. See README.md.
.PHONY: help setup import-deps build test import clean

MODEL ?= icosha/spam-xlmr-v1
PYTHON ?= python3

help:
	@echo "make setup        # install C/C++ deps (llama.cpp, gmime, xxhash, nlohmann-json)"
	@echo "make import-deps  # install Python deps for import ($(PYTHON) -m pip)"
	@echo "make import       # download + convert the model ($(MODEL)) into engine/model"
	@echo "make build        # build the engine + postfix milter"
	@echo "make test         # run the C ABI tests"
	@echo "make import MODEL=<hf-repo>        # convert any XLM-R spam model"

setup:
	@engine/scripts/setup.sh

# Python deps for model conversion only (kept separate from the C/C++ build).
# Use a virtualenv if your distro marks the system Python externally-managed.
import-deps:
	@$(PYTHON) -m pip install -r engine/requirements-demo.txt

build:
	@engine/scripts/build.sh
	@postfix/scripts/build.sh

test: build
	cd engine && ctest --test-dir build --output-on-failure --timeout 600
	cd postfix && ctest --test-dir build --output-on-failure --timeout 120

# Download an HF model and convert it into engine/model/ (encoder GGUF + head).
# Defaults to the public production model (icosha/spam-xlmr-v1, CC-BY-NC-4.0) so
# the repo runs out of the box at real quality. Point MODEL= at the toy demo
# (icosha/klar-spam-demo) for a lighter smoke-test download.
# Requires `make import-deps` (Python) and the llama.cpp converter (from `make setup`).
import: import-deps
	@command -v convert_hf_to_gguf.py >/dev/null 2>&1 || { \
		echo "Error: convert_hf_to_gguf.py not found. It ships with llama.cpp"; \
		echo "  (brew install llama.cpp puts it on PATH; on Linux get it from the"; \
		echo "   llama.cpp source tree and add it to PATH)."; exit 1; }
	@echo "[import] $(MODEL) -> engine/model/"
	mkdir -p engine/model/gguf
	cd engine && $(PYTHON) $$(command -v convert_hf_to_gguf.py) \
		$$($(PYTHON) -c "from huggingface_hub import snapshot_download; print(snapshot_download('$(MODEL)'))") \
		--outfile model/gguf/encoder-f16.gguf --outtype f16
	llama-quantize engine/model/gguf/encoder-f16.gguf engine/model/gguf/encoder-q4_k_m.gguf Q4_K_M
	cd engine && $(PYTHON) export_classifier_weights.py --hf-repo $(MODEL) --output-dir model
	@echo "[import] done — run: make build && ./engine/build/spam_classifier ./engine/model"

clean:
	rm -rf engine/build postfix/build
