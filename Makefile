# Klar Engine — open-core build. See README.md.
.PHONY: help setup model import-deps build test import clean check-image-public

MODEL ?= icosha/spam-xlmr-v1
PYTHON ?= python3
# The production model set, verified file by file against the pinned manifest.
RELEASED_MANIFEST ?= postfix/model/released-manifest.json

help:
	@echo "make setup        # install C/C++ deps (llama.cpp, gmime, xxhash, nlohmann-json)"
	@echo "make model        # fetch the production model (pinned by $(RELEASED_MANIFEST)) into engine/model"
	@echo "make build        # build the engine + postfix milter"
	@echo "make test         # run the C ABI tests"
	@echo "make import-deps  # install Python deps for converting your own model ($(PYTHON) -m pip)"
	@echo "make import MODEL=<hf-repo>        # convert any XLM-R spam model from Hugging Face instead"

# The classifier the Klar apps ship, fetched from Klar's public bucket and
# verified against the committed manifest (the same path the milter container
# uses on first start). The model is licensed separately from the code
# (LICENSE-MODEL.md); fetch_model.sh refuses to download until
# KLAR_ACCEPT_MODEL_LICENSE=1 records that you accept it.
model:
	@KLAR_ACCEPT_MODEL_LICENSE="$${KLAR_ACCEPT_MODEL_LICENSE:-}" \
		postfix/scripts/fetch_model.sh engine/model "$(RELEASED_MANIFEST)"
	@echo "[model] done — run: make build && ./engine/build/spam_classifier ./engine/model"

setup:
	@engine/scripts/setup.sh

# Python deps for model conversion only (kept separate from the C/C++ build).
# Use a virtualenv if your distro marks the system Python externally-managed.
import-deps:
	@$(PYTHON) -m pip install -r engine/requirements-import.txt

build:
	@engine/scripts/build.sh
	@postfix/scripts/build.sh

test: build stalwart/test-unit
	cd engine && ctest --test-dir build --output-on-failure --timeout 600
	cd postfix && ctest --test-dir build --output-on-failure --timeout 120
	bash stalwart/tests/test_e2e_fixtures.sh

# Can a stranger pull the released image? TAG=v0.1.0 (default latest). ghcr
# package visibility has no API; the release job runs this after its push and
# fails the release while the package is private.
check-image-public:
	@bash postfix/scripts/check_image_public.sh $(or $(TAG),latest)

# stalwart/: the same milter behind Stalwart. `make stalwart/test-e2e` runs the
# compose stack (docker compose + network); `make stalwart/apply` wires a server.
include stalwart/Makefile

# Download an HF model and convert it into engine/model/ (encoder GGUF + head),
# for running your own XLM-R spam classifier through this engine. The
# production model is NOT this path: it is fetched pre-converted by `make model`
# (its weights are not on Hugging Face). MODEL defaults to Klar's first public
# model (icosha/spam-xlmr-v1, XLM-RoBERTa-large, CC-BY-NC-4.0), which still
# converts and runs; point it at any XLM-R spam model to convert your own.
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
