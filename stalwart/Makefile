STALWART_DIR := $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))

.PHONY: stalwart/setup stalwart/build stalwart/test stalwart/test-unit stalwart/test-e2e stalwart/apply stalwart/up stalwart/down

# Nothing to install: apply.py and sieve_activate.py are stdlib Python, the
# daemon is postfix/'s. The compose stack needs docker (or podman) compose.
stalwart/setup:
	@command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
	@echo "[stalwart/setup] nothing to install; the milter builds via make postfix/build"

# The milter is the deliverable and postfix/ owns its build. The script, not
# `make postfix/build`: this Makefile is included by both the monorepo and the
# public klar-im/engine Makefile, and only the former has postfix/Makefile.
stalwart/build:
	@bash $(STALWART_DIR)/../postfix/scripts/build.sh

stalwart/test: stalwart/test-unit stalwart/test-e2e

# apply.py against a fake stalwart-cli: converges, idempotent, shadow on/off;
# sieve_activate.py against a fake JMAP session. Milliseconds, no network.
stalwart/test-unit:
	@python3 $(STALWART_DIR)/tests/test_apply.py
	@python3 $(STALWART_DIR)/tests/test_sieve_activate.py

# The compose stack, both modes, real SMTP and JMAP. Skips (exit 0, says so)
# where no container runtime works; the public CI runs it for real.
stalwart/test-e2e:
	@bash $(STALWART_DIR)/scripts/test_e2e.sh

# Wire a Stalwart you administer. STALWART_URL/USER/PASSWORD as for stalwart-cli;
# ARGS="--shadow" for the comparison window, "--dry-run" to see the plan.
stalwart/apply:
	@python3 $(STALWART_DIR)/scripts/apply.py $(ARGS)

stalwart/up:
	@KLAR_ACCEPT_MODEL_LICENSE=1 docker compose -f $(STALWART_DIR)/docker-compose.yml up -d --build

stalwart/down:
	@docker compose -f $(STALWART_DIR)/docker-compose.yml down -v
