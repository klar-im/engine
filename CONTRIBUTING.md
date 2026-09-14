# Contributing

Issues and pull requests are welcome. Two things about this repository are
unusual and worth knowing before you spend time on a change.

## It is a mirror

This repo is a one-way, curated mirror of Klar's internal monorepo, published
by a script that copies an explicit allowlist of files and runs a scrub. We do
not develop here directly. A pull request you open is reviewed here, and a
merged one is carried back into the monorepo as a patch and re-published, so
your change lands in the next sync commit rather than as your commit on `main`.
Authorship is kept in the commit message. It takes a moment; please bear with
us.

Consequences:

- `main` moves in sync commits, not in small steps. Rebase on the latest one
  before opening a PR.
- Files you do not see here (training data, the flywheel, infrastructure)
  exist and are deliberately closed. A change that needs them is a
  conversation first: open an issue.
- Tests you cannot run here (the Postfix E2E needs Docker; the Stalwart E2E
  needs docker compose and ~400 MB of model) run in CI on your PR.

## What a good change looks like

- **A fix comes with the test that goes red without it.** Every regression
  test in this tree was checked that way before it landed; a test that stays
  green when its subject is broken is worse than none.
- **Model quality is not a code change.** A message classified wrongly is a
  real report and belongs in an issue with the `.eml` (redact what you must),
  but the fix is in training, which is not here. What is here is the decision
  layer (`engine/decision_layer.h`) and the structural signals around the
  model, and a change to those needs a measurement on both sides: how many
  spams it catches and how many legitimate messages it costs.
- **Build the way CI does**: `make setup && make build && make test`, on
  Linux for the milter (`libmilter` is a Linux library; macOS builds the
  engine and the CLI only).
- **Style follows the file you are in.** C++17, no exceptions across the C
  ABI, `clang-tidy` clean (`engine/.clang-tidy` is the configuration and the
  reasons for every exclusion).

## Licence of contributions

By opening a pull request you agree that your contribution is licensed under
the AGPLv3 like the rest of the code (`LICENSE`). The model is a separate
artifact under a separate licence (`LICENSE-MODEL.md`) and is not something a
pull request can change.

## Security

Not on the tracker: see `SECURITY.md`.
