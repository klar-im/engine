# Security

klar-milterd and the engine parse untrusted mail in-process on your server.
If you find a way to crash them, make them misclassify on purpose in a way
that reads as a defect rather than a model limitation, escape the milter's
process, or read anything a message should not give access to, we want to
hear about it before anyone else does.

Write to **security@klar.im**. Say what you found, how to reproduce it, and
which version (`klar-milterd --version`, or the image tag). You will get an
acknowledgement within three working days and a fix or a reasoned answer
within thirty. We credit reporters in the release notes unless you ask us
not to.

Please do not open a public issue for a vulnerability. Everything else (a
false positive, a build failure, a question) is a normal issue on the tracker.

## Scope

- This repository: the engine (`engine/`), the milter (`postfix/`), and the
  Stalwart wiring (`stalwart/`).
- The container image `ghcr.io/klar-im/klar-milterd`.
- The model files fetched by `postfix/scripts/fetch_model.sh` (integrity, not
  classifier accuracy: a spam that gets through is a report for the issue
  tracker, a way to make every spam get through is a report for this address).

Out of scope: klar.im itself, the Apple apps, and any server you run this on
(report those to their operators).

## Two things to know before deploying

- The engine reads `Authentication-Results`; it does not verify DKIM or DMARC.
  Behind an MTA that hands the milter the client's own bytes (Stalwart), set
  `auth_results = "ignore"` or a forged header is believed. `postfix/README.md`
  and `stalwart/README.md` say when each setting is right.
- `/metrics`, `/livez` and `/readyz` are unauthenticated. The daemon refuses to
  bind them on all interfaces unless `health_allow_public = true`; keep them on
  loopback or behind your own auth.
