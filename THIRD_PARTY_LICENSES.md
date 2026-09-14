# Third-party licences

What the engine and the milter link against, under which licence, and why each
is compatible with distributing this code under the AGPLv3. Nothing here is
vendored: every library is installed from the distribution or, for llama.cpp,
downloaded as upstream's own release by `engine/scripts/setup.sh` at the pin
named there. The distinction matters for the Sendmail licence below.

| Library | Used by | Licence | Compatibility with AGPLv3 |
|---|---|---|---|
| [llama.cpp / ggml](https://github.com/ggml-org/llama.cpp) | engine (the encoder) | MIT | Permissive; MIT code may be combined with AGPL code. |
| [GMime 3](https://github.com/jstedfast/gmime) | engine (MIME parsing), spamd | LGPL-2.1-or-later | Dynamically linked; the LGPL permits linking from any licence, and the AGPL is GPL-compatible on top of that. |
| [xxHash](https://github.com/Cyan4973/xxHash) | engine (feature hashing) | BSD-2-Clause | Permissive. |
| [nlohmann/json](https://github.com/nlohmann/json) | engine (manifests, config) | MIT | Permissive. |
| [libarchive](https://www.libarchive.org) | engine (attachment features), optional | BSD-2-Clause | Permissive. |
| [SQLite](https://sqlite.org) | milter (event store) | Public domain | No conditions. |
| [libmilter](https://www.proofpoint.com/us/products/email-protection/open-source-email-solution) | milter (`klar-milterd` only) | Sendmail License | See below. |

## libmilter and the Sendmail License

libmilter is part of the sendmail distribution and carries the Sendmail
License, which is not on the FSF's list of GPL-compatible licences: it adds a
condition (redistributions must qualify as "freeware" or "Open Source
Software", at no charge or with a three-year source offer) that the GPL family
does not, and a licence with extra conditions cannot be *merged* with GPL code
into one work under one licence.

That is not what happens here, and this is the verdict the milter rests on:

- **We do not distribute libmilter.** No sendmail source or binary is in this
  repository or in the container image's build stage; the image installs
  Debian's `libmilter1.0.1` package at build time, unmodified, and Debian
  distributes it in `main` under that licence. Our code links against it as a
  system library.
- **The AGPL's system-library exception covers this shape.** AGPLv3 section 1
  excludes from the "Corresponding Source" a "System Library" that is "included
  in the normal form of packaging a Major Component" and "serves only to enable
  use of the work with that Major Component", and libmilter is the interface
  library a Linux distribution ships for talking to a milter-capable MTA.
- **Precedent.** `spamass-milter` (GPLv2) and `milter-greylist` (BSD) have
  linked libmilter from Debian `main` for two decades under the same reading.
- **Where it stops.** Shipping a statically linked `klar-milterd`, or bundling
  libmilter's source or `.so` inside a release artifact, would make the extra
  conditions ours to meet. `postfix/scripts/install.sh` and the Dockerfile
  therefore copy only our libraries and llama.cpp's; libmilter stays the
  distribution's package. Keep it that way.

`klar-policy-cli`, `spam_classifier` and the engine library itself do not link
libmilter at all.

## The model

The model weights (`icosha/spam-xlmr-v1`) are not code and not covered by the
AGPLv3: `LICENSE-MODEL.md` (CC-BY-NC-4.0). They are never inside a release
artifact; `postfix/scripts/fetch_model.sh` downloads them after the licence is
accepted.
