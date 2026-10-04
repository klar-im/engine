#!/bin/bash
# Build the release tarball the one-line installer (engine/publish/install.sh,
# install.sh at the public repo root) unpacks into /opt/klar:
#
#     klar-milterd-<version>-linux-<x86_64|arm64>.tar.gz  (+ .sha256)
#       bin/    klar-milterd, klar-policy-cli and every shared library they load
#               outside glibc, so it runs on any distro with the builder's glibc
#               or newer (the release CI builds x86_64 on ubuntu-22.04, glibc
#               2.35, and arm64 on ubuntu-24.04, glibc 2.39: ci.yml says why)
#       share/  fetch_model.sh + the pinned manifest, the systemd unit, the
#               Postfix config/snippet/Sieve, the Stalwart config, Sieve and
#               scripts, the licences
#
# NO model weights, on purpose: the model is CC-BY-NC-4.0 (LICENSE-MODEL.md)
# and is fetched at install time, sha256-verified, only once the operator has
# accepted that licence. A tarball carrying it would redistribute it.
#
# Run after `make build` (public repo) or `make postfix/build`, on Linux.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POSTFIX_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$POSTFIX_DIR")"
DIST_DIR="$POSTFIX_DIR/dist"
STAGE="$DIST_DIR/stage"
VERSION="${KLAR_VERSION:-$(git -C "$REPO_ROOT" describe --tags --always 2>/dev/null || echo dev)}"
case "$(uname -m)" in
    x86_64)        ARCH=x86_64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "error: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
[ "$(uname -s)" = Linux ] || { echo "error: the release tarball is Linux-only" >&2; exit 1; }

echo "[postfix/package] klar-milterd $VERSION for linux-$ARCH"
rm -rf "$DIST_DIR"
mkdir -p "$STAGE/share"

# bin/: the daemon, the CLI and the engine/llama.cpp libraries, staged by
# install.sh, the same tree a source install gets. One list of what the daemon
# loads lives there.
bash "$SCRIPT_DIR/install.sh" "$STAGE" >/dev/null
[ -x "$STAGE/bin/klar-policy-cli" ] || { echo "error: klar-policy-cli was not built" >&2; exit 1; }

# The system libraries too (gmime, glib, libmilter, sqlite, libarchive, libgomp,
# libstdc++ and what they pull in): every library ldd resolves outside glibc
# itself, so the install needs no package manager and no distro's package
# names. The unit's LD_LIBRARY_PATH=/opt/klar/bin makes this directory win.
# The ggml CPU plugins are dlopen'ed, so every .so is walked, not just the two
# executables. A "not found" fails the package rather than shipping a daemon
# that cannot start.
glibc='^(linux-vdso|ld-linux.*|libc|libm|libdl|libpthread|librt|libresolv|libutil)\.so'
deps="$(for f in "$STAGE"/bin/klar-milterd "$STAGE"/bin/klar-policy-cli "$STAGE"/bin/*.so*; do
    LD_LIBRARY_PATH="$STAGE/bin" ldd "$f"
done)"
if grep -q 'not found' <<<"$deps"; then
    grep 'not found' <<<"$deps" | sort -u >&2
    echo "error: unresolved libraries" >&2; exit 1
fi
awk '$2 == "=>" && $3 ~ /^\// { print $3 }' <<<"$deps" | sort -u | while read -r lib; do
    name="${lib##*/}"
    [[ "$name" =~ $glibc ]] && continue
    [ -e "$STAGE/bin/$name" ] && continue
    install -m 0644 "$(readlink -f "$lib")" "$STAGE/bin/$name"
done

# share/: everything the installer and the operator's next step need.
SHARE="$STAGE/share"
echo "$VERSION" > "$SHARE/VERSION"
install -m 0755 "$SCRIPT_DIR/fetch_model.sh" "$SHARE/fetch_model.sh"
install -m 0644 "$POSTFIX_DIR/model/released-manifest.json" "$SHARE/released-manifest.json"
install -m 0644 "$POSTFIX_DIR/packaging/klar-milterd.service" "$SHARE/klar-milterd.service"
mkdir -p "$SHARE/postfix" "$SHARE/stalwart/config" "$SHARE/stalwart/sieve" "$SHARE/stalwart/scripts"
install -m 0644 "$POSTFIX_DIR/config/example.toml" "$SHARE/postfix/klar-milterd.toml"
install -m 0644 "$POSTFIX_DIR/packaging/postfix-main.cf.snippet" "$SHARE/postfix/main.cf.snippet"
install -m 0644 "$POSTFIX_DIR/packaging/klar.sieve" "$SHARE/postfix/klar.sieve"
STALWART_DIR="$REPO_ROOT/stalwart"
install -m 0644 "$STALWART_DIR"/config/* "$SHARE/stalwart/config/"
install -m 0644 "$STALWART_DIR/sieve/klar.sieve" "$SHARE/stalwart/sieve/klar.sieve"
install -m 0755 "$STALWART_DIR/scripts/apply.py" "$STALWART_DIR/scripts/sieve_activate.py" "$SHARE/stalwart/scripts/"
# The licences sit at the public repo's root, and under engine/publish/ in the
# monorepo it is published from.
for f in LICENSE LICENSE-MODEL.md THIRD_PARTY_LICENSES.md; do
    src="$REPO_ROOT/$f"; [ -f "$src" ] || src="$REPO_ROOT/engine/publish/$f"
    install -m 0644 "$src" "$SHARE/$f"
done

TARBALL="klar-milterd-${VERSION}-linux-${ARCH}.tar.gz"
# root-owned entries: the builder's uid may be a real user on the target.
tar --owner=0 --group=0 --numeric-owner -czf "$DIST_DIR/$TARBALL" -C "$STAGE" bin share
(cd "$DIST_DIR" && sha256sum "$TARBALL" > "$TARBALL.sha256")
rm -rf "$STAGE"

echo "[postfix/package] $DIST_DIR/$TARBALL ($(du -h "$DIST_DIR/$TARBALL" | cut -f1))"
cat "$DIST_DIR/$TARBALL.sha256"
