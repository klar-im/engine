#!/bin/sh
# Install klar-milterd, the Klar spam filter for Stalwart and Postfix, from the
# prebuilt release binaries (Linux x86_64 or arm64, systemd):
#
#   curl -fsSL https://raw.githubusercontent.com/klar-im/engine/main/install.sh | sudo KLAR_ACCEPT_MODEL_LICENSE=1 sh
#
#   KLAR_ACCEPT_MODEL_LICENSE=1  required: the model is CC-BY-NC-4.0 (LICENSE-MODEL.md)
#   KLAR_MTA=postfix             write the Postfix config instead of the Stalwart one
#                                (first install only; an existing config is never touched)
#   KLAR_VERSION=v0.2.0          a given release instead of the latest
#   KLAR_TARBALL=/path/x.tar.gz  install a local tarball (with its .sha256 beside it)
#
# What it does: binaries and libraries into /opt/klar/bin, the configs and
# scripts into /opt/klar/share, a klarmilter system user, /etc/klar/klar-milterd.toml
# if absent, the model into /var/lib/klar/model (sha256-verified, files already
# there and matching are kept), the klar-milterd systemd unit enabled and
# (re)started, then it waits for /readyz. Re-running it upgrades in place.
set -eu

REPO=klar-im/engine
PREFIX=/opt/klar
CONFIG=/etc/klar/klar-milterd.toml
STATE=/var/lib/klar
UNIT=/etc/systemd/system/klar-milterd.service
MTA=${KLAR_MTA:-stalwart}

die() { echo "klar: $*" >&2; exit 1; }
say() { echo "klar: $*"; }

# Everything runs from main(), called on the last line: piped from curl, a
# download cut short then runs nothing instead of the first half of the script.
main() {
[ "$(uname -s)" = Linux ] || die "Linux only (this is $(uname -s))"
[ "$(id -u)" -eq 0 ] || die "run as root: curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sudo KLAR_ACCEPT_MODEL_LICENSE=1 sh"
[ -d /run/systemd/system ] || die "systemd is required: klar-milterd runs as a systemd service (or use the container, ghcr.io/klar-im/klar-milterd)"
if [ "${KLAR_ACCEPT_MODEL_LICENSE:-}" != 1 ]; then
    cat >&2 <<EOF
The Klar model is licensed separately from the code, under CC-BY-NC-4.0:
free for non-commercial use with attribution, a paid licence for commercial use (hello@klar.im).
Read https://github.com/$REPO/blob/main/LICENSE-MODEL.md, then re-run with KLAR_ACCEPT_MODEL_LICENSE=1.
EOF
    exit 2
fi
case $MTA in
    stalwart) DEFAULT_CONFIG=share/stalwart/config/klar-milterd.toml ;;
    postfix)  DEFAULT_CONFIG=share/postfix/klar-milterd.toml ;;
    *) die "KLAR_MTA must be stalwart or postfix, not '$MTA'" ;;
esac
case $(uname -m) in
    x86_64|amd64)  ARCH=x86_64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "no prebuilt binaries for $(uname -m) (x86_64 and arm64 only); build from source: https://github.com/$REPO/blob/main/stalwart/README.md" ;;
esac
# python3 runs fetch_model.sh's manifest read and the Stalwart scripts.
for tool in curl tar sha256sum python3 bash useradd systemctl; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required; install it with your package manager and re-run"
done

# Work next to /opt/klar, on the same filesystem, so the swap below is two renames.
mkdir -p "$PREFIX"
tmp=$(mktemp -d "$PREFIX.install.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

if [ -n "${KLAR_TARBALL:-}" ]; then
    tarball=$KLAR_TARBALL
    [ -f "$tarball" ] || die "KLAR_TARBALL: no such file: $tarball"
    [ -f "$tarball.sha256" ] || die "KLAR_TARBALL: $tarball.sha256 is missing"
    cp "$tarball.sha256" "$tmp/sha256"
else
    version=${KLAR_VERSION:-}
    if [ -z "$version" ]; then
        # releases/latest redirects to releases/tag/<version>: no API call, no rate limit.
        version=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") \
            || die "cannot reach github.com to find the latest release"
        version=${version##*/}
        case $version in v*) ;; *) die "no release published at https://github.com/$REPO/releases" ;; esac
    fi
    file=klar-milterd-$version-linux-$ARCH.tar.gz
    base=https://github.com/$REPO/releases/download/$version
    say "downloading $file"
    curl -fsSL --retry 3 -o "$tmp/$file" "$base/$file" || die "download failed: $base/$file"
    curl -fsSL --retry 3 -o "$tmp/sha256" "$base/$file.sha256" || die "download failed: $base/$file.sha256"
    tarball=$tmp/$file
fi
expected=$(cut -d' ' -f1 < "$tmp/sha256")
actual=$(sha256sum "$tarball" | cut -d' ' -f1)
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    die "sha256 mismatch for $tarball (expected $expected, got $actual)"
fi

mkdir "$tmp/new"
tar --no-same-owner -xzf "$tarball" -C "$tmp/new"
if [ ! -x "$tmp/new/bin/klar-milterd" ] || [ ! -d "$tmp/new/share" ]; then
    die "$tarball is not a klar-milterd release tarball"
fi
# Prove the binaries run on this system before replacing anything.
LD_LIBRARY_PATH="$tmp/new/bin" "$tmp/new/bin/klar-policy-cli" --version >/dev/null 2>&1 \
    || die "the prebuilt binaries do not run here (they need glibc 2.35 or newer on x86_64, 2.39 on arm64; or use the container, ghcr.io/klar-im/klar-milterd); build from source: https://github.com/$REPO"
say "installing $(cat "$tmp/new/share/VERSION") into $PREFIX"
for d in bin share; do
    rm -rf "${PREFIX:?}/$d.old"
    if [ -e "$PREFIX/$d" ]; then mv "$PREFIX/$d" "$PREFIX/$d.old"; fi
    mv "$tmp/new/$d" "$PREFIX/$d"
    rm -rf "${PREFIX:?}/$d.old"
done

if ! id -u klarmilter >/dev/null 2>&1; then
    nologin=$(command -v nologin || echo /bin/false)
    useradd --system --user-group --no-create-home --home-dir /nonexistent --shell "$nologin" klarmilter
fi
install -d -m 0755 /etc/klar
install -d -m 0750 -o klarmilter -g klarmilter "$STATE"
if [ -f "$CONFIG" ]; then
    say "keeping $CONFIG"
else
    install -m 0644 "$PREFIX/$DEFAULT_CONFIG" "$CONFIG"
    say "wrote $CONFIG ($MTA)"
fi

# The model goes where the config says, read the way the container's entrypoint
# reads it, so the fetch and the daemon cannot disagree about the directory.
model_dir=$(sed -n 's/^model_dir *= *"\([^"]*\)".*/\1/p' "$CONFIG" | head -1)
KLAR_ACCEPT_MODEL_LICENSE=1 "$PREFIX/share/fetch_model.sh" "${model_dir:-$STATE/model}" "$PREFIX/share/released-manifest.json"

install -m 0644 "$PREFIX/share/klar-milterd.service" "$UNIT"
systemctl daemon-reload
systemctl enable --quiet klar-milterd
systemctl restart klar-milterd

# Readiness through the health endpoint the kept config declares, as the daemon
# reads it (health_enabled, health_listen); a wildcard bind is probed on loopback.
if grep -q '^health_enabled *= *false' "$CONFIG"; then
    sleep 5
    systemctl is-active --quiet klar-milterd || die "klar-milterd did not start; see: journalctl -u klar-milterd -n 50"
    say "klar-milterd is running (health endpoint disabled in $CONFIG, so readiness is not checked)"
else
    health=$(sed -n 's/^health_listen *= *"\([^"]*\)".*/\1/p' "$CONFIG" | head -1)
    health=${health:-127.0.0.1:8892}
    host=${health%:*}
    case $host in 0.0.0.0) host=127.0.0.1 ;; '[::]') host='[::1]' ;; esac
    url="http://$host:${health##*:}/readyz"
    say "waiting for $url (loading the model)"
    waited=0
    until curl -fsS "$url" >/dev/null 2>&1; do
        [ "$waited" -lt 180 ] || die "klar-milterd is not ready after 180 s; see: journalctl -u klar-milterd -n 50"
        sleep 2
        waited=$((waited + 2))
    done
    say "klar-milterd is running and ready"
fi
say "config $CONFIG; re-run this command to upgrade"
echo

if [ "$MTA" = stalwart ]; then
    cat <<EOF
Next, point Stalwart at it (stalwart-cli on PATH, admin credentials; add --shadow
to keep Stalwart's own filter scoring beside Klar without filing, --dry-run to see the plan):

  export STALWART_URL=http://127.0.0.1:8080 STALWART_USER=admin STALWART_PASSWORD=...
  python3 $PREFIX/share/stalwart/scripts/apply.py --milter-host 127.0.0.1 --milter-port 8891

Then turn filing on for each mailbox people read, with that account's own password:

  STALWART_PASSWORD='...' python3 $PREFIX/share/stalwart/scripts/sieve_activate.py --url https://mail.example.com --user alice@example.com

Guide: https://github.com/$REPO/blob/main/stalwart/README.md
EOF
else
    cat <<EOF
Next, add this to /etc/postfix/main.cf and run \`postfix reload\`. If smtpd_milters
already lists OpenDKIM/OpenDMARC, put inet:127.0.0.1:8891 AFTER them: the milter
trusts the Authentication-Results they stamp.

$(grep -v '^#' "$PREFIX/share/postfix/main.cf.snippet")

Filing on the verdict: $PREFIX/share/postfix/klar.sieve as a Dovecot sieve_before script.
Guide: https://github.com/$REPO/blob/main/postfix/README.md
EOF
fi
}

main "$@"
