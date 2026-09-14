#!/bin/bash
# tar_chmod_only.sh against tar's real stderr shapes. The case that matters is
# the podman 3.4 overlayfs build: N chmod refusals PLUS the summary line GNU tar
# appends to every failed run. A tolerance that forgets the summary line is
# fatal on exactly the condition it exists for.
#
#   make engine/test-tar-tolerance
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$HERE/tar_chmod_only.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail() { echo "FAIL: $1" >&2; exit 1; }
pass() { echo "  ok: $1"; }

# GNU tar 1.34 on an overlayfs podman build, verbatim shape.
cat > "$WORK/gnu" <<'EOF'
tar: llama-b7000/lib/libllama.so: Cannot change mode to rwxr-xr-x: Operation not permitted
tar: llama-b7000/lib: Cannot change mode to rwxr-xr-x: Operation not permitted
tar: Exiting with failure status due to previous errors
EOF
bash "$CHECK" "$WORK/gnu" || fail "chmod refusals plus GNU tar's summary line must be tolerated"
pass "GNU tar: chmod refusals + summary line tolerated"

cat > "$WORK/bsd" <<'EOF'
tar: llama-b7000/lib/libllama.so: Cannot change mode to rwxr-xr-x: Operation not permitted
tar: Error exit delayed from previous errors.
EOF
bash "$CHECK" "$WORK/bsd" || fail "chmod refusals plus bsdtar's summary line must be tolerated"
pass "bsdtar: chmod refusal + summary line tolerated"

cat > "$WORK/trunc" <<'EOF'
gzip: stdin: unexpected end of file
tar: Unexpected EOF in archive
tar: Error is not recoverable: exiting now
EOF
if bash "$CHECK" "$WORK/trunc"; then fail "a truncated download must stay fatal"; fi
pass "truncated archive: fatal"

cat > "$WORK/mixed" <<'EOF'
tar: llama-b7000/lib: Cannot change mode to rwxr-xr-x: Operation not permitted
tar: llama-b7000/lib/libggml.so: Not found in archive
tar: Exiting with failure status due to previous errors
EOF
if bash "$CHECK" "$WORK/mixed"; then fail "a missing member beside chmod refusals must stay fatal"; fi
pass "chmod refusals + a real error: fatal"

# setup.sh must call this file, or the tolerance is dead code.
grep -q 'tar_chmod_only.sh' "$HERE/setup.sh" || fail "setup.sh does not call tar_chmod_only.sh"
pass "setup.sh calls it"

echo "[test-tar-tolerance] All checks passed."
