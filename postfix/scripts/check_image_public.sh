#!/bin/bash
# check_image_public.sh [tag]: can a stranger pull the released image?
#
# A ghcr package first pushed by a workflow token is PRIVATE, and GitHub has no
# API to change that (REST: list/get/delete/restore only; no GraphQL mutation),
# so the one switch is a click in the package's settings. It is also one-time:
# every later tag lands in the same package. This is the check that turns a
# reader's "the image does not exist" into a red step with the URL to fix it,
# in the release job right after the push and in `make postfix/check-image-public`.
#
# Anonymous, on purpose: a pull token from ghcr.io/token with no credentials,
# then the manifest. 200 is public; 401/403 is private or absent.
set -euo pipefail
OWNER="${IMAGE_OWNER:-klar-im}"
NAME="${IMAGE_NAME:-klar-milterd}"
TAG="${1:-latest}"

# For a private package ghcr refuses the anonymous pull token itself (401), so
# that is the first place the answer shows.
token="$(curl -sS "https://ghcr.io/token?scope=repository:$OWNER/$NAME:pull" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("token",""))
except Exception: print("")')"
code="$(curl -sS -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $token" \
    -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json" \
    "https://ghcr.io/v2/$OWNER/$NAME/manifests/$TAG")"
case "$code" in
    200)
        echo "[check-image-public] ghcr.io/$OWNER/$NAME:$TAG is pullable anonymously"
        ;;
    *)
        cat >&2 <<EOF
[check-image-public] ghcr.io/$OWNER/$NAME:$TAG is NOT pullable anonymously (HTTP $code).
  The package is private, which is what a first workflow push creates and what
  GitHub offers no API to change. One click, once, for every tag after it:
    https://github.com/orgs/$OWNER/packages/container/$NAME/settings
  > Change visibility > Public. Then re-run this check.
EOF
        exit 1
        ;;
esac
