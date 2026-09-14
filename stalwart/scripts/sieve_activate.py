#!/usr/bin/env python3
"""Activate the "klar" filing rules on one mailbox, over JMAP for Sieve (RFC 9661).

    STALWART_PASSWORD=... stalwart/scripts/sieve_activate.py --url https://mail.example.com --user alice@example.com
    stalwart/scripts/sieve_activate.py --url ... --user ... --deactivate

Per account, because that is where Stalwart files: the built-in filter's junk
decision is a flag set before milters run, so the milter's X-Klar-Label can
only be acted on by the account's own active Sieve script at delivery. This
installs a one-line script that includes the global user script "klar"
(published by apply.py from sieve/klar.sieve), and makes it the active one.
Updating the rules later means updating the global script; the per-account
include never changes.

Credentials are the ACCOUNT's (an account owns its scripts). The admin has no
way to write another account's Sieve through the management API, which is why
this is a separate tool from apply.py. Idempotent: an existing "klar" script is
left alone if its contents match and re-activated if it is not the active one.
An account that already runs a script of its own is refused (exit 3) with the
two lines to paste into it: JMAP allows one active script, and activating ours
would switch theirs off.

An account whose contents are the point (a spam trap, a corpus mailbox) must NOT
get this: it would file the very spam it exists to collect.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

SCRIPT_NAME = "klar"
SCRIPT_BODY = 'require ["include"];\ninclude :global "klar";\n'
CORE = "urn:ietf:params:jmap:core"
SIEVE = "urn:ietf:params:jmap:sieve"


def rebase(base_url: str, url: str) -> str:
    """The server's path on the operator's origin (base_url, no trailing slash).
    When --url itself carries a path prefix (a Stalwart served under /mail) and
    the advertised URL starts with that same prefix, it is one prefix, not two."""
    parts = urllib.parse.urlsplit(url)
    path = parts.path
    prefix = urllib.parse.urlsplit(base_url).path.rstrip("/")
    if prefix and path.startswith(prefix + "/"):
        path = path[len(prefix):]
    return base_url + path + (f"?{parts.query}" if parts.query else "")


class JmapError(RuntimeError):
    pass


class Session:
    """A JMAP session as one account, for the capabilities named (default: Sieve).

    Also the client stalwart/scripts/test_e2e.sh reads mailboxes with, hence
    `capabilities`: the same session, auth and URL handling, a different `using`.
    """

    def __init__(self, base_url: str, user: str, password: str, insecure: bool = False, capabilities=(SIEVE,)):
        self.base_url = base_url.rstrip("/")
        self.capabilities = tuple(capabilities)
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
        self.ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()  # noqa: S323 -- opt-in
        # urllib follows the 307 Stalwart answers here (to /jmap/session) on its own.
        self.session = self._get_json(f"{self.base_url}/.well-known/jmap")
        for cap in self.capabilities:
            if cap not in self.session.get("capabilities", {}):
                raise JmapError(f"this server does not advertise {cap}")
        primary = self.capabilities[0]
        self.account_id = self.session["primaryAccounts"].get(primary) or next(iter(self.session["accounts"]))
        # The session's apiUrl/uploadUrl/downloadUrl carry the server's CONFIGURED
        # public URL (Stalwart: STALWART_PUBLIC_URL, else https://<hostname>), not
        # the address this request reached it by. Reached by IP, through a port
        # map, or in a container, those would point somewhere unreachable; keep
        # their paths, use --url for the origin.
        for key in ("apiUrl", "uploadUrl", "downloadUrl"):
            self.session[key] = rebase(self.base_url, self.session[key])

    def _request(self, url: str, data: bytes | None = None, content_type: str | None = None) -> bytes:
        # The URL is the operator's --url plus paths the server's own session
        # document names; no file: or custom scheme reaches it (S310 below).
        req = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET")  # noqa: S310
        req.add_header("Authorization", self.auth)
        req.add_header("Accept", "application/json")
        if content_type:
            req.add_header("Content-Type", content_type)
        try:
            with urllib.request.urlopen(req, timeout=30, context=self.ctx) as resp:  # noqa: S310 -- caller-supplied https URL
                return resp.read()
        except urllib.error.HTTPError as exc:
            raise JmapError(f"HTTP {exc.code} from {url}: {exc.read().decode('utf-8', 'replace')[:300]}") from exc
        except urllib.error.URLError as exc:
            raise JmapError(f"cannot reach {url}: {exc.reason}") from exc

    def _get_json(self, url: str) -> dict:
        return json.loads(self._request(url))

    def call(self, method: str, args: dict) -> dict:
        payload = {
            "using": [CORE, *self.capabilities],
            "methodCalls": [[method, {"accountId": self.account_id, **args}, "0"]],
        }
        raw = self._request(self.session["apiUrl"], json.dumps(payload).encode(), "application/json")
        name, result, _ = json.loads(raw)["methodResponses"][0]
        if name == "error":
            raise JmapError(f"{method}: {result}")
        refused = result.get("notCreated") or result.get("notUpdated") or result.get("notDestroyed")
        if refused:
            raise JmapError(f"{method} refused: {refused}")
        return result

    def upload(self, data: bytes, content_type: str) -> str:
        url = self.session["uploadUrl"].replace("{accountId}", self.account_id)
        return json.loads(self._request(url, data, content_type))["blobId"]

    def download(self, blob_id: str) -> bytes:
        url = (
            self.session["downloadUrl"]
            .replace("{accountId}", self.account_id)
            .replace("{blobId}", blob_id)
            .replace("{name}", "script.sieve")
            .replace("{type}", "application/sieve")
        )
        return self._request(url)


def scripts(session: Session) -> list[dict]:
    return session.call("SieveScript/get", {"ids": None}).get("list", [])


class ActiveScriptError(Exception):
    """The account already runs a Sieve script of its own."""


def activate(session: Session) -> str:
    """Install or refresh the "klar" script and make it active. Returns what happened."""
    all_scripts = scripts(session)
    # JMAP allows one active script per account, so activating ours would
    # silently switch off whatever the account runs today (forwarding, a
    # vacation notice, its own filing). Never take that decision for a user.
    other = next((s for s in all_scripts if s.get("isActive") and s.get("name") != SCRIPT_NAME), None)
    if other:
        raise ActiveScriptError(
            f"this account already has an active Sieve script ({other.get('name')!r}); klar was not installed. "
            f"Add these two lines to that script instead, or deactivate it first:\n{SCRIPT_BODY.rstrip()}"
        )
    existing = next((s for s in all_scripts if s.get("name") == SCRIPT_NAME), None)
    if existing and session.download(existing["blobId"]).decode("utf-8", "replace") == SCRIPT_BODY:
        if existing.get("isActive"):
            return "ok: klar is installed and active"
        session.call("SieveScript/set", {"onSuccessActivateScript": existing["id"]})
        return "activated: klar was installed but not active"
    blob_id = session.upload(SCRIPT_BODY.encode(), "application/sieve")
    if existing:
        session.call(
            "SieveScript/set",
            {"update": {existing["id"]: {"blobId": blob_id}}, "onSuccessActivateScript": existing["id"]},
        )
        return "updated: klar rewritten and active"
    session.call(
        "SieveScript/set",
        {"create": {"k": {"name": SCRIPT_NAME, "blobId": blob_id}}, "onSuccessActivateScript": "#k"},
    )
    return "installed: klar created and active"


def deactivate(session: Session) -> str:
    existing = next((s for s in scripts(session) if s.get("name") == SCRIPT_NAME), None)
    if not existing:
        return "ok: no klar script on this account"
    if existing.get("isActive"):
        session.call("SieveScript/set", {"onSuccessDeactivateScript": True})
    session.call("SieveScript/set", {"destroy": [existing["id"]]})
    return "removed: klar deactivated and deleted"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", required=True, help="https://mail.example.com (the JMAP host)")
    p.add_argument("--user", required=True, help="the account, e.g. alice@example.com")
    p.add_argument("--password", default=None, help="defaults to $STALWART_PASSWORD")
    p.add_argument("--deactivate", action="store_true", help="remove the klar script instead")
    p.add_argument("-k", "--insecure", action="store_true", help="skip TLS verification (test stacks)")
    args = p.parse_args(argv)
    password = args.password or os.environ.get("STALWART_PASSWORD")
    if not password:
        print("error: pass --password or set STALWART_PASSWORD (the account's password)", file=sys.stderr)
        return 2
    try:
        session = Session(args.url, args.user, password, insecure=args.insecure)
        print(f"{args.user}: {deactivate(session) if args.deactivate else activate(session)}")
    except ActiveScriptError as exc:
        print(f"refused: {args.user}: {exc}", file=sys.stderr)
        return 3
    except JmapError as exc:
        print(f"error: {args.user}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
