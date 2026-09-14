#!/usr/bin/env python3
"""sieve_activate.activate() against a fake JMAP session: installs on an empty
account, is a no-op once installed, and REFUSES an account that already runs a
script of its own (JMAP allows one active script; activating ours would switch
theirs off).

    make stalwart/test-unit
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))

import sieve_activate as sa  # noqa: E402


class FakeSession:
    """Just enough of sieve_activate.Session: scripts, blobs, one active script."""

    def __init__(self, scripts: list[dict], blobs: dict[str, bytes] | None = None):
        self.scripts = scripts
        self.blobs = dict(blobs or {})
        self.calls: list[dict] = []

    def call(self, method: str, args: dict) -> dict:
        if method == "SieveScript/get":
            return {"list": self.scripts}
        assert method == "SieveScript/set", method
        self.calls.append(args)
        for key, spec in (args.get("create") or {}).items():
            self.scripts.append({"id": f"id-{key}", "name": spec["name"], "blobId": spec["blobId"], "isActive": False})
        for ident, patch in (args.get("update") or {}).items():
            next(s for s in self.scripts if s["id"] == ident).update(patch)
        activate = args.get("onSuccessActivateScript")
        if activate:
            ident = f"id-{activate[1:]}" if activate.startswith("#") else activate
            for s in self.scripts:
                s["isActive"] = s["id"] == ident
        return {}

    def upload(self, data: bytes, content_type: str) -> str:
        blob_id = f"blob-{len(self.blobs) + 1}"
        self.blobs[blob_id] = data
        return blob_id

    def download(self, blob_id: str) -> bytes:
        return self.blobs[blob_id]


def active_names(session: FakeSession) -> list[str]:
    return [s["name"] for s in session.scripts if s.get("isActive")]


def check_installs_on_an_empty_account() -> list[str]:
    session = FakeSession([])
    out = sa.activate(session)
    problems = []
    if not out.startswith("installed"):
        problems.append(f"expected 'installed', got {out!r}")
    if active_names(session) != ["klar"]:
        problems.append(f"klar must be the active script, got {active_names(session)}")
    if session.blobs.get("blob-1") != sa.SCRIPT_BODY.encode():
        problems.append("the uploaded script is not SCRIPT_BODY")
    return problems


def check_installed_and_active_is_a_noop() -> list[str]:
    session = FakeSession(
        [{"id": "k", "name": "klar", "blobId": "b", "isActive": True}], {"b": sa.SCRIPT_BODY.encode()}
    )
    out = sa.activate(session)
    problems = []
    if not out.startswith("ok"):
        problems.append(f"expected 'ok', got {out!r}")
    if session.calls:
        problems.append(f"a no-op must not write, wrote {session.calls}")
    return problems


def check_refuses_an_account_with_its_own_active_script() -> list[str]:
    session = FakeSession(
        [{"id": "v", "name": "vacation", "blobId": "bv", "isActive": True}], {"bv": b"vacation :days 3 \"away\";"}
    )
    problems = []
    try:
        out = sa.activate(session)
    except sa.ActiveScriptError as exc:
        if "vacation" not in str(exc) or 'include :global "klar"' not in str(exc):
            problems.append(f"the refusal must name the script and give the include line, got {exc}")
    else:
        problems.append(f"an account running 'vacation' must be refused, got {out!r}")
    if session.calls:
        problems.append(f"a refusal must write nothing, wrote {session.calls}")
    if active_names(session) != ["vacation"]:
        problems.append(f"the user's script must stay active, got {active_names(session)}")
    return problems


def check_refusal_exits_3_from_main() -> list[str]:
    refused = FakeSession([{"id": "v", "name": "vacation", "blobId": "bv", "isActive": True}], {"bv": b"x"})
    real = sa.Session
    sa.Session = lambda *a, **k: refused  # noqa: E731
    try:
        code = sa.main(["--url", "https://mail.example", "--user", "alice@example", "--password", "pw"])
    finally:
        sa.Session = real
    return [] if code == 3 else [f"main() must exit 3 on a refusal, got {code}"]


def check_rebase_keeps_one_path_prefix() -> list[str]:
    """Session URLs carry the server's configured public URL; --url wins for the
    origin. A --url with a path prefix that the server also advertises is one
    prefix, not two; a --url without one keeps the server's path whole."""
    def rebase(base: str, advertised: str) -> str:
        return sa.rebase(base.rstrip("/"), advertised)

    cases = [
        ("http://127.0.0.1:18080", "https://mail.example/jmap/", "http://127.0.0.1:18080/jmap/"),
        ("https://mail.example/mail", "https://mail.example/mail/jmap/", "https://mail.example/mail/jmap/"),
        ("https://mail.example/mail", "https://mail.example/jmap/", "https://mail.example/mail/jmap/"),
        ("https://mail.example/mail", "https://x/mailbox/jmap/", "https://mail.example/mail/mailbox/jmap/"),
        ("http://h:1", "https://mail.example/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
         "http://h:1/jmap/download/{accountId}/{blobId}/{name}?accept={type}"),
    ]
    return [f"{base} + {adv} -> {rebase(base, adv)}, expected {want}" for base, adv, want in cases if rebase(base, adv) != want]


def main() -> int:
    checks = [
        ("_rebase keeps one path prefix", check_rebase_keeps_one_path_prefix()),
        ("installs on an empty account", check_installs_on_an_empty_account()),
        ("installed and active is a no-op", check_installed_and_active_is_a_noop()),
        ("refuses an account with its own active script", check_refuses_an_account_with_its_own_active_script()),
        ("the refusal exits 3", check_refusal_exits_3_from_main()),
    ]
    failed = False
    for label, problems in checks:
        if problems:
            failed = True
            for problem in problems:
                print(f"  {label.upper()}: {problem}", file=sys.stderr)
        else:
            print(f"  ok  {label}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
