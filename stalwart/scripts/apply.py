#!/usr/bin/env python3
"""Wire Klar into a Stalwart 0.16 server, idempotently, through `stalwart-cli`.

    stalwart/scripts/apply.py [--shadow] [--milter-host H] [--milter-port P] [--milter-id ID|new] [--dry-run]

Reads STALWART_URL / STALWART_USER / STALWART_PASSWORD (or STALWART_TOKEN) like
stalwart-cli itself, and STALWART_CLI for the binary (default: on PATH). Every
step is desired-state: an object that already matches is left alone, one that
differs is updated, one that is missing is created, and the run says which.
Re-running is a no-op. Nothing here is destructive except leaving shadow mode,
which deletes the two KLAR_SHADOW objects it created.

What it applies, from stalwart/config/ (the same fragments klar.im runs):

  MtaMilter        klar-milterd at --milter-host:--milter-port, DATA stage,
                   unauthenticated inbound only, tempFailOnError off. The
                   endpoint is the object's only identity (Stalwart gives a
                   milter no name), so when the milter moves, --milter-id
                   names the object to re-point; the run refuses to add a
                   second milter beside an unexplained one.
  SenderAuth       dmarcVerify strict on port 25 (DMARC p=reject forgeries are
                   refused at SMTP time; the milter runs with auth_results=ignore
                   and never sees a DMARC result itself).
  SieveUserScript  the global user script "klar" (sieve/klar.sieve), which each
                   filing mailbox includes (scripts/sieve_activate.py).
  MtaStageData     enableSpamFilter false, so Stalwart's built-in filter stops
                   deciding. Under --shadow the filter must be ON to score, so
                   the exact "false" this script set is put back to Stalwart's
                   default; any other expression is left alone.
  SpamTag+SpamRule KLAR_SHADOW at -100 on every message, created with --shadow,
                   deleted without it. Shadow = Stalwart still scores and writes
                   X-Spam-Result for the comparison, but can never file.

Then one ReloadSettings if anything changed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG = HERE.parent / "config"
SIEVE = HERE.parent / "sieve" / "klar.sieve"
SCRIPT_NAME = "klar"
SHADOW_TAG = "KLAR_SHADOW"


class CliError(RuntimeError):
    pass


class Cli:
    """stalwart-cli, with the two output shapes this script needs."""

    def __init__(self, binary: str, dry_run: bool = False):
        self.binary = binary
        self.dry_run = dry_run
        self.changed = False

    def _run(self, *args: str, stdin: str | None = None) -> str:
        cmd = [self.binary, *args]
        proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True, check=False)  # noqa: S603 -- our own CLI
        if proc.returncode != 0:
            raise CliError(f"{' '.join(cmd)} failed ({proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}")
        return proc.stdout

    def get(self, obj: str, ident: str = "singleton") -> dict:
        return json.loads(self._run("get", obj, ident, "--json"))

    def query(self, obj: str) -> list[dict]:
        """One object per line, SUMMARY fields only (id plus a few identifying
        ones). Anything to be diffed against a desired state must go through
        get(); comparing a query row makes every absent field look changed and
        turns an idempotent run into an update on every deploy."""
        out = self._run("query", obj, "--json")
        return [json.loads(line) for line in out.splitlines() if line.strip()]

    def find(self, obj: str, **match) -> dict | None:
        """The full object whose summary fields equal `match`, or None."""
        for row in self.query(obj):
            if all(row.get(k) == v for k, v in match.items()):
                return self.get(obj, row["id"])
        return None

    def _write(self, verb: str, obj: str, payload: dict, ident: str | None = None, what: str = "") -> None:
        args = [verb, obj] + ([ident] if ident else []) + ["--stdin"]
        print(f"  {verb:<6} {obj:<16} {what}".rstrip())
        self.changed = True
        if self.dry_run:
            return
        self._run(*args, stdin=json.dumps(payload))

    def create(self, obj: str, payload: dict, what: str = "") -> None:
        self._write("create", obj, payload, what=what)

    def update(self, obj: str, ident: str, payload: dict, what: str = "") -> None:
        self._write("update", obj, payload, ident=ident, what=what)

    def delete(self, obj: str, ident: str, what: str = "") -> None:
        print(f"  delete {obj:<16} {what}".rstrip())
        self.changed = True
        if not self.dry_run:
            self._run("delete", obj, "--ids", ident)

    def reload_settings(self) -> None:
        print("  action ReloadSettings")
        if not self.dry_run:
            self._run("create", "Action", "--stdin", stdin=json.dumps({"@type": "ReloadSettings"}))


def load_fragment(name: str) -> dict:
    return {k: v for k, v in json.loads((CONFIG / name).read_text()).items() if not k.startswith("_comment")}


def _canonical(value):
    """Stalwart returns a score as -100.0 where the fragment says -100; the same
    number, two JSON spellings. Fold integral floats before comparing, or the
    tag is 'updated' on every run."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {k: _canonical(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_canonical(v) for v in value]
    return value


def same(a, b) -> bool:
    return json.dumps(_canonical(a), sort_keys=True) == json.dumps(_canonical(b), sort_keys=True)


def differing(current: dict, desired: dict) -> dict:
    return {k: v for k, v in desired.items() if not same(current.get(k), v)}


def converge(cli: Cli, obj: str, current: dict | None, desired: dict, what: str) -> None:
    """Desired-state for one object already looked up: create it when absent,
    patch what differs, or say ok. Every managed object goes through here, so
    "what counts as changed" and how a run reports it are decided once."""
    if current is None:
        cli.create(obj, desired, what=what)
        return
    patch = differing(current, desired)
    if patch:
        cli.update(obj, current["id"], patch, what=f"{what} ({', '.join(patch)})")
    else:
        print(f"  ok     {obj:<16} {what}")


def apply_object(cli: Cli, obj: str, desired: dict, what: str, **match) -> None:
    converge(cli, obj, cli.find(obj, **match), desired, what)


def apply_singleton(cli: Cli, obj: str, desired: dict) -> None:
    converge(cli, obj, cli.get(obj), desired, ", ".join(desired))


def apply_milter(cli: Cli, host: str, port: int, milter_id: str | None = None) -> None:
    desired = load_fragment("mta-milter.json")
    desired["hostname"] = host
    desired["port"] = port
    what = f"{host}:{port}"
    if milter_id and milter_id != "new":
        # The operator named the object to move: point it at the new endpoint.
        converge(cli, "MtaMilter", cli.get("MtaMilter", milter_id), desired, what)
        return
    rows = cli.query("MtaMilter")
    mine = next((m for m in rows if (m.get("hostname"), m.get("port")) == (host, port)), None)
    # An MtaMilter has no name; the endpoint is its only identity. So a milter
    # that moved (a container's new address) looks like a missing one, and
    # creating it would leave the old endpoint active: two milters, one of
    # them timing out on every message. Refuse to guess.
    if mine is None and rows and milter_id is None:
        listing = ", ".join(f"{m.get('hostname')}:{m.get('port')} ({m['id']})" for m in rows)
        raise CliError(
            f"no MtaMilter at {what}, but other milters exist: {listing}. If one of them is the Klar milter at "
            f"its old address, re-run with --milter-id <id> to move it; if it is something else, --milter-id new"
        )
    converge(cli, "MtaMilter", cli.get("MtaMilter", mine["id"]) if mine else None, desired, what)


def apply_stage_data(cli: Cli, shadow: bool) -> None:
    """MtaStageData.enableSpamFilter, one owner for both modes. Final: off, the
    built-in filter stops deciding. Shadow: Stalwart must score, so the exact
    "off" this script wrote is put back to Stalwart's default; any other
    expression is the operator's and is left alone (a server that ran final and
    returns to shadow would otherwise record no X-Spam-Result at all and read
    as a filter that never fires)."""
    off = load_fragment("stage-data.json")
    if not shadow:
        apply_singleton(cli, "MtaStageData", off)
        return
    current = cli.get("MtaStageData")
    if same(current.get("enableSpamFilter"), off["enableSpamFilter"]):
        on = {"enableSpamFilter": load_fragment("shadow.json")["enableSpamFilter"]}
        cli.update("MtaStageData", "singleton", on, what="enableSpamFilter back on (shadow needs Stalwart scoring)")
    else:
        print("  skip   MtaStageData     enableSpamFilter left as is (shadow)")


def apply_sieve(cli: Cli) -> None:
    # Stalwart stores the script without its trailing newline; compare what it
    # will store, or every run rewrites an identical script.
    desired = {
        "name": SCRIPT_NAME,
        "description": "Klar: file on X-Klar-Label / X-Klar-Class",
        "isActive": True,
        "contents": SIEVE.read_text().rstrip("\n"),
    }
    apply_object(cli, "SieveUserScript", desired, SCRIPT_NAME, name=SCRIPT_NAME)


def apply_shadow(cli: Cli, shadow: bool) -> None:
    fragment = load_fragment("shadow.json")
    if shadow:
        # Desired-state, not existence: a hand-edited score, condition or
        # enable flag on either object is what lets Stalwart start filing
        # again, so the reconcile has to put the contents back, not just the
        # names.
        apply_object(cli, "SpamTag", fragment["tag"], f"{SHADOW_TAG} -100", tag=SHADOW_TAG)
        apply_object(cli, "SpamRule", fragment["rule"], SHADOW_TAG, name=SHADOW_TAG)
        return
    tags = [t for t in cli.query("SpamTag") if t.get("tag") == SHADOW_TAG]
    rules = [r for r in cli.query("SpamRule") if r.get("name") == SHADOW_TAG]
    for rule in rules:
        cli.delete("SpamRule", rule["id"], what=SHADOW_TAG)
    for tag in tags:
        cli.delete("SpamTag", tag["id"], what=SHADOW_TAG)
    if not rules and not tags:
        print(f"  ok     no {SHADOW_TAG} objects")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--milter-host", default=os.environ.get("KLAR_MILTER_HOST", "127.0.0.1"))
    p.add_argument("--milter-port", type=int, default=int(os.environ.get("KLAR_MILTER_PORT", "8891")))
    p.add_argument(
        "--milter-id",
        default=None,
        help="when the milter moved: the id of the MtaMilter to point at the new endpoint, or 'new' to add one "
        "beside milters that are not Klar's",
    )
    p.add_argument(
        "--shadow", action="store_true", help="keep Stalwart scoring (never filing) for the comparison window"
    )
    p.add_argument("--dry-run", action="store_true", help="print the plan, write nothing")
    args = p.parse_args(argv)

    binary = os.environ.get("STALWART_CLI", "stalwart-cli")
    if not shutil.which(binary) and not Path(binary).exists():
        print(f"error: {binary} not found; install stalwart-cli or set STALWART_CLI", file=sys.stderr)
        return 2
    cli = Cli(binary, dry_run=args.dry_run)

    mode = "shadow (Stalwart scores, never files)" if args.shadow else "final (Stalwart's filter off)"
    print(f"[klar/stalwart] milter {args.milter_host}:{args.milter_port}, {mode}{' [dry run]' if args.dry_run else ''}")
    try:
        apply_milter(cli, args.milter_host, args.milter_port, args.milter_id)
        apply_singleton(cli, "SenderAuth", load_fragment("sender-auth.json"))
        apply_sieve(cli)
        apply_stage_data(cli, args.shadow)
        apply_shadow(cli, args.shadow)
        if cli.changed:
            cli.reload_settings()
        else:
            print("  nothing to do")
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
