#!/usr/bin/env python3
"""apply.py against the fake stalwart-cli: converges a fresh server, is a no-op
the second time, and leaving shadow mode removes exactly what shadow added.

    make stalwart/test-unit
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
APPLY = HERE.parent / "scripts" / "apply.py"
FAKE = HERE / "fake_stalwart_cli.py"
SIEVE = HERE.parent / "sieve" / "klar.sieve"


def invoke(state: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    """apply.py against the fake CLI, whatever its exit code."""
    env = {**os.environ, "STALWART_CLI": str(FAKE), "FAKE_STALWART_STATE": str(state)}
    return subprocess.run(  # noqa: S603
        [sys.executable, str(APPLY), *args], env=env, capture_output=True, text=True, check=False
    )


def run(state: pathlib.Path, *args: str) -> str:
    proc = invoke(state, *args)
    if proc.returncode != 0:
        raise RuntimeError(f"apply.py failed: {proc.stderr}\n{proc.stdout}")
    return proc.stdout


def load(state: pathlib.Path) -> dict:
    return json.loads(state.read_text())


def check_fresh_server_converges(state: pathlib.Path) -> list[str]:
    out = run(state, "--shadow", "--milter-host", "klar-milterd", "--milter-port", "8891")
    s = load(state)
    problems = []
    milters = s["objects"].get("MtaMilter", [])
    if len(milters) != 1 or milters[0]["hostname"] != "klar-milterd" or milters[0]["port"] != 8891:
        problems.append(f"expected one MtaMilter at klar-milterd:8891, got {milters}")
    if milters and milters[0].get("tempFailOnError") is not False:
        problems.append("tempFailOnError must be false (fail_open, never defer)")
    if milters and "_comment" in milters[0]:
        problems.append("the _comment key leaked into the object")
    if s["singletons"]["SenderAuth"]["dmarcVerify"]["match"]["0"]["then"] != "strict":
        problems.append("SenderAuth.dmarcVerify must be strict on port 25")
    if s["singletons"]["MtaStageData"]["enableSpamFilter"]["else"] != "is_empty(authenticated_as)":
        problems.append("--shadow must leave enableSpamFilter alone")
    scripts = s["objects"].get("SieveUserScript", [])
    if len(scripts) != 1 or scripts[0]["contents"] != SIEVE.read_text().rstrip("\n") or not scripts[0]["isActive"]:
        problems.append("the global user script 'klar' must carry sieve/klar.sieve, active")
    tags = [t["tag"] for t in s["objects"].get("SpamTag", [])]
    rules = [r["name"] for r in s["objects"].get("SpamRule", [])]
    if tags != ["KLAR_SHADOW"] or rules != ["KLAR_SHADOW"]:
        problems.append(f"shadow must add exactly one tag and one rule, got {tags} {rules}")
    if s["actions"] != ["ReloadSettings"]:
        problems.append(f"one ReloadSettings after changes, got {s['actions']}")
    if "create MtaMilter" not in out:
        problems.append("the run must say what it created")
    return problems


def check_second_run_is_a_noop(state: pathlib.Path) -> list[str]:
    before = load(state)
    out = run(state, "--shadow", "--milter-host", "klar-milterd", "--milter-port", "8891")
    after = load(state)
    problems = []
    if after["objects"] != before["objects"] or after["singletons"] != before["singletons"]:
        problems.append("a second identical run changed objects")
    if after["actions"] != before["actions"]:
        problems.append("a no-op run must not ReloadSettings")
    if "nothing to do" not in out:
        problems.append("a no-op run must say so")
    return problems


def check_shadow_drift_is_put_back(state: pathlib.Path) -> list[str]:
    """A hand edit to the shadow tag's score or the rule's enable flag is what
    lets Stalwart start filing again; the reconcile must restore the contents,
    not just see that the names exist."""
    s = load(state)
    s["objects"]["SpamTag"][0]["score"] = -1
    s["objects"]["SpamRule"][0]["enable"] = False
    state.write_text(json.dumps(s))
    out = run(state, "--shadow", "--milter-host", "klar-milterd", "--milter-port", "8891")
    s = load(state)
    problems = []
    if s["objects"]["SpamTag"][0]["score"] != -100:
        problems.append(f"the tag score must go back to -100, got {s['objects']['SpamTag'][0]['score']}")
    if s["objects"]["SpamRule"][0]["enable"] is not True:
        problems.append("the rule must be re-enabled")
    if len(s["objects"]["SpamTag"]) != 1 or len(s["objects"]["SpamRule"]) != 1:
        problems.append("drift repair must patch in place, not add a second object")
    if "update SpamTag" not in out or "update SpamRule" not in out:
        problems.append(f"the run must say what it repaired, got:\n{out}")
    return problems


def check_a_moved_milter_is_refused_then_moved(state: pathlib.Path) -> list[str]:
    """Stalwart gives a milter no name, so a milter at a new address looks like
    a missing one. Creating it would leave the old endpoint active (two
    milters, one timing out on every message): refuse, then move on request."""
    problems = []
    proc = invoke(state, "--shadow", "--milter-host", "10.88.0.7", "--milter-port", "8891")
    milters = load(state)["objects"]["MtaMilter"]
    if proc.returncode == 0 or "--milter-id" not in proc.stderr:
        problems.append(f"a new endpoint beside an existing milter must be refused with the remedy, got {proc.stderr!r}")
    if len(milters) != 1:
        problems.append(f"the refusal must create nothing, got {milters}")
    run(state, "--shadow", "--milter-host", "10.88.0.7", "--milter-port", "8891", "--milter-id", milters[0]["id"])
    milters = load(state)["objects"]["MtaMilter"]
    if len(milters) != 1 or milters[0]["hostname"] != "10.88.0.7":
        problems.append(f"--milter-id must move the one milter, got {milters}")
    # And back, so the later checks see the address they expect.
    run(state, "--shadow", "--milter-host", "klar-milterd", "--milter-port", "8891", "--milter-id", milters[0]["id"])
    return problems


def check_leaving_shadow(state: pathlib.Path) -> list[str]:
    run(state, "--milter-host", "klar-milterd", "--milter-port", "8891")
    s = load(state)
    problems = []
    if s["objects"].get("SpamTag") or s["objects"].get("SpamRule"):
        problems.append("leaving shadow must delete the KLAR_SHADOW tag and rule")
    if s["singletons"]["MtaStageData"]["enableSpamFilter"]["else"] != "false":
        problems.append("the final state disables Stalwart's spam filter")
    if len(s["objects"].get("MtaMilter", [])) != 1:
        problems.append("leaving shadow must not touch the milter")
    if s["actions"][-1] != "ReloadSettings":
        problems.append("the switch must be followed by ReloadSettings")
    return problems


def check_back_to_shadow_turns_the_filter_on(state: pathlib.Path) -> list[str]:
    """After "final" the filter is off. A return to shadow (another comparison
    window) needs Stalwart scoring again, or every X-Spam-Result is missing and
    the audit reads an idle filter as a perfect one. Only the exact "off" this
    script wrote is put back; an operator's own expression stays."""
    problems = []
    run(state, "--shadow", "--milter-host", "klar-milterd", "--milter-port", "8891")
    s = load(state)
    if s["singletons"]["MtaStageData"]["enableSpamFilter"]["else"] != "is_empty(authenticated_as)":
        problems.append(f"shadow after final must turn the filter back on, got {s['singletons']['MtaStageData']}")
    if [t["tag"] for t in s["objects"].get("SpamTag", [])] != ["KLAR_SHADOW"]:
        problems.append("shadow after final must recreate the tag")
    custom = {"match": {}, "else": "remote_ip != '10.0.0.1'"}
    s["singletons"]["MtaStageData"]["enableSpamFilter"] = custom
    state.write_text(json.dumps(s))
    run(state, "--shadow", "--milter-host", "klar-milterd", "--milter-port", "8891")
    if load(state)["singletons"]["MtaStageData"]["enableSpamFilter"] != custom:
        problems.append("an operator's own enableSpamFilter expression must be left alone under --shadow")
    return problems


def check_dry_run_writes_nothing() -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        state = pathlib.Path(tmp) / "state.json"
        out = run(state, "--dry-run")
        s = load(state)
        problems = []
        untouched = s["singletons"]["MtaStageData"]["enableSpamFilter"]["else"] == "is_empty(authenticated_as)"
        if s["objects"] or s["actions"] or not untouched:
            problems.append("--dry-run must write nothing")
        if "create MtaMilter" not in out or "[dry run]" not in out:
            problems.append("--dry-run must still print the plan")
        return problems


def main() -> int:
    failed = False
    with tempfile.TemporaryDirectory() as tmp:
        state = pathlib.Path(tmp) / "state.json"
        checks = [
            ("a fresh server converges under --shadow", check_fresh_server_converges(state)),
            ("a second run is a no-op", check_second_run_is_a_noop(state)),
            ("drifted shadow objects are put back", check_shadow_drift_is_put_back(state)),
            ("a moved milter is refused, then moved with --milter-id", check_a_moved_milter_is_refused_then_moved(state)),
            ("leaving shadow removes what shadow added and turns the filter off", check_leaving_shadow(state)),
            ("back to shadow turns the filter on, an operator's expression stays", check_back_to_shadow_turns_the_filter_on(state)),
            ("--dry-run writes nothing", check_dry_run_writes_nothing()),
        ]
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
