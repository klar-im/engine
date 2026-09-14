#!/usr/bin/env python3
"""A stand-in for `stalwart-cli` that keeps its objects in a JSON file.

Speaks exactly the subset apply.py uses: `get <Obj> singleton --json`,
`query <Obj> --json` (one object per line, like the real CLI), `create <Obj>
--stdin`, `update <Obj> <id> --stdin`, `delete <Obj> --ids <id>`. State lives
at $FAKE_STALWART_STATE so a test can seed a server and read back what a run
did. Singletons start from Stalwart 0.16.18's defaults for the two fields
apply.py touches, copied from a live `get` on klar.im on 2026-09-13.
"""

from __future__ import annotations

import itertools
import json
import os
import sys
from pathlib import Path

STATE = Path(os.environ["FAKE_STALWART_STATE"])

# What `query <Obj> --json` prints per object on the real CLI (observed on
# klar.im, 2026-09-13): identifying fields and the id, nothing else.
SUMMARY = {
    "MtaMilter": ("hostname", "port", "id"),
    "SieveUserScript": ("name", "description", "id"),
    "SpamTag": ("tag", "score", "id"),
    "SpamRule": ("name", "id"),
}

DEFAULT_SINGLETONS = {
    "MtaStageData": {"enableSpamFilter": {"match": {}, "else": "is_empty(authenticated_as)"}, "id": "singleton"},
    "SenderAuth": {
        "dmarcVerify": {"match": {"0": {"if": "local_port == 25", "then": "relaxed"}}, "else": "disable"},
        "id": "singleton",
    },
}


def load() -> dict:
    if STATE.exists():
        return json.loads(STATE.read_text())
    return {"singletons": dict(DEFAULT_SINGLETONS), "objects": {}, "actions": []}


def save(state: dict) -> None:
    STATE.write_text(json.dumps(state, indent=1))


def main(argv: list[str]) -> int:
    state = load()
    verb, obj = argv[0], argv[1]
    rest = argv[2:]
    payload = json.loads(sys.stdin.read()) if "--stdin" in rest else None
    ids = itertools.count(sum(len(v) for v in state["objects"].values()) + 1)

    if verb == "get":
        ident = rest[0] if rest and not rest[0].startswith("--") else "singleton"
        if ident == "singleton":
            print(json.dumps(state["singletons"][obj]))
        else:
            print(json.dumps(next(i for i in state["objects"].get(obj, []) if i["id"] == ident)))
    elif verb == "query":
        # Like the real CLI: summary fields only. `get` has the full object.
        for item in state["objects"].get(obj, []):
            print(json.dumps({k: item[k] for k in SUMMARY.get(obj, ("id",)) if k in item}))
    elif verb == "create":
        if obj == "Action":
            state["actions"].append(payload["@type"])
        else:
            payload = {**payload, "id": f"{obj.lower()}-{next(ids)}"}
            if "score" in payload:
                # The real CLI prints a SpamTag score as a float (-100.0 on
                # klar.im for the -100 we sent); apply.py must read that as equal.
                payload["score"] = float(payload["score"])
            state["objects"].setdefault(obj, []).append(payload)
    elif verb == "update":
        ident = rest[0]
        if ident == "singleton":
            state["singletons"][obj].update(payload)
        else:
            for item in state["objects"].get(obj, []):
                if item["id"] == ident:
                    item.update(payload)
    elif verb == "delete":
        ident = rest[rest.index("--ids") + 1]
        state["objects"][obj] = [i for i in state["objects"].get(obj, []) if i["id"] != ident]
    else:
        print(f"fake stalwart-cli: unsupported {argv}", file=sys.stderr)
        return 2
    save(state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
