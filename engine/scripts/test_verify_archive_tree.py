#!/usr/bin/env python3
"""Regression checks for the pinned converter source-tree verifier."""
from __future__ import annotations

import os
import tempfile
import tarfile
from pathlib import Path

from verify_archive_tree import verify


def main() -> int:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        original = root / "package-v1"
        (original / "lib").mkdir(parents=True)
        (original / "tool.py").write_text("print('pinned')\n")
        (original / "lib/data.txt").write_text("bytes\n")
        archive = root / "package.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(original, arcname=original.name)

        source = root / "source"
        source.mkdir()
        with tarfile.open(archive, "r:gz") as bundle:
            for member in bundle.getmembers():
                parts = Path(member.name).parts
                if len(parts) <= 1:
                    continue
                member.name = str(Path(*parts[1:]))
                bundle.extract(member, source, filter="data")

        (source / "build-klar-tools").mkdir()
        (source / "build-klar-tools/generated.o").write_bytes(b"derived")
        (source / "lib/__pycache__").mkdir()
        (source / "lib/__pycache__/data.pyc").write_bytes(b"derived")
        os.chmod(source / "tool.py", 0o664)
        result = verify(archive, source, "build-klar-tools")
        assert result["pass"], result

        os.chmod(source / "tool.py", 0o755)
        result = verify(archive, source, "build-klar-tools")
        assert not result["pass"] and result["changed"] == ["tool.py"]
        os.chmod(source / "tool.py", 0o644)

        (source / "tool.py").write_text("print('tampered')\n")
        result = verify(archive, source, "build-klar-tools")
        assert not result["pass"] and result["changed"] == ["tool.py"]
        (source / "tool.py").write_text("print('pinned')\n")
        (source / "unexpected.txt").write_text("extra\n")
        result = verify(archive, source, "build-klar-tools")
        assert not result["pass"] and result["extra"] == ["unexpected.txt"]

    print("[test-verify-archive-tree] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
