#!/usr/bin/env python3
"""Verify an extracted source tree against its immutable tar archive."""
from __future__ import annotations

import argparse
import hashlib
import json
import stat
import tarfile
from pathlib import Path, PurePosixPath


DERIVED_NAMES = {"__pycache__"}
DERIVED_SUFFIXES = {".pyc"}


def entry_digest(kind: str, relative: str, mode: int, payload: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(kind.encode("ascii"))
    digest.update(b"\0")
    digest.update(relative.encode("utf-8"))
    digest.update(b"\0")
    # GitHub source archives use group-writable modes (664/775), while the
    # extracted tree is normalized by the local umask (644/755).  Preserve the
    # only mode information that affects how these sources are consumed.
    digest.update(f"{mode & 0o111:o}".encode("ascii"))
    digest.update(b"\0")
    digest.update(payload)
    return digest.digest()


def allowed_derived(relative: PurePosixPath, excluded_root: str) -> bool:
    return bool(
        relative.parts
        and (
            relative.parts[0] == excluded_root
            or any(part in DERIVED_NAMES for part in relative.parts)
            or relative.suffix in DERIVED_SUFFIXES
        )
    )


def archive_entries(archive: Path) -> dict[str, bytes]:
    entries: dict[str, bytes] = {}
    roots: set[str] = set()
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            parts = PurePosixPath(member.name).parts
            if not parts:
                continue
            roots.add(parts[0])
            if len(parts) == 1 or member.isdir():
                continue
            relative = PurePosixPath(*parts[1:]).as_posix()
            if member.isfile():
                extracted = bundle.extractfile(member)
                if extracted is None:
                    raise ValueError(f"cannot read archive member {member.name}")
                payload = extracted.read()
                kind = "file"
            elif member.issym():
                payload = member.linkname.encode("utf-8")
                kind = "symlink"
            else:
                raise ValueError(
                    f"unsupported archive member type for {member.name}"
                )
            if relative in entries:
                raise ValueError(f"duplicate archive path after root stripping: {relative}")
            entries[relative] = entry_digest(
                kind, relative, stat.S_IMODE(member.mode), payload
            )
    if len(roots) != 1:
        raise ValueError(f"archive must contain exactly one root, got {sorted(roots)}")
    if not entries:
        raise ValueError("archive contains no source files")
    return entries


def local_entries(source: Path, excluded_root: str) -> dict[str, bytes]:
    entries: dict[str, bytes] = {}
    for path in sorted(source.rglob("*")):
        relative_path = PurePosixPath(path.relative_to(source).as_posix())
        if allowed_derived(relative_path, excluded_root) or path.is_dir():
            continue
        relative = relative_path.as_posix()
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if path.is_symlink():
            payload = path.readlink().as_posix().encode("utf-8")
            kind = "symlink"
        elif path.is_file():
            payload = path.read_bytes()
            kind = "file"
        else:
            raise ValueError(f"unsupported local source entry: {path}")
        entries[relative] = entry_digest(kind, relative, mode, payload)
    return entries


def collection_digest(entries: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name, value in sorted(entries.items()):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(value)
    return digest.hexdigest()


def verify(archive: Path, source: Path, excluded_root: str) -> dict:
    if not archive.is_file():
        raise ValueError(f"source archive missing: {archive}")
    if not source.is_dir():
        raise ValueError(f"extracted source directory missing: {source}")
    expected = archive_entries(archive)
    observed = local_entries(source, excluded_root)
    missing = sorted(set(expected) - set(observed))
    extra = sorted(set(observed) - set(expected))
    changed = sorted(
        name for name in set(expected) & set(observed)
        if expected[name] != observed[name]
    )
    result = {
        "archive_tree_sha256": collection_digest(expected),
        "local_tree_sha256": collection_digest(observed),
        "entries": len(expected),
        "missing": missing,
        "extra": extra,
        "changed": changed,
        "pass": not missing and not extra and not changed,
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--exclude", default="build-klar-tools")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = verify(args.archive, args.source, args.exclude)
    except (OSError, ValueError, tarfile.TarError) as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(
            f"source archive tree: {'PASS' if result['pass'] else 'FAIL'} "
            f"({result['entries']} entries, {result['archive_tree_sha256']})"
        )
        for key in ("missing", "extra", "changed"):
            if result[key]:
                print(f"  {key}: {result[key]}")
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
