"""Check that the installed scamgate code hasn't been modified.

A wheel install has a RECORD file with a SHA-256 for every file. The hook verifies scamgate's
own Python and config files against it at startup and fails closed if anything changed.
An editable/dev install (source checkout) has nothing to verify against, so it reports "dev"
and passes: run the hook from a pinned install (`uv tool install`) to get this protection.
"""

from __future__ import annotations

import base64
import hashlib
from importlib import metadata
from pathlib import Path


def _digest(path: Path) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest()).rstrip(b"=").decode()


def verify(entries: list[tuple[Path, str, str]]) -> tuple[bool, str]:
    problems = []
    for path, algo, expected in entries:
        if algo != "sha256":
            continue
        if not path.is_file():
            problems.append(f"missing: {path.name}")
        elif _digest(path) != expected:
            problems.append(f"modified: {path.name}")
    if problems:
        return False, "; ".join(problems[:5])
    return True, f"{len(entries)} files verified"


def _is_editable(dist: metadata.Distribution) -> bool:
    import json

    try:
        direct = json.loads(dist.read_text("direct_url.json") or "{}")
    except (FileNotFoundError, json.JSONDecodeError):
        return False
    return bool((direct.get("dir_info") or {}).get("editable"))


def check() -> tuple[bool, str]:
    try:
        dist = metadata.distribution("scamgate")
    except metadata.PackageNotFoundError:
        return True, "dev (not installed as a package)"
    if _is_editable(dist):
        return True, "dev (editable install, nothing to verify)"
    entries = []
    for f in dist.files or []:
        s = str(f).replace("\\", "/")
        if not s.startswith("scamgate/") or not f.hash or not s.endswith((".py", ".yaml", ".txt")):
            continue
        entries.append((Path(f.locate()), f.hash.mode, f.hash.value))
    if not entries:
        return True, "dev (no RECORD hashes)"
    return verify(entries)
