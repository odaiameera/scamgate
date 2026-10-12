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


_KNOWN_PTH = {"distutils-precedence.pth", "_virtualenv.pth"}


def unexpected_pth(dirs: list[Path]) -> list[str]:
    """.pth files no installed package owns. Python runs `import` lines in them at every start."""
    out = []
    for d in dirs:
        d = Path(d)
        if not d.is_dir():
            continue
        owned = set()
        for rec in d.glob("*.dist-info/RECORD"):
            for line in rec.read_text("utf-8", errors="replace").splitlines():
                name = line.split(",", 1)[0].replace("\\", "/")
                if name.endswith(".pth") and "/" not in name:
                    owned.add(name)
        for p in sorted(d.glob("*.pth")):
            if p.name not in owned and p.name not in _KNOWN_PTH and not p.name.startswith("__editable__"):
                out.append(p.name)
    return out


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
    ok, why = verify(entries)
    if ok and (extra := unexpected_pth([Path(dist.locate_file(""))])):
        return False, f"unknown startup file(s) next to scamgate: {', '.join(extra[:3])}"
    return ok, why
