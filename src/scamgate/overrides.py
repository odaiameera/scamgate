"""Human-approved overrides, promoted from the ask log with `scamgate promote`.

Rules for overrides, so the gate can't be trained by an attacker:
- Only a person can add them: `add()` refuses agent environments and non-interactive callers,
  whether it's called from the CLI or imported directly.
- Every line is signed (see guard.py). Lines written any other way are ignored.
- `deny` covers an exact host and its subdomains.
- `allow` is narrow: one exact host (no subdomains) AND one named rule. It waives only that rule's
  points for that host. It never waives known-bad feeds, the blocklist, intent checks or your own deny.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from . import guard
from .state import state_dir

NEVER_WAIVED = {"url.known_bad_feed", "url.blocklist", "url.override", "url.intent_mismatch"}
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
_interactive = guard._interactive


def overrides_path() -> Path:
    return state_dir() / "overrides.jsonl"


def _check_host(host: str) -> str:
    h = (host or "").strip().lower().rstrip(".")
    if not _HOST.match(h):
        raise ValueError(f"not an exact host name: {host!r} (no wildcards, schemes or paths)")
    return h


def add(host: str, decision: str, *, rule: str | None = None, note: str = "") -> dict:
    h = _check_host(host)
    if decision not in ("allow", "deny"):
        raise ValueError("decision must be 'allow' or 'deny'")
    if decision == "allow" and not rule:
        raise ValueError("an allow override needs --rule: it waives one rule on one host")
    if decision == "allow" and rule in NEVER_WAIVED:
        raise ValueError(f"{rule} can't be waived: known-bad lists, your blocklist and intent checks always apply")
    guard.require_human("Adding a scamgate override", interactive=lambda: _interactive())
    rec = guard.sign({"host": h, "decision": decision, "rule": rule if decision == "allow" else None,
                      "note": note[:200], "added_by": "human-cli",
                      "added_at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    guard.append_private(overrides_path(), json.dumps(rec))
    return rec


def load() -> list[dict]:
    return load_checked()[0]


def load_checked() -> tuple[list[dict], int]:
    """(rules that verify, number of lines that don't). A missing or changed key fails every line,
    and the engine says so rather than dropping your rules silently."""
    p = overrides_path()
    if not p.exists():
        return [], 0
    out, bad = [], 0
    for line in p.read_text("utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            bad += 1
            continue
        if (isinstance(rec, dict) and rec.get("host") and rec.get("decision") in ("allow", "deny")
                and guard.verify(rec)):
            out.append(rec)
        else:
            bad += 1
    return out, bad


def deny_match(host: str, items: list[dict]) -> dict | None:
    for o in items:
        if o["decision"] == "deny" and (host == o["host"] or host.endswith("." + o["host"])):
            return o
    return None


def waived_rules(host: str, items: list[dict]) -> set[str]:
    return {o["rule"] for o in items
            if o["decision"] == "allow" and o.get("rule") and host == o["host"]} - NEVER_WAIVED
