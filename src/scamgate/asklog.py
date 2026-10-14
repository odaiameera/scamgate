"""Ask log: every gated call scamgate escalated or blocked, plus what happened next.

Two append-only JSONL files in the state dir:
- asks.jsonl: one entry per flagged call (redacted targets, rules, score, agent's stated reason)
- outcomes.jsonl: whether the call then ran (human approved) or didn't (human refused / blocked)

The agent's stated reason is stored for a human to read. It is marked untrusted and is never used
to change rules automatically: injected page text can write it.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .redact import redact_text, redact_url
from .state import ensure_state_dir, state_dir


def log_path() -> Path:
    return state_dir() / "asks.jsonl"


def outcomes_path() -> Path:
    return state_dir() / "outcomes.jsonl"


def _pending_path(key: str) -> Path:
    return state_dir() / "pending" / key


def _append(path: Path, rec: dict) -> None:
    ensure_state_dir()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def make_key(session: str, call_id: str) -> str:
    return hashlib.sha256(f"{session}\0{call_id}".encode()).hexdigest()[:16]


def log_check(*, tool: str, decision: str, risk_score: int, rule_ids: list[str], targets: list[str],
              hosts: list[str], stated_reason: str | None, session: str, call_id: str,
              agent: str = "hermes") -> str:
    key = make_key(session, call_id or f"{time.time_ns()}")
    _append(log_path(), {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "key": key,
        "agent": agent,
        "tool": tool,
        "decision": decision,
        "risk_score": risk_score,
        "rules": sorted(set(rule_ids)),
        "hosts": sorted(set(hosts)),
        "targets": [redact_url(t) for t in targets[:5]],
        "stated_reason": redact_text(stated_reason or "", limit=80),
        "stated_reason_trust": "untrusted",
    })
    if decision in ("approve", "ask"):
        p = _pending_path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("", encoding="utf-8")
    return key


def record_outcome(key: str, outcome: str) -> bool:
    """outcome: 'ran' (human approved) or 'not_run' (refused, timed out, or blocked)."""
    p = _pending_path(key)
    if not p.exists():
        return False
    _append(outcomes_path(), {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                              "key": key, "outcome": outcome})
    p.unlink(missing_ok=True)
    return True


def _read(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text("utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def read_entries() -> list[dict]:
    return _read(log_path())


def read_outcomes() -> dict[str, str]:
    return {o["key"]: o["outcome"] for o in _read(outcomes_path()) if "key" in o}


@dataclass
class ReviewRow:
    host: str
    asks: int = 0
    blocks: int = 0
    ran: int = 0
    not_run: int = 0
    pending: int = 0
    rules: dict[str, int] = field(default_factory=dict)
    tools: dict[str, int] = field(default_factory=dict)
    sample_reasons: list[str] = field(default_factory=list)


def summarize(days: int = 7, now: datetime | None = None) -> list[ReviewRow]:
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)
    outcomes = read_outcomes()
    rows: dict[str, ReviewRow] = {}
    rule_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    tool_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for e in read_entries():
        try:
            ts = datetime.fromisoformat(e["ts"])
        except (KeyError, ValueError):
            continue
        if ts < cutoff:
            continue
        for host in e.get("hosts") or ["<no host>"]:
            row = rows.setdefault(host, ReviewRow(host))
            if e.get("decision") == "block":
                row.blocks += 1
            else:
                row.asks += 1
                o = outcomes.get(e.get("key", ""))
                if o == "ran":
                    row.ran += 1
                elif o == "not_run":
                    row.not_run += 1
                else:
                    row.pending += 1
            for r in e.get("rules", []):
                rule_counts[host][r] += 1
            tool_counts[host][e.get("tool", "?")] += 1
            reason = e.get("stated_reason")
            if reason and reason not in row.sample_reasons and len(row.sample_reasons) < 3:
                row.sample_reasons.append(reason)
    for host, row in rows.items():
        row.rules = dict(sorted(rule_counts[host].items(), key=lambda kv: -kv[1]))
        row.tools = dict(sorted(tool_counts[host].items(), key=lambda kv: -kv[1]))
    return sorted(rows.values(), key=lambda r: (-(r.asks + r.blocks), r.host))
