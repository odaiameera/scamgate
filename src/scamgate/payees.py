"""Local payee history, so payment checks don't rely on what the agent claims.

Stores salted SHA-256 hashes of the normalized payee name and account, never the values.
`scamgate record-payment` adds a payee after a human-confirmed payment.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from scamgate.state import ensure_state_dir, state_dir

_SUFFIXES = r"\b(ltd|limited|llc|inc|plc|gmbh|teoranta|dac|co|company|the)\b"


def history_path() -> Path:
    return state_dir() / "payees.jsonl"


def _salt() -> bytes:
    p = state_dir() / "payees.salt"
    if not p.exists():
        ensure_state_dir()
        p.write_text(secrets.token_hex(16), encoding="utf-8")
    return p.read_text("utf-8").strip().encode()


def norm_name(name: str) -> str:
    n = re.sub(_SUFFIXES, " ", (name or "").lower())
    return re.sub(r"[^a-z0-9]", "", n)


def norm_account(account: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (account or "").upper())


def _h(kind: str, value: str) -> str:
    return hashlib.sha256(_salt() + kind.encode() + b"\0" + value.encode()).hexdigest()[:32]


@dataclass
class PayeeFacts:
    has_history: bool
    known_name: bool
    known_account: bool
    name_seen_with_other_account: bool


def _rows() -> list[dict]:
    p = history_path()
    if not p.exists():
        return []
    out = []
    for line in p.read_text("utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def lookup(name: str, account: str) -> PayeeFacts:
    rows = _rows()
    if not rows:
        return PayeeFacts(False, False, False, False)
    nh, ah = _h("name", norm_name(name)), _h("acct", norm_account(account))
    names = {r.get("name") for r in rows}
    pairs = {(r.get("name"), r.get("account")) for r in rows}
    known_name = nh in names
    known_account = (nh, ah) in pairs
    return PayeeFacts(True, known_name, known_account, known_name and not known_account)


def record(name: str, account: str) -> None:
    ensure_state_dir()
    rec = {"name": _h("name", norm_name(name)), "account": _h("acct", norm_account(account)),
           "ts": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    with history_path().open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
