"""Local payee history, so payment checks don't rely on what the agent claims.

Stores salted hashes of the normalized payee name and account, never the values, plus hashes of
one-letter-deletion variants of the name's first word, so near-names ("Acme Trading Ltd",
"Acmee Ltd", Cyrillic "Acmе") still match a payee you've paid before without storing the name.
Only a person can add a payee (`scamgate record-payment`), and every line is signed.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from scamgate import guard
from scamgate.state import state_dir

_SUFFIXES = r"\b(ltd|limited|llc|inc|plc|gmbh|teoranta|dac|co|company|the|and|of)\b"
_GENERIC = {"bank", "the", "mr", "mrs", "ms", "dr", "st", "saint", "group", "services", "payments", "account"}
# Letters that look Latin in most fonts.
_CONFUSABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ϲ": "c", "0": "o", "1": "l",
})
_interactive = guard._interactive


def history_path() -> Path:
    return state_dir() / "payees.jsonl"


def _salt_path() -> Path:
    return state_dir() / "payees.salt"


def _salt(create: bool = False) -> bytes | None:
    p = _salt_path()
    if not p.exists():
        if not create:
            return None
        guard._private_write(p, secrets.token_hex(16))
    return p.read_text("utf-8").strip().encode()


def _fold(name: str) -> str:
    n = unicodedata.normalize("NFKC", name or "").lower().translate(_CONFUSABLE)
    n = "".join(c for c in unicodedata.normalize("NFKD", n) if not unicodedata.combining(c))
    return re.sub(_SUFFIXES, " ", n)


def norm_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", _fold(name))


def core_word(name: str) -> str:
    words = [w for w in re.split(r"[^a-z0-9]+", _fold(name)) if len(w) >= 3 and w not in _GENERIC]
    return words[0] if words else norm_name(name)


def _variants(word: str) -> set[str]:
    return {word} | {word[:i] + word[i + 1:] for i in range(len(word))} if len(word) >= 4 else {word}


def norm_account(account: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (account or "").upper())


def _h(kind: str, value: str, salt: bytes | None = None) -> str:
    s = salt if salt is not None else (_salt() or b"")
    return hashlib.sha256(s + kind.encode() + b"\0" + value.encode()).hexdigest()[:32]


@dataclass
class PayeeFacts:
    has_history: bool
    known_name: bool
    known_account: bool
    name_seen_with_other_account: bool
    near_name: bool = False
    account_under_other_name: bool = False
    history_broken: bool = False


def _rows() -> list[dict]:
    p = history_path()
    if not p.exists():
        return []
    out = []
    for line in p.read_text("utf-8").splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and guard.verify(rec):
            out.append(rec)
    return out


def lookup(name: str, account: str) -> PayeeFacts:
    p = history_path()
    if p.exists() and p.stat().st_size and (_salt() is None or not guard.key_exists()):
        return PayeeFacts(True, False, False, False, history_broken=True)
    rows = _rows()
    if not rows:
        return PayeeFacts(False, False, False, False)
    nh, ah = _h("name", norm_name(name)), _h("acct", norm_account(account))
    near = {_h("core", v) for v in _variants(core_word(name))}
    exact_name = [r for r in rows if r.get("name") == nh]
    near_name = [r for r in rows if r.get("name") != nh and near & set(r.get("core") or [])]
    same_acct = [r for r in rows if r.get("account") == ah]
    known_account = any(r in exact_name or r in near_name for r in same_acct)
    return PayeeFacts(
        has_history=True,
        known_name=bool(exact_name),
        known_account=known_account,
        name_seen_with_other_account=bool(exact_name) and not known_account,
        near_name=bool(near_name) and not exact_name and not known_account,
        account_under_other_name=bool(same_acct) and not known_account,
    )


def record(name: str, account: str) -> None:
    guard.require_human("Recording a payee", interactive=lambda: _interactive())
    salt = _salt(create=True)
    rec = guard.sign({"v": 2, "name": _h("name", norm_name(name), salt), "account": _h("acct", norm_account(account), salt),
                      "core": sorted(_h("core", v, salt) for v in _variants(core_word(name))),
                      "ts": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    guard.append_private(history_path(), json.dumps(rec))
