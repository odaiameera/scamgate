"""Strip secrets before anything is written to disk.

Logs must be safe to read and share: no passwords, query-string values, card numbers,
full IBANs, emails or API keys.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

_LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_\-]{24,}(?![A-Za-z0-9])")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_IBAN = re.compile(r"\b([A-Z]{2}\d{2})(?:[ ]?[A-Z0-9]){10,30}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@([\w-]+(?:\.[\w-]+)+)\b")
_KV_SECRET = re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|otp|pin|cvv|cvc)(\s*[=:]\s*)(\S+)")
_KEYLIKE = re.compile(r"\b(sk|pk|ghp|gho|xox[bp]|AKIA)[-_A-Za-z0-9]{12,}\b")


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def _mask_cards(text: str) -> str:
    def repl(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        return "<card>" if 13 <= len(digits) <= 19 and _luhn_ok(digits) else m.group(0)
    return _CARD.sub(repl, text)


def redact_text(text: str, limit: int = 300) -> str:
    t = text or ""
    t = _KV_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", t)
    t = _KEYLIKE.sub("<key>", t)
    t = _mask_cards(t)
    t = _IBAN.sub(lambda m: f"{m.group(1)}<iban>", t)
    t = _EMAIL.sub(lambda m: f"<email>@{m.group(1)}", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t if len(t) <= limit else t[:limit] + "…"


def redact_url(url: str) -> str:
    """Keep scheme, host, port and path shape; drop userinfo, query values and fragment."""
    raw = (url or "").strip()
    try:
        p = urlsplit(raw if "://" in raw else "http://" + raw)
        host = p.hostname or ""
        port = f":{p.port}" if p.port else ""
    except ValueError:
        return "<unparseable-url>"
    user = "<user>@" if p.username else ""
    path = _LONG_TOKEN.sub("<token>", p.path)
    path = _mask_cards(path)
    query = "&".join(f"{k}=" for k, _ in parse_qsl(p.query, keep_blank_values=True))
    return urlunsplit((p.scheme, f"{user}{host}{port}", path, query, ""))
