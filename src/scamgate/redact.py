"""Strip secrets before anything is written to disk.

Logs must be safe to read and share: no passwords, query-string values, card numbers,
full IBANs, emails, API keys, tokens or seed phrases.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

_LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_\-]{24,}(?![A-Za-z0-9])")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_IBAN = re.compile(r"(?i)\b([A-Z]{2}\d{2})((?:[ ]?[A-Z0-9]){10,30})\b")
_EMAIL = re.compile(r"\b[\w.+-]+@([\w-]+(?:\.[\w-]+)+)\b")
_KV_SECRET = re.compile(r"(?i)\b(password|passwd|passphrase|passcode|pwd|secret|token|api[_-]?key|otp|pin|cvv|cvc)"
                        r"(\s*[=:]\s*|\s+(?:is|was|=)\s+)(\S+)")
_KEYLIKE = re.compile(r"\b(?:sk|pk|rk|ghp|gho|ghs|ghu|ghr|github_pat|glpat|xox[abprs]|AKIA|ASIA|AIza|hf|npm|pypi)"
                      r"[-_][-_A-Za-z0-9]{10,}|\bAKIA[0-9A-Z]{16}\b|\bAIza[-_A-Za-z0-9]{20,}")
_JWT = re.compile(r"\beyJ[\w-]{4,}\.[\w-]{4,}\.[\w-]{4,}")
_HIGH_ENTROPY = re.compile(r"(?<![\w/+=-])(?=[\w/+=-]*[a-z])(?=[\w/+=-]*[A-Z])(?=[\w/+=-]*\d)[\w/+=-]{30,}(?![\w/+=-])")
_SEED = re.compile(r"(?i)\b(seed(?:\s*phrase)?|mnemonic|recovery\s*(?:phrase|words)|secret\s*(?:phrase|words))"
                   r"(\W{0,3})((?:[a-z]{3,8}[\s,]+){11,23}[a-z]{3,8})\b")


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


def iban_ok(iban: str) -> bool:
    s = re.sub(r"\s", "", iban).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    digits = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    return int(digits) % 97 == 1


def _mask_cards(text: str) -> str:
    def repl(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        return "<card>" if 13 <= len(digits) <= 19 and _luhn_ok(digits) else m.group(0)
    return _CARD.sub(repl, text)


def _mask_iban(text: str) -> str:
    def repl(m: re.Match) -> str:
        whole = m.group(0)
        if whole.isupper() or iban_ok(whole):  # lowercase only when the checksum proves it's an IBAN
            return f"{m.group(1).upper()}<iban>"
        return whole
    return _IBAN.sub(repl, text)


def _mask_secrets(t: str) -> str:
    t = _SEED.sub(lambda m: f"{m.group(1)}{m.group(2)}<seed>", t)
    t = _KV_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", t)
    t = _JWT.sub("<jwt>", t)
    t = _KEYLIKE.sub("<key>", t)
    t = _HIGH_ENTROPY.sub("<secret>", t)
    t = _mask_cards(t)
    t = _mask_iban(t)
    return _EMAIL.sub(lambda m: f"<email>@{m.group(1)}", t)


def redact_text(text: str, limit: int = 300) -> str:
    t = _mask_secrets(text or "")
    t = re.sub(r"\s+", " ", t).strip()
    return t if len(t) <= limit else t[:limit] + "…"


def redact_url(url: str) -> str:
    """Keep scheme, host, port and path shape; drop userinfo, query values, fragment and secrets in the path."""
    raw = (url or "").strip()
    try:
        p = urlsplit(raw if "://" in raw else "http://" + raw)
        host = p.hostname or ""
        port = f":{p.port}" if p.port else ""
    except ValueError:
        return "<unparseable-url>"
    user = "<user>@" if p.username else ""
    path = _mask_secrets(p.path)
    path = _LONG_TOKEN.sub("<token>", path)
    query = "&".join(f"{k}=" for k, _ in parse_qsl(p.query, keep_blank_values=True))
    return urlunsplit((p.scheme, f"{user}{host}{port}", path, query, ""))
