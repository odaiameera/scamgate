"""Host normalisation shared by the rules and the feed lookups.

Browsers and curl accept hosts that look nothing like the domain they reach:
percent-encoded letters (`evilsh%6fp.com`), integer IPv4 (`3405803781`), hex or octal parts
(`0xcb007105`, `0313.0.0.1`). Normalise them so every check sees the real destination.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import unquote

_NUM_PART = re.compile(r"^(?:0x[0-9a-f]+|0[0-7]*|[1-9][0-9]*)$", re.I)


def _num(part: str) -> int:
    p = part.lower()
    if p.startswith("0x"):
        return int(p, 16)
    if len(p) > 1 and p.startswith("0"):
        return int(p, 8)
    return int(p)


def numeric_ipv4(host: str) -> str | None:
    """'3405803781', '0xcb007105', '0313.0.0.1', '203.0x0.113.5' -> dotted quad, else None.

    Follows inet_aton: 1-4 parts, the last part fills the remaining bytes.
    """
    h = host.strip("[]").rstrip(".")
    parts = h.split(".")
    if not 1 <= len(parts) <= 4 or not all(_NUM_PART.match(p) for p in parts):
        return None
    try:
        nums = [_num(p) for p in parts]
    except ValueError:
        return None
    *head, last = nums
    if any(n > 255 for n in head) or last >= 256 ** (4 - len(head)):
        return None
    value = 0
    for n in head:
        value = value * 256 + n
    value = value * 256 ** (4 - len(head)) + last
    return str(ipaddress.IPv4Address(value))


# Ideographic and halfwidth full stops: browsers read them as '.' in a host name.
_DOTS = str.maketrans({"。": ".", "．": ".", "｡": "."})


def canon_host(host: str) -> str:
    """Lowercase, percent-decoded, no trailing dot, numeric IPv4 in dotted form."""
    h = unicodedata.normalize("NFKC", unquote(host or "")).translate(_DOTS).strip().lower().rstrip(".")
    if h and not h.startswith("["):
        if (ip := numeric_ipv4(h)) is not None and h != ip:
            return ip
    return h
