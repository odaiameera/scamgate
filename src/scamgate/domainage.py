"""Domain age from RDAP, for `url.domain_age`. Off by default; opt in with SCAMGATE_RDAP.

New domains are a strong scam-shop signal, but looking one up means asking the domain's registry,
which tells the registry which site you're about to visit. So it's your call:

- `SCAMGATE_RDAP=off` (default): no lookups, the rule never fires.
- `SCAMGATE_RDAP=cache`: use ages already in the cache (from `scamgate domain-age HOST` or an
  earlier live lookup); never go online.
- `SCAMGATE_RDAP=live`: look up unknown domains (3 s timeout) and cache the result.

The registry list comes from IANA's RDAP bootstrap file (data.iana.org/rdap/dns.json), cached for
30 days. Ages are cached for a year; failed or unknown lookups for 7 days, so a domain that won't
answer doesn't slow every call. Any error means "no answer", never a verdict.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

ENV_RDAP = "SCAMGATE_RDAP"
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
TIMEOUT_S = 3
BOOTSTRAP_TTL = timedelta(days=30)
KNOWN_TTL = timedelta(days=365)
UNKNOWN_TTL = timedelta(days=7)


def mode() -> str:
    m = (os.environ.get(ENV_RDAP) or "off").strip().lower()
    return m if m in ("off", "cache", "live") else "off"


def _cache_path() -> Path:
    from .feeds import cache_dir

    return cache_dir() / "rdap.json"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _load() -> dict:
    try:
        data = json.loads(_cache_path().read_text("utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data: dict) -> None:
    p = _cache_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=1, sort_keys=True), "utf-8")
        tmp.replace(p)
    except OSError:
        pass  # a read-only cache just means no caching


def _http_get(url: str) -> str:
    import urllib.request

    from .feeds import USER_AGENT

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:  # noqa: S310
        return resp.read(2_000_000).decode("utf-8", "replace")


def _parse_ts(s: str) -> datetime | None:
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _rdap_base(tld: str, data: dict, fetch: Callable[[str], str]) -> str | None:
    boot = data.get("_bootstrap") or {}
    fetched = _parse_ts(boot.get("fetched_at", ""))
    if not boot.get("services") or not fetched or _now() - fetched > BOOTSTRAP_TTL:
        try:
            services = json.loads(fetch(BOOTSTRAP_URL)).get("services", [])
            boot = {"fetched_at": _now().isoformat(timespec="seconds"), "services": services}
            data["_bootstrap"] = boot
        except Exception:
            if not boot.get("services"):
                return None
    for tlds, urls in boot.get("services", []):
        if tld in tlds and urls:
            https = [u for u in urls if u.startswith("https://")]
            return (https or urls)[0].rstrip("/") + "/"
    return None


def registration_date(rdap_json: str) -> datetime | None:
    try:
        doc = json.loads(rdap_json)
    except ValueError:
        return None
    for ev in doc.get("events", []) if isinstance(doc, dict) else []:
        if isinstance(ev, dict) and ev.get("eventAction") == "registration":
            return _parse_ts(ev.get("eventDate", ""))
    return None


def lookup(domain: str, *, live: bool | None = None, fetch: Callable[[str], str] | None = None) -> int | None:
    """Age of `domain` in days, or None if unknown. `live` overrides SCAMGATE_RDAP."""
    domain = (domain or "").strip().lower().rstrip(".")
    try:
        domain = domain.encode("idna").decode("ascii")  # registries take the xn-- form
    except UnicodeError:
        return None
    if not _HOSTNAME.match(domain):
        return None  # only a plain host name goes into the registry URL
    m = mode()
    allow_net = m == "live" if live is None else live
    if m == "off" and live is None:
        return None
    data = _load()
    hit = data.get(domain)
    if isinstance(hit, dict):
        checked = _parse_ts(hit.get("checked_at", ""))
        created = _parse_ts(hit.get("created") or "")
        ttl = KNOWN_TTL if created else UNKNOWN_TTL
        if checked and _now() - checked < ttl:
            return (_now() - created).days if created else None
    if not allow_net:
        return None
    fetch = fetch or _http_get
    created = None
    base = _rdap_base(domain.rsplit(".", 1)[1], data, fetch)
    if base:
        try:
            created = registration_date(fetch(base + "domain/" + domain))
        except Exception:
            created = None
    data[domain] = {"created": created.isoformat(timespec="seconds") if created else None,
                    "checked_at": _now().isoformat(timespec="seconds")}
    _save(data)
    return (_now() - created).days if created else None
