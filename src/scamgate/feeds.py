"""Known-bad-link feeds: download into a local cache, then look up offline.

`update_feeds()` is the only code path that touches the network (`scamgate update-feeds`, and the
Hermes plugin's refresh in refresh.py). Checks only read the cache. Each feed is stored as its own normalized file, so every entry keeps its source,
and `meta.json` records when each feed was last fetched successfully.

Cache dir: $SCAMGATE_CACHE_DIR, else $XDG_CACHE_HOME/scamgate, else ~/.cache/scamgate.
"""

from __future__ import annotations

import csv
import io
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlsplit, urlunsplit

from .hostnorm import canon_host

ENV_CACHE_DIR = "SCAMGATE_CACHE_DIR"
ENV_URLHAUS_KEY = "SCAMGATE_URLHAUS_AUTH_KEY"
USER_AGENT = "scamgate/0.3 (+https://github.com/odaiameera/scamgate)"
STALE_AFTER_HOURS = 24
REFRESH_HINT = ("Refresh them with `scamgate update-feeds`, or with `/scamgate update` "
                "(`hermes scamgate update-feeds` in a terminal) when scamgate is a Hermes plugin.")


def cache_dir() -> Path:
    if env := os.environ.get(ENV_CACHE_DIR):
        return Path(env).expanduser()
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "scamgate"


# ---------------------------------------------------------------- normalization

def normalize_url(url: str) -> str | None:
    """Canonical form for exact matching: lowercase scheme+host, no default port,
    no fragment, no trailing slash on the path. Path and query are kept as-is."""
    raw = url.strip()
    if not raw or raw.startswith("#"):
        return None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        p = urlsplit(raw)
        host = canon_host(p.hostname or "")
        port = p.port
    except ValueError:
        return None
    if not host:
        return None
    scheme = p.scheme.lower()
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    path = p.path.rstrip("/")
    # http and https variants of the same URL are treated as the same link.
    if scheme in ("http", "https"):
        scheme = "http"
    return urlunsplit((scheme, netloc, path, p.query, ""))


def normalize_host(value: str) -> str | None:
    v = value.strip().lower()
    if not v or v.startswith("#"):
        return None
    if "://" in v:
        try:
            v = urlsplit(v).hostname or ""
        except ValueError:
            return None
    v = canon_host(v.split("/", 1)[0].split(":", 1)[0])
    if not v or "." not in v or " " in v:
        return None
    return v


def host_of(url: str) -> str | None:
    return normalize_host(url if "://" in url else "http://" + url)


# ---------------------------------------------------------------- parsers

def _lines(text: str) -> Iterable[str]:
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            yield line


def parse_url_list(text: str) -> tuple[set[str], set[str]]:
    """One URL per line -> (urls, hosts)."""
    urls, hosts = set(), set()
    for line in _lines(text):
        if (u := normalize_url(line)) and (h := host_of(line)):
            urls.add(u)
            hosts.add(h)
    return urls, hosts


def parse_domain_list(text: str) -> tuple[set[str], set[str]]:
    """One domain per line -> (no urls, hosts)."""
    return set(), {h for line in _lines(text) if (h := normalize_host(line))}


def parse_urlhaus_csv(text: str) -> tuple[set[str], set[str]]:
    """URLhaus CSV dump: id,dateadded,url,url_status,... (comment lines start with #)."""
    body = "\n".join(line for line in text.splitlines() if line and not line.startswith("#"))
    urls, hosts = set(), set()
    for row in csv.reader(io.StringIO(body)):
        if len(row) > 2 and (u := normalize_url(row[2])) and (h := host_of(row[2])):
            urls.add(u)
            hosts.add(h)
    return urls, hosts


# ---------------------------------------------------------------- feed registry

@dataclass(frozen=True)
class Feed:
    name: str
    title: str
    parser: Callable[[str], tuple[set[str], set[str]]]
    url: Callable[[], str | None]  # None -> feed not configured (e.g. missing key)
    license: str
    default: bool = True
    # Host matches from URL feeds can be shared hosting; only exact host hits count then.
    hosts_are_listed_domains: bool = True


def _urlhaus_url() -> str | None:
    key = os.environ.get(ENV_URLHAUS_KEY)
    return f"https://urlhaus-api.abuse.ch/v2/files/exports/{key}/csv_online" if key else None


FEEDS: dict[str, Feed] = {f.name: f for f in [
    Feed("openphish", "OpenPhish community feed", parse_url_list,
         lambda: "https://openphish.com/feed.txt",
         "OpenPhish Terms of Use: personal / non-commercial research only, no redistribution",
         hosts_are_listed_domains=False),
    Feed("phishing_database_domains", "Phishing.Database (active domains)", parse_domain_list,
         lambda: "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
         "MIT (Phishing.Database contributors)"),
    Feed("phishing_database_links", "Phishing.Database (active links)", parse_url_list,
         lambda: "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt",
         "MIT (Phishing.Database contributors)", default=False, hosts_are_listed_domains=False),
    Feed("urlhaus", "abuse.ch URLhaus (online malware URLs)", parse_urlhaus_csv, _urlhaus_url,
         "abuse.ch fair-use terms; free Auth-Key required; commercial use may need a paid plan",
         hosts_are_listed_domains=False),
]}


# ---------------------------------------------------------------- update

@dataclass
class FeedResult:
    name: str
    ok: bool
    urls: int = 0
    hosts: int = 0
    message: str = ""


MAX_FEED_BYTES = 256 * 1024 * 1024  # GitHub serves files up to 100 MB; far bigger isn't a feed


def _download(url: str, timeout: int = 120) -> str:
    import urllib.request  # lazy: the hook never downloads, so it skips this import

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        data = resp.read(MAX_FEED_BYTES + 1)
    if len(data) > MAX_FEED_BYTES:
        raise ValueError(f"feed is larger than {MAX_FEED_BYTES // (1024 * 1024)} MB; kept the old cache")
    return data.decode("utf-8", "replace")


def _meta_path(d: Path) -> Path:
    return d / "meta.json"


def read_meta(d: Path | None = None) -> dict:
    p = _meta_path(d or cache_dir())
    try:
        return json.loads(p.read_text("utf-8"))
    except (OSError, ValueError):
        return {}


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, "utf-8")
    tmp.replace(path)


def update_feeds(names: list[str] | None = None, *, directory: Path | None = None,
                 fetch: Callable[[str], str] | None = None) -> list[FeedResult]:
    """Download feeds into the cache. A failed feed keeps its previous cache files."""
    fetch = fetch or _download  # looked up per call, so tests and the CI smoke job can serve fixtures
    d = directory or cache_dir()
    d.mkdir(parents=True, exist_ok=True)
    meta = read_meta(d)
    selected = names or [n for n, f in FEEDS.items() if f.default]
    results = []
    for name in selected:
        feed = FEEDS.get(name)
        if feed is None:
            results.append(FeedResult(name, False, message="unknown feed"))
            continue
        url = feed.url()
        if url is None:
            results.append(FeedResult(name, False, message=f"skipped: set {ENV_URLHAUS_KEY} to enable"))
            continue
        try:
            urls, hosts = feed.parser(fetch(url))
            if not urls and not hosts:
                raise ValueError("feed parsed to zero entries")
        except Exception as e:  # network, HTTP, parse: keep the old cache
            old = meta.get(name, {}).get("fetched_at")
            results.append(FeedResult(name, False, message=f"{type(e).__name__}: {e}; kept cache from {old or 'never'}"))
            continue
        _atomic_write(d / f"{name}.urls.txt", "\n".join(sorted(urls)) + "\n")
        _atomic_write(d / f"{name}.hosts.txt", "\n".join(sorted(hosts)) + "\n")
        meta[name] = {"fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                      "source_url": url.replace(os.environ.get(ENV_URLHAUS_KEY) or "\0", "<key>"),
                      "urls": len(urls), "hosts": len(hosts), "license": feed.license}
        _atomic_write(_meta_path(d), json.dumps(meta, indent=2))
        results.append(FeedResult(name, True, len(urls), len(hosts)))
    load_index.cache_clear()
    return results


# ---------------------------------------------------------------- lookup

@dataclass
class FeedHit:
    kind: str  # "url" | "host" | "parent"
    feeds: list[str]
    matched: str


@dataclass
class FeedIndex:
    urls: dict[str, list[str]] = field(default_factory=dict)  # normalized url -> feeds
    hosts: dict[str, list[str]] = field(default_factory=dict)  # host -> feeds
    listed_domains: dict[str, list[str]] = field(default_factory=dict)  # parent-match ok
    fetched_at: dict[str, str] = field(default_factory=dict)

    def lookup(self, url: str) -> FeedHit | None:
        if (u := normalize_url(url)) and u in self.urls:
            return FeedHit("url", self.urls[u], u)
        host = host_of(url)
        if not host:
            return None
        if host in self.hosts:
            return FeedHit("host", self.hosts[host], host)
        labels = host.split(".")
        for i in range(1, len(labels) - 1):
            parent = ".".join(labels[i:])
            if parent in self.listed_domains:
                return FeedHit("parent", self.listed_domains[parent], parent)
        return None

    def stale_feeds(self, hours: float = STALE_AFTER_HOURS, now: float | None = None) -> list[str]:
        now = now or time.time()
        out = []
        for name, ts in self.fetched_at.items():
            try:
                age = now - datetime.fromisoformat(ts).timestamp()
            except ValueError:
                age = float("inf")
            if age > hours * 3600:
                out.append(name)
        return out

    def __bool__(self) -> bool:
        return bool(self.urls or self.hosts)


def _read_set(p: Path) -> list[str]:
    try:
        return [x for x in p.read_text("utf-8").splitlines() if x]
    except OSError:
        return []


class LazyFeedIndex:
    """Same lookups as FeedIndex, without building dicts: searches the cached files directly.

    For short-lived processes (the enforcement hook runs once per tool call), loading ~400k
    domains into dicts costs ~0.6s; a substring search over the raw file costs a few ms.
    """

    def __init__(self, directory: Path | str | None = None):
        self.dir = Path(directory) if directory else cache_dir()
        self.meta = read_meta(self.dir)
        self.fetched_at = {n: i.get("fetched_at", "") for n, i in self.meta.items() if n in FEEDS}
        self._blobs: dict[str, bytes] = {}

    def _blob(self, name: str, kind: str) -> bytes:
        key = f"{name}.{kind}"
        if key not in self._blobs:
            try:
                data = (self.dir / f"{name}.{kind}.txt").read_bytes().replace(bytes([13]), b"")
            except OSError:
                data = b""
            self._blobs[key] = b"\n" + data + (b"" if data.endswith(b"\n") else b"\n")
        return self._blobs[key]

    def _has(self, name: str, kind: str, value: str) -> bool:
        return b"\n" + value.encode() + b"\n" in self._blob(name, kind)

    def lookup(self, url: str) -> FeedHit | None:
        names = list(self.fetched_at)
        if u := normalize_url(url):
            if hit := [n for n in names if self._has(n, "urls", u)]:
                return FeedHit("url", hit, u)
        host = host_of(url)
        if not host:
            return None
        if hit := [n for n in names if self._has(n, "hosts", host)]:
            return FeedHit("host", hit, host)
        listed = [n for n in names if FEEDS[n].hosts_are_listed_domains]
        labels = host.split(".")
        for i in range(1, len(labels) - 1):
            parent = ".".join(labels[i:])
            if hit := [n for n in listed if self._has(n, "hosts", parent)]:
                return FeedHit("parent", hit, parent)
        return None

    stale_feeds = FeedIndex.stale_feeds

    def __bool__(self) -> bool:
        return any(len(self._blob(n, k)) > 2 for n in self.fetched_at for k in ("urls", "hosts"))


@lru_cache(maxsize=4)
def load_index(directory: str | None = None) -> FeedIndex:
    d = Path(directory) if directory else cache_dir()
    idx = FeedIndex()
    for name, info in read_meta(d).items():
        feed = FEEDS.get(name)
        if feed is None:
            continue
        idx.fetched_at[name] = info.get("fetched_at", "")
        for u in _read_set(d / f"{name}.urls.txt"):
            idx.urls.setdefault(u, []).append(name)
        for h in _read_set(d / f"{name}.hosts.txt"):
            if feed.hosts_are_listed_domains:
                idx.listed_domains.setdefault(h, []).append(name)
            idx.hosts.setdefault(h, []).append(name)
    return idx


def current_index() -> FeedIndex:
    """The cached index, reloaded when `update-feeds` has rewritten meta.json
    (so a long-running MCP server picks up refreshed feeds without a restart)."""
    d = cache_dir()
    try:
        mtime = _meta_path(d).stat().st_mtime
    except OSError:
        mtime = 0.0
    return _index_at(str(d), mtime)


@lru_cache(maxsize=2)
def _index_at(directory: str, mtime: float) -> FeedIndex:
    return load_index.__wrapped__(directory)
