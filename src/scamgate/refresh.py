"""Refreshing the known-bad-link feeds without extra packages.

The Hermes plugin's `/scamgate update`, its `scamgate_update_feeds` tool, `hermes scamgate
update-feeds` and the background refresh all come through `refresh()`. None of them takes a feed
name, a URL or a folder from the caller: it always downloads the default feeds from their fixed
sources into the configured cache. An agent can ask for a refresh, but can't choose what lands in
the cache.

A lock file in the cache folder makes sure only one refresh runs at a time, however many Hermes
processes (gateway, chats, cron jobs) have the plugin loaded.
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator

from . import feeds

AUTO_REFRESH_HOURS = 6.0  # the background refresh downloads again once the lists are this old
TOOL_MIN_GAP_HOURS = 1.0  # the agent tool doesn't download again within this time
LOCK_NAME = ".update.lock"
LOCK_STALE_SECONDS = 30 * 60  # a lock older than this was left by a refresh that died


@dataclass
class Outcome:
    updated: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)
    not_configured: dict[str, str] = field(default_factory=dict)
    counts: dict[str, dict[str, int]] = field(default_factory=dict)
    skipped: str = ""  # "fresh" | "busy" when nothing was downloaded on purpose

    @property
    def ok(self) -> bool:
        return bool(self.updated) or self.skipped in ("fresh", "busy")

    def as_dict(self) -> dict:
        return {"updated": self.updated, "failed": self.failed, "not_configured": self.not_configured,
                "counts": self.counts, "skipped": self.skipped, "cache": str(feeds.cache_dir())}

    def text(self) -> str:
        if self.skipped == "fresh":
            return f"scamgate: the phishing lists were refreshed less than {TOOL_MIN_GAP_HOURS:g} hour ago."
        if self.skipped == "busy":
            return "scamgate: another refresh is already running; the lists will update when it finishes."
        lines = []
        for name in self.updated:
            c = self.counts.get(name, {})
            lines.append(f"{name}: updated ({c.get('urls', 0)} links, {c.get('hosts', 0)} hosts)")
        for name, why in self.failed.items():
            lines.append(f"{name}: not updated, kept the old list ({why})")
        for name, why in self.not_configured.items():
            lines.append(f"{name}: {why}")
        head = "scamgate: phishing lists refreshed." if self.updated else "scamgate: no list could be refreshed."
        return head + "\n" + "\n".join(lines)


def _configured_defaults() -> list[str]:
    """Default feeds that can be downloaded here (URLhaus only counts once its key is set)."""
    return [n for n, f in feeds.FEEDS.items() if f.default and f.url() is not None]


def oldest_age_hours(now: float | None = None) -> float:
    """Age of the oldest default feed in hours; infinity when one was never downloaded."""
    now = now or time.time()
    meta = feeds.read_meta()
    oldest = 0.0
    for name in _configured_defaults():
        ts = meta.get(name, {}).get("fetched_at")
        try:
            age = (now - datetime.fromisoformat(ts).timestamp()) / 3600 if ts else float("inf")
        except ValueError:
            age = float("inf")
        oldest = max(oldest, age)
    return oldest


@contextmanager
def _lock() -> Iterator[bool]:
    d = feeds.cache_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = d / LOCK_NAME
    try:
        if time.time() - path.stat().st_mtime > LOCK_STALE_SECONDS:
            path.unlink(missing_ok=True)
    except OSError:
        pass
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        yield False
        return
    with os.fdopen(fd, "w") as f:
        f.write(str(os.getpid()))
    try:
        yield True
    finally:
        path.unlink(missing_ok=True)


def refresh(*, if_older_than_hours: float | None = None) -> Outcome:
    """Download the default feeds into the cache. Never raises for network or parse errors."""
    if if_older_than_hours is not None and oldest_age_hours() < if_older_than_hours:
        return Outcome(skipped="fresh")
    with _lock() as got:
        if not got:
            return Outcome(skipped="busy")
        results = feeds.update_feeds()
    out = Outcome()
    for r in results:
        if r.ok:
            out.updated.append(r.name)
            out.counts[r.name] = {"urls": r.urls, "hosts": r.hosts}
        elif r.message.startswith("skipped"):
            out.not_configured[r.name] = r.message
        else:
            out.failed[r.name] = r.message
    return out


def auto_pass() -> Outcome:
    """One pass of the background refresh: download only when the lists are 6 hours old."""
    return refresh(if_older_than_hours=AUTO_REFRESH_HOURS)


def status() -> tuple[bool, list[str]]:
    """(any feeds cached, one line per cached feed)."""
    meta = {k: v for k, v in feeds.read_meta().items() if k in feeds.FEEDS}
    if not meta:
        return False, []
    idx = feeds.FeedIndex(fetched_at={k: v.get("fetched_at", "") for k, v in meta.items()})
    stale = set(idx.stale_feeds())
    lines = [f"{name}: {m.get('urls', 0)} links, {m.get('hosts', 0)} hosts, fetched {m.get('fetched_at')}"
             + (" (stale)" if name in stale else "") for name, m in meta.items()]
    return True, lines


# ---------------------------------------------------------------- `hermes scamgate ...`

def setup_cli(parser) -> None:
    """Builds `hermes scamgate ...`. Hermes sets `func=cli_main` on this parser."""
    sub = parser.add_subparsers(dest="scamgate_command", metavar="COMMAND")
    sub.required = True
    up = sub.add_parser("update-feeds", help="Download the default phishing lists into the cache now")
    up.set_defaults(scamgate_run=_cli_update)
    st = sub.add_parser("feeds-status", help="Show the cached phishing lists and their age")
    st.set_defaults(scamgate_run=_cli_status)


def _cli_update(args) -> int:
    out = refresh()
    print(out.text())
    print(f"cache: {feeds.cache_dir()}")
    return 0 if out.ok else 1


def _cli_status(args) -> int:
    any_cached, lines = status()
    if not any_cached:
        print("No phishing lists cached yet. Run `hermes scamgate update-feeds`, or `/scamgate update` in a chat.")
        return 1
    print("\n".join(lines))
    return 0


def cli_main(args) -> int:
    run = getattr(args, "scamgate_run", None)
    if run is None:
        print("Usage: hermes scamgate update-feeds | feeds-status")
        return 2
    return run(args)
