"""Stub: pull community phishing feeds into data/feeds/ (never committed).

Planned sources (check each feed's licence and terms before use):
  - phishdestroy/destroylist  https://github.com/phishdestroy/destroylist
  - OpenPhish community feed  https://openphish.com/feed.txt

Nothing is bundled with scamgate. This script is a stub: it prints what it would do.
Run with --download to actually fetch the OpenPhish community feed.
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

FEEDS_DIR = Path(__file__).resolve().parents[1] / "data" / "feeds"
OPENPHISH_URL = "https://openphish.com/feed.txt"


def fetch_openphish() -> int:
    FEEDS_DIR.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(OPENPHISH_URL, timeout=30) as resp:  # noqa: S310
        lines = resp.read().decode("utf-8", "replace").splitlines()
    hosts = sorted({(urlsplit(u.strip()).hostname or "").lower() for u in lines if u.strip()} - {""})
    (FEEDS_DIR / "openphish.txt").write_text("\n".join(hosts) + "\n", "utf-8")
    return len(hosts)


def main() -> None:
    if "--download" not in sys.argv:
        print(__doc__)
        print(f"Would write domain lists to {FEEDS_DIR}/*.txt (scamgate loads them automatically).")
        print("TODO: destroylist importer.")
        return
    n = fetch_openphish()
    print(f"Wrote {n} hosts to {FEEDS_DIR / 'openphish.txt'}")


if __name__ == "__main__":
    main()
