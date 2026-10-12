"""Deprecated: use `scamgate update-feeds`. Kept as a thin wrapper for old cron entries."""

from scamgate.cli import app

if __name__ == "__main__":
    app(["update-feeds"])
