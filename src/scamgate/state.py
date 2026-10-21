"""Where scamgate keeps local state (ask log, human overrides, payee history).

State dir: $SCAMGATE_STATE_DIR, else $XDG_STATE_HOME/scamgate, else ~/.local/state/scamgate.
Nothing here ever leaves the machine.
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_STATE_DIR = "SCAMGATE_STATE_DIR"


def state_dir() -> Path:
    if env := os.environ.get(ENV_STATE_DIR):
        return Path(env).expanduser()
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "scamgate"


def ensure_state_dir() -> Path:
    """Created private (0700): the ask log shows which sites your agent tried to visit."""
    d = state_dir()
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    if d.name == "scamgate":  # tighten our own folder from an older install; leave a custom dir as you set it
        try:
            if d.stat().st_mode & 0o077:
                d.chmod(0o700)
        except OSError:
            pass
    return d
