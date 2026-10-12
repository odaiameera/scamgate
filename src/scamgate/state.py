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
    d = state_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d
