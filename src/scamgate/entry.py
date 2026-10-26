"""The `scamgate` console script.

`scamgate hook` runs once per agent tool call (the Claude Code plugin calls `uvx scamgate==X hook`), so it
skips the typer/rich command line and goes straight to the hook. Every other command loads the full CLI.
"""

from __future__ import annotations

import sys


def main() -> None:
    if sys.argv[1:] == ["hook"]:
        from .hook import main as run_hook

        sys.exit(run_hook())
    from .cli import app

    app()
