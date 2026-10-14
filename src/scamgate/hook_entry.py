"""Fast entry point for the enforcement hook (skips typer/rich startup).

`scamgate-hook` runs once per tool call, so startup time matters. `scamgate hook` does the
same thing through the full CLI.
"""

from __future__ import annotations

import sys


def main() -> None:
    from .hook import main as run

    sys.exit(run())
