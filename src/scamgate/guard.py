"""Who may change scamgate's state, and how its records are signed.

Overrides and payee history change what scamgate allows, so only a person may write them:
- `require_human()` refuses when the caller is non-interactive or runs inside a known agent
  (Claude Code, Hermes, Codex). The CLI calls it, and so do the library functions, so an agent
  importing `scamgate.overrides` directly is refused too.
- Each record is signed with an HMAC key in the state dir (created 0600). A line an agent appends
  with any text editor fails verification and is ignored.

This is tamper-evidence against an agent using its normal tools, not protection against code
running as you: that code can read the key. See README "Limits".
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
from pathlib import Path

from .state import ensure_state_dir, state_dir

AGENT_ENV_MARKERS = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "HERMES_SESSION_ID", "HERMES_GATEWAY_SESSION",
                     "HERMES_INTERACTIVE_AGENT", "CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED",
                     "CURSOR_AGENT", "SCAMGATE_AGENT")


def _interactive() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def agent_marker() -> str | None:
    return next((m for m in AGENT_ENV_MARKERS if os.environ.get(m)), None)


def require_human(action: str, *, interactive=None) -> None:
    if m := agent_marker():
        raise PermissionError(f"{action} must be done by a person, not an agent (running under {m}).")
    if not (interactive or _interactive)():
        raise PermissionError(f"{action} must be run by a person in an interactive terminal.")


def _private_write(p: Path, data: str) -> None:
    ensure_state_dir()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def _key() -> bytes:
    p = state_dir() / "state.key"
    if not p.exists():
        _private_write(p, secrets.token_hex(32))
    return p.read_text("utf-8").strip().encode()


def key_exists() -> bool:
    return (state_dir() / "state.key").exists()


def _canonical(rec: dict) -> bytes:
    return json.dumps({k: v for k, v in rec.items() if k != "sig"}, sort_keys=True, separators=(",", ":")).encode()


def sign(rec: dict) -> dict:
    return {**rec, "sig": hmac.new(_key(), _canonical(rec), hashlib.sha256).hexdigest()}


def verify(rec: dict) -> bool:
    sig = rec.get("sig")
    if not isinstance(sig, str) or not key_exists():
        return False
    return hmac.compare_digest(sig, hmac.new(_key(), _canonical(rec), hashlib.sha256).hexdigest())


def append_private(p: Path, line: str) -> None:
    ensure_state_dir()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
