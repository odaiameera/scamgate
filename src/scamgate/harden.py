"""Extra gate checks found while fitting scamgate to Hermes.

The hook already scores links and payments. This module covers what that scan never saw:

- Hermes safety switches (approvals off, /yolo, uninstalling the gate).
- Reading the signing key.
- A script the agent writes, then runs, including one cron will run later with no agent.
- The body of a file another tool will run (Makefile, package.json, git hooks, CI).

Quiet tools (notes, chat) are not scanned: quoting a scam link in a report is not a visit.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

_SAFETY_BLOCK = re.compile(
    r"""(?ix)
    hermes\s+config\s+set\s+(?:approvals\b|plugins\.(?:hook_callback_timeout|disabled|entries)\b)
  | hermes\s+config\s+unset\s+approvals\b
  | hermes\s+config\s+edit\b
  | hermes(?:['\"\],\s]+)config(?:['\"\],\s]+)set(?:['\"\],\s]+)['\"]?approvals
  | hermes\s+plugins\s+(?:uninstall|remove|disable)\b
  | (?<![A-Za-z0-9_-])--yolo\b
  | HERMES_YOLO_MODE\s*=
  | HERMES_YOLO_MODE['\"]\s*\]\s*=
  | \$env:HERMES_YOLO_MODE\b
  | (?<![A-Za-z0-9_-])--safe-mode\b
  | HERMES_SAFE_MODE\s*=
  | (?<![A-Za-z0-9_-])--ignore-user-config\b
  | (?<![A-Za-z0-9_-])--dangerously-skip-permissions\b
  | --permission-mode\s+bypassPermissions\b
  | --dangerously-bypass-approvals-and-sandbox\b
  | set_config_value\s*\([^)]*approvals
"""
)
_SAFETY_ASK = re.compile(
    r"""(?ix)
    hermes\s+plugins\s+(?:install|enable)\b
  | \bhermes\b[^\n]{0,120}\s(?:-p|--profile)\s+\S
"""
)
_SECRET = re.compile(r"(?i)state\.key|payees\.salt|\.local[/\\]+state[/\\]+scamgate\b")
# Claude Code: disabling or removing a plugin (scamgate is one) or its marketplace, and starting a nested
# claude session that skips hooks (bare mode, or settings with disableAllHooks). The other bypass flags are
# in _SAFETY_BLOCK.
_CLAUDE_BIN = r"\bclaude(?:-code)?(?:\.exe|\.cmd)?"
_CLAUDE_SAFETY_BLOCK = re.compile(
    rf"""(?ix)
    {_CLAUDE_BIN}\s+plugins?\s+(?:disable|uninstall|remove|rm)\b
  | {_CLAUDE_BIN}\s+plugins?\s+marketplace\s+(?:remove|rm)\b
  | {_CLAUDE_BIN}\b[^\n|;&]{{0,300}}?(?<![A-Za-z0-9_-])--bare\b
  | {_CLAUDE_BIN}\b[^\n|;&]{{0,300}}?/plugins?\s+(?:disable|uninstall|remove|rm)\b
  | (?<![A-Za-z0-9_-])--allow-dangerously-skip-permissions\b
  | disableAllHooks['"\s]*[:=]\s*['"]?true\b
"""
)
# Claude Code: changing which plugins or settings a session loads.
_CLAUDE_SAFETY_ASK = re.compile(
    rf"""(?ix)
    {_CLAUDE_BIN}\s+plugins?\s+(?:install|i|enable|configure)\b
  | {_CLAUDE_BIN}\b[^\n|;&]{{0,300}}?(?<![A-Za-z0-9_-])--setting-sources\b
  | {_CLAUDE_BIN}\b[^\n|;&]{{0,300}}?(?<![A-Za-z0-9_-])--settings\b
"""
)
# Exactly scamgate's own tools: Claude Code MCP, Claude Code plugin MCP, Hermes MCP, Hermes plugin. Not any
# name containing them.
_OWN_CHECK = re.compile(
    r"(?i)^(?:mcp__scamgate__|mcp__plugin_scamgate_scamgate__|mcp_scamgate_|scamgate_)check_(?:url|payment)$")
_SCRIPT_EXT = re.compile(r"(?i)\.(?:sh|bash|py|js|mjs|cjs|ps1|bat|cmd)$")
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_RUNNABLE = re.compile(
    r"(?i)(?:^|/)(?:makefile|package\.json|conftest\.py|[^/]+\.(?:sh|bash|py|js|mjs|ps1|bat|cmd|ya?ml))$"
)
_CONTENT_KEYS = ("content", "new_string", "new_text", "text", "body", "patch")
_PATH_KEYS = ("path", "file_path", "filepath", "notebook_path", "target_file")
_SKIP = {"sudo", "command", "time", "nohup", "builtin"}
_SHELLS = {"bash", "sh", "dash", "zsh", "ksh", "fish"}
_PY = {"python", "python3", "py", "python.exe", "python3.exe"}
_NODE = {"node", "nodejs", "node.exe"}
_PWSH = {"pwsh", "powershell", "pwsh.exe", "powershell.exe"}


def own_check(tool: str) -> bool:
    """scamgate's own check tools. Asking 'is this link bad?' must not be blocked for naming it."""
    return bool(_OWN_CHECK.match((tool or "").strip()))


def gate_extra(tool: str, tool_input: dict):
    """Strongest extra decision, or None when these checks have nothing to say."""
    from .hook import QUIET_TOOLS, Result, _RANK, _canon_tool, _norm_path, _strings

    t = _canon_tool(tool)
    quiet = t in QUIET_TOOLS
    found = Result("none")

    def take(new):
        nonlocal found
        if new is not None and _RANK[new.decision] > _RANK[found.decision]:
            found = new

    for key in _PATH_KEYS:
        val = tool_input.get(key)
        if isinstance(val, str) and _secret_path(val):
            take(_block(f"it would read scamgate's signing state ({val})"))

    if not quiet:
        blob = "\n".join(_strings(tool_input))
        if _SECRET.search(blob) or _mentions_state_dir(blob):
            take(_block("it would read scamgate's signing key or payee history"))
        if m := _SAFETY_BLOCK.search(blob) or _CLAUDE_SAFETY_BLOCK.search(blob):
            take(_block(f"it would switch a safety control off ('{m.group(0).strip()[:80]}')"))
        elif m := _SAFETY_ASK.search(blob) or _CLAUDE_SAFETY_ASK.search(blob):
            take(_ask(f"it changes which agent or plugins are in force ('{m.group(0).strip()[:80]}'). "
                      "Approve only if you meant to install or switch."))
        if t in {"write_file", "patch", "write", "edit", "multiedit", "notebookedit", "str_replace_editor"}:
            path = next((tool_input.get(k) for k in _PATH_KEYS if isinstance(tool_input.get(k), str)), "")
            body = "\n".join(tool_input.get(k) for k in _CONTENT_KEYS if isinstance(tool_input.get(k), str))
            if path and body:
                take(_judge_written(path, body))

    if t == "cronjob_manage" or "cronjob" in t:
        take(_cron_scripts(tool_input))
    if not quiet:
        take(_ran_scripts(tool, tool_input))

    return None if found.decision == "none" else found


def _block(why: str):
    from .hook import Result

    return Result("block", f"scamgate blocked this because {why}. Agents can't weaken the scam gate or read "
                           "its signing key. Don't retry it another way; tell the user to do it themselves, "
                           "outside the agent.")


def _ask(why: str):
    from .hook import Result

    return Result("approve", f"scamgate: {why}", "scamgate:safety")


def _secret_path(path: str) -> bool:
    from .hook import _norm_path
    from .state import state_dir

    p = _norm_path(path)
    root = _norm_path(str(state_dir()))
    if root and (p == root or p.startswith(root + "/")):
        return True
    return bool(_SECRET.search(p))


def _mentions_state_dir(text: str) -> bool:
    from .hook import _expand, _norm_path
    from .state import state_dir

    root = _norm_path(str(state_dir()))
    if len(root) < 8:
        return False
    return root in _norm_path(_expand(text))


def _runnable(path: str) -> bool:
    p = path.replace("\\", "/").lower()
    if "/.git/hooks/" in p or "/.github/workflows/" in p:
        return True
    if _under_hermes_scripts(path):
        return True
    return bool(_RUNNABLE.search(p))


def _shellish(path: str) -> bool:
    p = path.replace("\\", "/").lower()
    if p.endswith(("/makefile", "makefile", ".sh", ".bash", ".ps1", ".bat", ".cmd")):
        return True
    if "/.git/hooks/" in p or "/.github/workflows/" in p:
        return True
    return _under_hermes_scripts(path)


def _under_hermes_scripts(path: str) -> bool:
    from .hook import _norm_path

    home = os.environ.get("HERMES_HOME")
    if not home:
        return False
    root = _norm_path(str(Path(home) / "scripts"))
    p = _norm_path(path)
    return p == root or p.startswith(root + "/")


def _judge_written(path: str, body: str):
    from .hook import Result, _DECODE_RUN, _INDIRECT_RE, _NET_RE, _RANK, _URL_RE, _evaluate, _repair_schemes
    from .hook import Gate

    if not _runnable(path):
        return None
    if m := _SAFETY_BLOCK.search(body):
        return _block(f"the file would switch a safety control off ('{m.group(0).strip()[:80]}')")
    g = Gate(tool="write_file")
    g.urls = _URL_RE.findall(_repair_schemes(body))
    found = _evaluate(g) if g.urls else Result("none")
    if _DECODE_RUN.search(body):
        ask = Result("approve", "scamgate: this file decodes something and runs it, so scamgate can't see what "
                                 "it will do. Approve only if you wrote it.", "scamgate:write-decode")
        if _RANK[ask.decision] > _RANK[found.decision]:
            found = ask
    if _shellish(path) and _NET_RE.search(body) and _INDIRECT_RE.search(body) and found.decision != "block":
        ask = Result("approve", "scamgate: this script can reach the network, but the destination isn't written "
                                 "out, so scamgate can't check it. Approve only if you know where it goes.",
                     "scamgate:write-opaque")
        if _RANK[ask.decision] > _RANK[found.decision]:
            found = ask
    return None if found.decision == "none" else found


def _cron_scripts(tool_input: dict):
    from .hook import Result

    home = os.environ.get("HERMES_HOME")
    base = Path(home) / "scripts" if home else None
    worst = None
    for key in ("script", "monitor_script"):
        name = tool_input.get(key)
        if not isinstance(name, str) or not name.strip():
            continue
        path = Path(name)
        if not path.is_absolute():
            path = (base / name) if base else path
        got = _read(path)
        if got is None:
            worst = worst or Result("approve", "scamgate: this scheduled job names a script scamgate can't read, "
                                               "so it can't check what the job will do later. Approve only if you "
                                               "know that script.", "scamgate:cron-unread")
            continue
        if got == "big":
            return Result("approve", "scamgate: this scheduled script is too large to read. Approve only if you "
                                     "know what it does.", "scamgate:cron-big")
        judged = _judge_script(got, "cronjob_manage")
        if judged and (worst is None or judged.decision == "block" or worst.decision != "block"):
            worst = judged
    return worst


def _ran_scripts(tool: str, tool_input: dict):
    from .hook import CODE_KEYS, CODE_TOOLS, NET_TOOL_HINT, Result, _canon_tool, _segments

    t = _canon_tool(tool)
    if t not in CODE_TOOLS and not NET_TOOL_HINT.search(t):
        return None
    command = "\n".join(str(tool_input.get(k)) for k in CODE_KEYS if isinstance(tool_input.get(k), str))
    if not command.strip():
        return None
    workdir = tool_input.get("workdir") if isinstance(tool_input.get("workdir"), str) else ""
    cwd = workdir
    worst = None
    seen: set[str] = set()
    for seg in _segments(command):
        cd = re.match(r"(?i)^cd\s+(.+)$", seg.strip())
        if cd and "&&" not in seg and ";" not in seg:
            dest = cd.group(1).strip().strip("'\"")
            cwd = dest if Path(dest).is_absolute() or not cwd else str(Path(cwd) / dest)
            continue
        for token in _script_tokens(seg):
            path = _resolve(token, cwd)
            hit = _follow(path, seen, 0)
            if hit is None:
                continue
            if isinstance(hit, Result) and (worst is None or hit.decision == "block" or worst.decision != "block"):
                worst = hit
    return worst


def _follow(path: Path, seen: set[str], depth: int):
    from .hook import MAX_SCRIPT_DEPTH, Result, _segments

    key = str(path)
    if key in seen or depth > MAX_SCRIPT_DEPTH:
        return None
    seen.add(key)
    got = _read(path)
    if got is None or got == "big":
        if got == "big":
            return Result("approve", f"scamgate: '{path.name}' is too large to read, so scamgate can't check what "
                                     "it will do. Approve only if you know that script.", "scamgate:script-big")
        return None
    judged = _judge_script(got, "terminal")
    if judged and judged.decision == "block":
        return judged
    nested = judged
    for seg in _segments(got):
        for token in _script_tokens(seg):
            child = _follow(_resolve(token, str(path.parent)), seen, depth + 1)
            if child is not None and (nested is None or child.decision == "block"):
                nested = child
    return nested


def _judge_script(text: str, tool: str):
    from . import paygate
    from .hook import Result, _RANK, _TAMPER_CMD, _evaluate, _scan_code
    from .hook import Gate

    if m := _SAFETY_BLOCK.search(text):
        return _block(f"the script would switch a safety control off ('{m.group(0).strip()[:80]}')")
    if m := _TAMPER_CMD.search(text):
        return _block(f"the script would weaken or remove the scam gate ('{m.group(0).strip()[:80]}')")
    g = Gate(tool=tool)
    _scan_code(text, g)
    found = _evaluate(g) if (g.urls or g.opaque_network) else Result("none")
    if cp := paygate.scan_code(text):
        ask = Result("approve", f"scamgate: this script makes a payment ({cp.detail}), and scamgate can't read "
                                "who gets paid or how much. Approve once, only if you started this payment.",
                     "scamgate:script-pay")
        if _RANK[ask.decision] >= _RANK[found.decision]:
            found = ask
    return None if found.decision == "none" else found


def _read(path: Path):
    from .hook import MAX_SCRIPT_BYTES

    try:
        if not path.is_file():
            return None
        if path.stat().st_size > MAX_SCRIPT_BYTES:
            return "big"
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "big"


def _resolve(token: str, cwd: str) -> Path:
    token = os.path.expanduser(token.strip().strip("'\""))
    path = Path(token)
    if not path.is_absolute():
        path = (Path(cwd) if cwd else Path.cwd()) / token
    return path


def _script_tokens(segment: str) -> list[str]:
    from .hook import _words  # shlex's words in one pass: shlex itself is superlinear on long tokens

    toks = _words(segment)
    if toks is None:
        return []
    i = 0
    while i < len(toks) and _ENV_ASSIGN.match(toks[i]) and "/" not in toks[i] and "\\" not in toks[i]:
        i += 1
    while i < len(toks) and Path(toks[i]).name.lower() in _SKIP:
        i += 1
        while i < len(toks) and toks[i].startswith("-"):
            i += 1
    if i >= len(toks):
        return []
    if toks[i] in ("&", "."):
        return [toks[i + 1]] if i + 1 < len(toks) else []
    cmd = Path(toks[i]).name.lower()
    rest = toks[i + 1:]
    if cmd in _SHELLS or cmd == "source":
        return _first_file(rest, inline_flags={"-c", "-lc"})
    if cmd in _PY or cmd in _NODE:
        return _first_file(rest, inline_flags={"-c", "-m"})
    if cmd == "uv" and rest and rest[0] == "run":
        return _first_file(rest[1:], inline_flags=set())
    if cmd in _PWSH:
        if "-File" in rest:
            k = rest.index("-File")
            return [rest[k + 1]] if k + 1 < len(rest) else []
        if rest and rest[0].lower().endswith(".ps1"):
            return [rest[0]]
        return []
    token = toks[i]
    if token.startswith("./") or token.startswith(".\\") or _SCRIPT_EXT.search(token):
        return [token]
    return []


def _first_file(args: list[str], inline_flags: set[str]) -> list[str]:
    j = 0
    while j < len(args):
        arg = args[j]
        if arg in inline_flags:
            return []
        if arg.startswith("-"):
            j += 1
            continue
        return [arg]
    return []
