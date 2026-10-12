"""Enforcement hook: the harness runs scamgate before tools act, the model can't skip it.

`scamgate hook` reads one hook event as JSON on stdin and writes a decision on stdout.
It speaks two dialects:

- Hermes shell hooks (`pre_tool_call` / `post_tool_call`): {"action": "block"|"approve", ...}
- Claude Code hooks (`PreToolUse` / `PostToolUse`): {"hookSpecificOutput": {"permissionDecision": ...}}

What it gates (pre events):
1. Tamper attempts: writes to scamgate's own files/state or the agent's hook config, and shell
   commands that remove the hook/MCP server or promote overrides. Always blocked.
2. Network-capable tools: every URL found in the arguments is checked. deny -> block,
   ask -> human approval. A network call whose destination can't be read -> human approval.
3. Everything else passes silently.

Never returns "allow": silence means "no objection", so the hook can only tighten the
agent's own permissions, never loosen them.

Fails closed: bad input or an internal error on a pre event blocks the call (exit 2).
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scamgate import asklog, engine, integrity
from scamgate.models import Decision
from scamgate.rules.url import parse
from scamgate.state import state_dir

MAX_URLS = 20

# ------------------------------------------------------------------ tool classes

URL_TOOLS = {  # tools whose arguments name a destination directly
    "browser_navigate", "browser_tool", "web_extract", "webfetch", "fetch", "navigate",
}
CODE_TOOLS = {  # tools whose arguments are code/commands that may reach the network
    "terminal", "bash", "shell", "execute_code", "browser_exec", "browser_cdp", "browser_console",
    "powershell", "python",
}
WRITE_TOOLS = {"write_file", "patch", "write", "edit", "multiedit", "notebookedit", "str_replace_editor"}
URL_KEYS = ("url", "urls", "link", "href", "target", "uri", "endpoint", "page", "image_url", "video_url")
CODE_KEYS = ("command", "code", "script", "expression", "cmd", "input")
PATH_KEYS = ("path", "file_path", "filepath", "notebook_path", "target_file")
REASON_KEYS = ("description", "prompt", "intent", "reason", "task", "goal")

_URL_RE = re.compile(r"""(?i)\b(?:https?|wss?|ftp)://[^\s'"<>`)\]}\\]+""")
_NET_RE = re.compile(
    r"(?i)\b(curl|wget|aria2c|httpie|\bhttp\b|nc|ncat|telnet|ssh|scp|sftp|rsync|ftp|"
    r"invoke-webrequest|invoke-restmethod|iwr|irm|start-bitstransfer|"
    r"requests\.|httpx\.|urllib|urlopen|aiohttp|socket\.|fetch\(|xmlhttprequest|websocket|"
    r"new_tab\(|goto_url\(|goto\(|navigate\(|page\.goto|window\.open|location\.href|"
    r"web_search\(|web_extract\(|webbrowser\.open|start\s+https?|open\s+https?|"
    r"git\s+clone|pip\s+install|uv\s+(?:pip|add|tool)|npm\s+(?:i|install)|npx\s)"
)
_TAMPER_CMD = re.compile(
    r"(?i)(hermes\s+(?:hooks\s+(?:revoke|rm|remove)|mcp\s+(?:rm|remove)|plugins\s+(?:disable|remove)|"
    r"config\s+set\s+(?:hooks\b|hooks_auto_accept|mcp_servers))|"
    r"scamgate\s+promote|"
    r"(?:uv\s+tool|pipx|pip3?|uv\s+pip)\s+uninstall\s+(?:-y\s+)?scamgate|"
    r"claude\s+mcp\s+remove\s+scamgate|"
    r"--accept-hooks|HERMES_ACCEPT_HOOKS)"
)
_SHELL_WRITE = re.compile(
    r"(?i)(\brm\b|\bdel\b|\berase\b|\bmv\b|\bmove\b|\bcp\b|\bcopy\b|\btruncate\b|\bsed\s+-i|\btee\b|"
    r">>?|remove-item|set-content|add-content|out-file|clear-content|rename-item|\.write_text|"
    r"\.unlink|shutil\.|os\.remove|open\([^)]*['\"][wa])"
)


def _canon_tool(name: str) -> str:
    n = (name or "").strip()
    if n.startswith("mcp__") or n.startswith("mcp_"):
        n = n.split("__")[-1] if "__" in n else n
    return n.lower()


# ------------------------------------------------------------------ protected paths

def _norm_path(p: str) -> str:
    s = os.path.expandvars(os.path.expanduser(p.strip().strip("'\"")))
    s = s.replace("\\", "/")
    m = re.match(r"^/([a-zA-Z])/(.*)$", s)  # git-bash /c/Users -> c:/users
    if m:
        s = f"{m.group(1)}:/{m.group(2)}"
    try:
        s = str(Path(s).resolve(strict=False)).replace("\\", "/")
    except (OSError, RuntimeError):
        pass
    return s.lower().rstrip("/")


def protected_roots() -> list[str]:
    roots: list[str] = []
    pkg = Path(__file__).resolve().parent
    roots.append(str(pkg))
    roots.append(str(state_dir()))
    if env := os.environ.get("SCAMGATE_CONFIG"):
        roots.append(env)
    if env := os.environ.get("SCAMGATE_BLOCKLIST"):
        roots.append(env)
    if home := os.environ.get("HERMES_HOME"):
        h = Path(home)
        roots += [str(h / "config.yaml"), str(h / "shell-hooks-allowlist.json"), str(h / "agent-hooks"),
                  str(h / "hooks"), str(h / "plugins")]
    roots += [str(Path.home() / ".claude" / "settings.json"), str(Path.home() / ".claude" / "hooks")]
    if env := os.environ.get("SCAMGATE_PROTECT"):
        roots += [p for p in env.split(os.pathsep) if p.strip()]
    return [_norm_path(r) for r in roots if r]


def _is_protected(path: str, roots: list[str]) -> str | None:
    p = _norm_path(path)
    for r in roots:
        if p == r or p.startswith(r + "/"):
            return r
    return None


def _mentions_protected(text: str, roots: list[str]) -> str | None:
    norm = text.replace("\\", "/").lower()
    norm = re.sub(r"(?<![a-z])/([a-z])/", lambda m: f"{m.group(1)}:/", norm)
    for r in roots:
        tail = r.split(":/", 1)[-1] if ":/" in r else r.lstrip("/")
        if r in norm or (len(tail) > 12 and tail in norm):
            return r
    return None


# ------------------------------------------------------------------ extraction

@dataclass
class Gate:
    tool: str
    urls: list[str] = field(default_factory=list)
    opaque_network: bool = False
    stated_reason: str = ""


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _strings(v)]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    return []


def _first_comment(code: str) -> str:
    for line in code.splitlines():
        s = line.strip()
        if s.startswith(("#", "//")):
            return s.lstrip("#/ ").strip()
        if s:
            break
    return ""


def _looks_like_bare_host(s: str) -> bool:
    s = s.strip()
    return bool(s) and " " not in s and "." in s and not s.startswith(("/", ".", "~")) \
        and bool(re.match(r"^[\w.-]+\.[a-z]{2,}(?::\d+)?(?:[/?#].*)?$", s, re.I))


def extract(tool: str, tool_input: dict) -> Gate:
    t = _canon_tool(tool)
    g = Gate(tool=tool)
    for k in REASON_KEYS:
        if isinstance(tool_input.get(k), str):
            g.stated_reason = tool_input[k]
            break
    if t in URL_TOOLS or any(k in tool_input for k in URL_KEYS):
        for k in URL_KEYS:
            for s in _strings(tool_input.get(k)):
                found = _URL_RE.findall(s)
                if found:
                    g.urls += found
                elif _looks_like_bare_host(s):
                    g.urls.append(s.strip())
        if t in URL_TOOLS and not g.urls:
            g.opaque_network = True
    if t in CODE_TOOLS:
        code = "\n".join(_strings({k: tool_input.get(k) for k in CODE_KEYS}))
        g.urls += _URL_RE.findall(code)
        if not g.stated_reason:
            g.stated_reason = _first_comment(code)
        if not g.urls and _NET_RE.search(code):
            g.opaque_network = True
    seen, out = set(), []
    for u in g.urls:
        u = u.rstrip(".,;:'\"")
        if u not in seen:
            seen.add(u)
            out.append(u)
    g.urls = out
    return g


def _tamper_reason(tool: str, tool_input: dict) -> str | None:
    t = _canon_tool(tool)
    roots = protected_roots()
    if t in WRITE_TOOLS:
        for k in PATH_KEYS:
            v = tool_input.get(k)
            if isinstance(v, str) and (hit := _is_protected(v, roots)):
                return f"it would change scamgate's protected files ({hit})"
    if t in CODE_TOOLS:
        code = "\n".join(_strings({k: tool_input.get(k) for k in CODE_KEYS}))
        if m := _TAMPER_CMD.search(code):
            return f"the command would weaken or remove the scam gate ('{m.group(0).strip()}')"
        if (hit := _mentions_protected(code, roots)) and _SHELL_WRITE.search(code):
            return f"the command would change scamgate's protected files ({hit})"
    return None


# ------------------------------------------------------------------ decision

@dataclass
class Result:
    decision: str  # "none" | "approve" | "block"
    message: str = ""
    rule_key: str | None = None
    rules: list[str] = field(default_factory=list)
    score: int = 0
    hosts: list[str] = field(default_factory=list)


_FEEDS: Any = None


def _feeds() -> Any:
    """One lazy feed index per process: the hook is short-lived, so skip building big dicts."""
    global _FEEDS
    if _FEEDS is None:
        from scamgate.feeds import LazyFeedIndex

        _FEEDS = LazyFeedIndex()
    return _FEEDS


def _evaluate(g: Gate) -> Result:
    if len(g.urls) > MAX_URLS:
        return Result("approve", f"scamgate: this call opens {len(g.urls)} links at once, too many to check. "
                                 "Confirm before it runs.", "scamgate:bulk", [], 0, [])
    worst, worst_v, worst_url = Decision.allow, None, None
    rank = {Decision.allow: 0, Decision.ask: 1, Decision.deny: 2}
    hosts, rules = [], []
    for u in g.urls:
        v = engine.check_url(u, g.stated_reason or None, feeds=_feeds())
        h = parse(u).host
        if h:
            hosts.append(h)
        if v.decision is not Decision.allow:
            rules += [r.rule_id for r in v.reasons]
        if rank[v.decision] > rank[worst] or (worst_v and v.decision is worst
                                              and v.risk_score > worst_v.risk_score):
            worst, worst_v, worst_url = v.decision, v, u
    if worst is Decision.deny:
        h = parse(worst_url).host
        return Result("block",
                      f"scamgate blocked this: {worst_v.summary} (score {worst_v.risk_score}/100, link host: {h}). "
                      "Don't retry it another way. Tell the user what was blocked and why.",
                      None, rules, worst_v.risk_score, hosts)
    if worst is Decision.ask:
        h = parse(worst_url).host
        return Result("approve", f"scamgate: {worst_v.summary} (score {worst_v.risk_score}/100). "
                                 "Approve only if you trust where this link goes.",
                      f"scamgate:{h}", rules, worst_v.risk_score, hosts)
    if g.opaque_network:
        return Result("approve", "scamgate: this call can reach the network, but scamgate can't see where it "
                                 "goes, so it can't check it. Approve only if you know the destination.",
                      f"scamgate:opaque:{_canon_tool(g.tool)}", ["hook.opaque_network"], 0, [])
    return Result("none", hosts=hosts)


# ------------------------------------------------------------------ dialects

PRE_EVENTS = {"pre_tool_call": "hermes", "PreToolUse": "claude"}
POST_EVENTS = {"post_tool_call": "hermes", "PostToolUse": "claude", "PostToolUseFailure": "claude"}


def _call_ids(payload: dict) -> tuple[str, str]:
    extra = payload.get("extra") or {}
    session = str(payload.get("session_id") or extra.get("task_id") or "")
    call_id = str(extra.get("tool_call_id") or payload.get("tool_use_id") or "")
    return session, call_id


def _render(dialect: str, r: Result) -> dict:
    if r.decision == "none":
        return {}
    if dialect == "claude":
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                       "permissionDecision": "deny" if r.decision == "block" else "ask",
                                       "permissionDecisionReason": r.message}}
    out: dict = {"action": r.decision, "message": r.message}
    if r.decision == "approve" and r.rule_key:
        out["rule_key"] = r.rule_key
    return out


def handle(payload: dict) -> dict:
    event = payload.get("hook_event_name") or ""
    tool = payload.get("tool_name") or ""
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {"input": str(tool_input)}

    if event in POST_EVENTS:
        session, call_id = _call_ids(payload)
        if call_id:
            status = (payload.get("extra") or {}).get("status") or payload.get("status")
            if POST_EVENTS[event] == "claude":
                outcome = "not_run" if event == "PostToolUseFailure" else "ran"
            else:
                # Hermes model_tools.py: "ok" | "error" (ran, maybe failed) | "blocked" (hook or human said no)
                outcome = "not_run" if status == "blocked" else "ran"
            asklog.record_outcome(asklog.make_key(session, call_id), outcome)
        return {}

    if event not in PRE_EVENTS:
        return {}
    dialect = PRE_EVENTS[event]

    ok, why = integrity.check()
    if not ok:
        return _render(dialect, Result("block", f"scamgate's installed files don't match their release ({why}). "
                                                "Blocking all gated tools until it's fixed. Reinstall scamgate."))

    if reason := _tamper_reason(tool, tool_input):
        return _render(dialect, Result("block", f"scamgate blocked this because {reason}. "
                                                "Agents can't change the scam gate. Don't retry it another way; "
                                                "tell the user they must make this change themselves, outside "
                                                "the agent."))

    g = extract(tool, tool_input)
    if not g.urls and not g.opaque_network:
        return {}
    r = _evaluate(g)
    if r.decision != "none":
        session, call_id = _call_ids(payload)
        asklog.log_check(tool=tool, decision=r.decision, risk_score=r.score, rule_ids=r.rules,
                         targets=g.urls, hosts=r.hosts, stated_reason=g.stated_reason,
                         session=session, call_id=call_id, agent=dialect)
    return _render(dialect, r)


def run(payload: dict) -> tuple[str, int]:
    return json.dumps(handle(payload)), 0


def main(stdin=None, stdout=None) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    raw = stdin.read()
    payload: Any = None
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("hook payload must be a JSON object")
        text, code = json.dumps(handle(payload)), 0
    except Exception as exc:  # fail closed on pre events (and on unreadable input)
        event = payload.get("hook_event_name") if isinstance(payload, dict) else None
        if event in POST_EVENTS or (event and event not in PRE_EVENTS):
            stdout.write("{}")
            return 0
        msg = f"scamgate hook error, failing closed: {type(exc).__name__}: {exc}"
        dialect = PRE_EVENTS.get(event or "", "hermes")
        stdout.write(json.dumps(_render(dialect, Result("block", msg))))
        print(msg, file=sys.stderr)
        return 2
    stdout.write(text)
    return code
