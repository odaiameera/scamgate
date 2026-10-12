"""Enforcement hook: the harness runs scamgate before tools act, the model can't skip it.

`scamgate hook` reads one hook event as JSON on stdin and writes a decision on stdout.
It speaks two dialects:

- Hermes shell hooks (`pre_tool_call` / `post_tool_call`): {"action": "block"|"approve", ...}
- Claude Code hooks (`PreToolUse` / `PostToolUse`): {"hookSpecificOutput": {"permissionDecision": ...}}

What it gates (pre events):
1. Tamper attempts: writes to scamgate's own files/state/cache or the agent's hook config, and shell
   commands that remove the hook/MCP server or promote overrides. Always blocked.
2. Network-capable tools: every URL found in the arguments is checked. deny -> block,
   ask -> human approval. A network step whose destination can't be read -> human approval.
3. Everything else passes silently.

Never returns "allow": silence means "no objection", so the hook can only tighten the
agent's own permissions, never loosen them.

Fails closed: bad input or an internal error on a pre event blocks the call (exit 2).
"""

from __future__ import annotations

import hashlib
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
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 64
STALE_FOR_HOOK_HOURS = 7 * 24

# ------------------------------------------------------------------ tool classes

URL_TOOLS = {  # tools whose arguments name a destination directly
    "browser_navigate", "browser_tool", "web_extract", "webfetch", "fetch", "navigate",
}
CODE_TOOLS = {  # tools whose arguments are code/commands that may reach the network
    "terminal", "bash", "shell", "execute_code", "browser_exec", "browser_cdp", "browser_console",
    "powershell", "python",
}
WRITE_TOOLS = {"write_file", "patch", "write", "edit", "multiedit", "notebookedit", "str_replace_editor"}
# Tools whose text is a note, a search query or a message, not a visit.
QUIET_TOOLS = {"memory", "todo", "todo_list", "todowrite", "clarify", "send_message", "skill_manage",
               "hindsight_retain", "context_notes", "web_search", "websearch", "read_file", "search_files",
               "skill_view", "skills_list", "text_to_speech", "image_generate", "browser_click",
               "browser_snapshot", "browser_scroll", "browser_press", "browser_back"}
# Name fragments that mark an unknown (usually MCP) tool as able to reach the network.
NET_TOOL_HINT = re.compile(r"(?i)fetch|navigat|browser|browse|url|http|request|download|crawl|scrape|"
                           r"open_?page|visit|goto|shell|exec|run_?(?:command|code|script)|terminal|curl|"
                           r"evaluate|web")
URL_KEYS = ("url", "urls", "link", "href", "target", "uri", "endpoint", "page", "image_url", "video_url",
            "address", "location", "src", "source_url", "website")
CODE_KEYS = ("command", "code", "script", "expression", "cmd", "input", "cmdline", "function", "args", "argv")
PATH_KEYS = ("path", "file_path", "filepath", "notebook_path", "target_file")
REASON_KEYS = ("description", "prompt", "intent", "reason", "task", "goal")

_URL_RE = re.compile(r"""(?i)\b(?:https?|wss?|ftp)://[^\s'"<>`)\]}\\]+""")
# A URL whose host is built at run time: variables, templates, string concatenation.
_DYNAMIC_URL_RE = re.compile(
    r"""(?ix)\b(?:https?|wss?|ftp)://
        (?: [^\s/'"`]*[$%{}`]                  # $H, ${H}, %H%, {host}, `cmd` in the host part
          | [^\s/'"`]*['"`]\s*(?:\+|\.\s|['"])  # 'https://evil'+'shop', "https://evil""shop"
          | ['"`] )""")
_NET_RE = re.compile(
    r"(?i)(?:(?<![\w.-])(?:curl|wget|aria2c|httpie|http|nc|ncat|telnet|ssh|scp|sftp|rsync|ftp|tftp|socat|"
    r"nslookup|dig|host|ping|traceroute|"
    r"invoke-webrequest|invoke-restmethod|iwr|irm|start-bitstransfer|start-process|certutil|bitsadmin|"
    r"xdg-open|open|start|explorer|"
    r"pipx|uvx|npx|bunx)(?![\w.-])|"
    # Package managers: only the subcommands that download something.
    r"(?<![\w.-])(?:pip3?|poetry|conda|npm|yarn|pnpm|bun|deno|gem|cargo|go|brew|winget|choco|scoop|apt|apt-get|"
    r"docker|podman|helm)\s+(?:install|i|add|ci|update|upgrade|fetch|get|pull|download|publish|push|dlx|"
    r"create|search|source|run\s+https?)\b|"
    r"(?<![\w.-])(?:yarn|pnpm|bun)(?:\s*$|\s+--)|"           # bare 'yarn' / 'pnpm' installs
    r"(?<![\w.-])kubectl\s+(?:apply|create)\s+-f\s+https?|"
    r"\bgit\s+(?:clone|fetch|pull|push|submodule|ls-remote|remote\s+add)\b|"
    r"\buv\s+(?:pip|add|tool|sync|run\s+--with)\b|"
    r"requests\.|httpx\.|urllib|urlopen|aiohttp|socket\.|http\.client|ftplib|smtplib|"
    r"\bfetch\(|xmlhttprequest|websocket|navigator\.sendbeacon|"
    r"new_tab\(|goto_url\(|goto\(|navigate\(|page\.goto|window\.open|location\.(?:href|assign|replace)|"
    r"web_search\(|web_extract\(|webbrowser\.open|net\.webclient|downloadstring|downloadfile)"
)
# Signs a network step's destination is hidden in a variable, a file, a subshell or stdin.
_INDIRECT_RE = re.compile(r"""(?x)\$\{?\w|\$\(|`|<\(|%\w+%|\bopen\(|\.read\(\)|\bxargs\b|
                              \s-K\s|--config\b|\s-i\s|--input-file""")
_SEGMENT_SPLIT = re.compile(r"\n|;|&&|\|\||\|")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
_TAMPER_CMD = re.compile(
    r"(?i)(hermes\s+(?:hooks\s+(?:revoke|rm|remove)|mcp\s+(?:rm|remove)|plugins\s+(?:disable|remove)|"
    r"config\s+set\s+(?:hooks\b|hooks_auto_accept|mcp_servers))|"
    r"(?:scamgate|-m\s+scamgate(?:\.cli)?)\W{0,3}\s+\W{0,2}(?:promote|record-payment)\b|"
    r"\b(?:promote|record-payment)\b[^\n]*\s--(?:host|payee|account|decision)\b|"
    r"scamgate\.(?:overrides|payees|asklog|state|guard)\b|"
    r"(?:over['\"]?\s*\+\s*['\"]?rides|pay['\"]?\s*\+\s*['\"]?ees)|"
    r"__import__\(\s*['\"]scamgate|importlib[^\n]*scamgate|"
    r"from\s+scamgate\s+import\s+[^\n;]*\b(?:overrides|payees|asklog|state|guard)\b|"
    r"disableAllHooks|"
    r"(?:uv\s+tool|pipx|pip3?|uv\s+pip)\s+uninstall\s+(?:-y\s+)?scamgate|"
    r"claude\s+mcp\s+remove\s+scamgate|"
    r"--accept-hooks|HERMES_ACCEPT_HOOKS)"
)
_SHELL_WRITE = re.compile(
    r"(?i)(\brm\b|\bdel\b|\berase\b|\bmv\b|\bmove\b|\bcp\b|\bcopy\b|\btruncate\b|\bsed\s+-i|\btee\b|"
    r"\bln\b|\binstall\s+-|\bchmod\b|\bchown\b|\bperl\s+-[a-z]*i|\bdd\b|write_text|write_bytes|\.write\(|"
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
    from scamgate.feeds import cache_dir

    roots: list[str] = []
    pkg = Path(__file__).resolve().parent
    roots.append(str(pkg))
    # The virtualenv scamgate runs from (uv tool / pipx installs are venvs): its site-packages, where a
    # new .pth file would run code at every start, and its entry scripts. A system-wide install is
    # not covered: protecting /usr would block too much.
    if sys.prefix != sys.base_prefix:
        import sysconfig

        paths = sysconfig.get_paths()
        roots += [paths["purelib"], paths["scripts"]]
    roots.append(str(state_dir()))
    roots.append(str(cache_dir()))
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


# Path endings that are always protected, however the path is spelled (~, $HOME, globs, cd + relative).
_PROTECTED_TAILS = (
    (".claude/settings.json", ".claude/settings"), (".claude/settings.local.json", ".claude/settings"),
    (".claude/hooks", ".claude/hooks"), (".hermes/config.yaml", ".hermes/config"),
    ("hermes/config.yaml", "hermes/config"), ("shell-hooks-allowlist.json", "shell-hooks-allowlist"),
    ("hermes/agent-hooks", "hermes/agent-hooks"), ("hermes/plugins", "hermes/plugins"),
)
_TAIL_RE = re.compile(r"""(?ix)
    (?:\.claude|\.cl\*|\.c\*)[/\\]+(?:settings[\w.*]*|sett\*[\w.*]*|hooks)\b
  | \bhermes[/\\]+(?:config\.ya?ml|agent-hooks|plugins|hooks)\b
  | shell-hooks-allowlist
  | ['"]\.claude['"]\s*[)/]\s*(?:/\s*)?['"]settings
  | \bcd\s+\S*\.claude\b[^\n]*\bsettings
  | \bcd\s+\S*hermes\b[^\n]*\bconfig\.ya?ml""")


def _expand(text: str) -> str:
    t = text.replace("\\", "/")
    home = str(Path.home()).replace("\\", "/")
    t = re.sub(r"(?<![\w/])~(?=/|\b)", home, t)
    t = re.sub(r"\$\{?(?:HOME|USERPROFILE)\}?|\$env:(?:USERPROFILE|HOME)|%USERPROFILE%", home, t, flags=re.I)
    if hh := os.environ.get("HERMES_HOME"):
        t = re.sub(r"\$\{?HERMES_HOME\}?|\$env:HERMES_HOME|%HERMES_HOME%", hh.replace("\\", "/"), t, flags=re.I)
    if la := os.environ.get("LOCALAPPDATA"):
        t = re.sub(r"\$\{?LOCALAPPDATA\}?|\$env:LOCALAPPDATA|%LOCALAPPDATA%", la.replace("\\", "/"), t, flags=re.I)
    return t


def _mentions_protected(text: str, roots: list[str]) -> str | None:
    norm = _expand(text).lower()
    norm = re.sub(r"(?<![a-z])/([a-z])/", lambda m: f"{m.group(1)}:/", norm)
    for r in roots:
        tail = r.split(":/", 1)[-1] if ":/" in r else r.lstrip("/")
        if r in norm or (len(tail) > 12 and tail in norm):
            return r
    if m := _TAIL_RE.search(norm):
        return m.group(0).strip()
    return None


def _is_protected_tail(path: str) -> bool:
    p = _norm_path(path)
    return any(p.endswith("/" + t) or p == t or f"/{t}/" in p for t, _ in _PROTECTED_TAILS) \
        or bool(re.search(r"/\.claude/settings[^/]*\.json$", p))


# ------------------------------------------------------------------ extraction

@dataclass
class Gate:
    tool: str
    urls: list[str] = field(default_factory=list)
    opaque_network: bool = False
    opaque_detail: str = ""
    stated_reason: str = ""

    def opaque(self, detail: str) -> None:
        self.opaque_network = True
        self.opaque_detail = self.opaque_detail or detail


def _strings(value: Any, depth: int = 0) -> list[str]:
    if depth > MAX_DEPTH:
        raise ValueError(f"tool input nested more than {MAX_DEPTH} levels")
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _strings(v, depth + 1)]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v, depth + 1)]
    return []


def _first_comment(code: str) -> str:
    for line in code.splitlines():
        s = line.strip()
        if s.startswith(("#", "//")):
            return s.lstrip("#/ ").strip()
        if s:
            break
    return ""


_BARE_HOST = re.compile(r"^[\w.-]+\.[a-z]{2,}(?::\d+)?(?:[/?#].*)?$", re.I)
_HOST_TOKEN = re.compile(r"(?i)(?<![\w@/.:$-])((?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:/[^\s'\"`;|&]*)?)(?![\w-])")
_NOT_A_HOST = re.compile(r"(?i)\.(?:py|js|mjs|ts|sh|json|ya?ml|toml|md|txt|csv|html?|css|lock|cfg|ini|exe|zip|tar|"
                         r"gz|png|jpe?g|gif|pdf|log|env|whl|ps1|bat|cmd|get|post|read|text|status_code)$")


def _looks_like_bare_host(s: str) -> bool:
    s = s.strip()
    return bool(s) and " " not in s and "." in s and not s.startswith(("/", ".", "~")) and bool(_BARE_HOST.match(s))


def _bare_hosts(segment: str) -> list[str]:
    out = []
    for tok in _HOST_TOKEN.findall(segment):
        host = tok.split("/", 1)[0].split(":", 1)[0]
        if _NOT_A_HOST.search(host) or host.lower().split(".")[-1] in {"get", "post", "run", "main"}:
            continue
        out.append(tok)
    return out


def _is_local(url: str) -> bool:
    return parse(url).host in _LOCAL_HOSTS


def _segments(code: str) -> list[str]:
    return [s.strip() for s in _SEGMENT_SPLIT.split(code) if s.strip()]


def _scan_code(code: str, g: Gate) -> None:
    """URLs, bare hosts after network commands, and opaque network steps, judged per segment."""
    g.urls += _URL_RE.findall(code)
    if m := _DYNAMIC_URL_RE.search(code):
        g.opaque(f"a link built at run time ({m.group(0).strip()[:40]})")
    is_program = any(k in code for k in ("import ", "def ", "const ", "await ", "=>", "require("))
    has_literal = bool(_URL_RE.search(code))
    for seg in _segments(code):
        if seg.lstrip().startswith(("#", "//")) or not _NET_RE.search(seg):
            continue
        seg_urls = _URL_RE.findall(seg)
        bare = _bare_hosts(seg) if not seg_urls else []
        g.urls += bare
        indirect = bool(_INDIRECT_RE.search(seg))
        if (seg_urls or bare) and not indirect:
            continue
        if is_program and has_literal and not indirect:
            continue  # url = "https://..." on one line, requests.get(url) on the next
        g.opaque(f"'{seg[:60]}'")


def extract(tool: str, tool_input: dict) -> Gate:
    t = _canon_tool(tool)
    g = Gate(tool=tool)
    everything = _strings(tool_input)  # also enforces MAX_DEPTH for every tool
    for k in REASON_KEYS:
        if isinstance(tool_input.get(k), str):
            g.stated_reason = tool_input[k]
            break
    if t in QUIET_TOOLS or t in WRITE_TOOLS:
        return g
    netty = t in URL_TOOLS or bool(NET_TOOL_HINT.search(t))
    if t in URL_TOOLS or any(k in tool_input for k in URL_KEYS):
        for k in URL_KEYS:
            for s in _strings(tool_input.get(k)):
                found = _URL_RE.findall(s)
                if found:
                    g.urls += found
                    if _DYNAMIC_URL_RE.search(s):
                        g.opaque("a link built at run time")
                elif _looks_like_bare_host(s):
                    g.urls.append(s.strip())
                elif s.strip() and netty:
                    g.opaque(f"a destination scamgate can't read ('{s.strip()[:40]}')")
        if t in URL_TOOLS:
            for s in everything:
                g.urls += _URL_RE.findall(s)
        if t in URL_TOOLS and not g.urls:
            g.opaque("no readable link")
    if t in CODE_TOOLS:
        code = "\n".join(_strings({k: tool_input.get(k) for k in CODE_KEYS}))
        if not g.stated_reason:
            g.stated_reason = _first_comment(code)
        _scan_code(code, g)
    elif t not in URL_TOOLS:
        # Unknown tool (often MCP): any link anywhere in its arguments is checked, and network-ish
        # tools get their code-like arguments scanned like a shell command.
        for s in everything:
            g.urls += _URL_RE.findall(s)
        if netty:
            code = "\n".join(_strings({k: tool_input.get(k) for k in CODE_KEYS}))
            if code:
                _scan_code(code, g)
            if any(_DYNAMIC_URL_RE.search(s) for s in everything):
                g.opaque("a link built at run time")
    seen, out = set(), []
    for u in g.urls:
        u = u.rstrip(".,;:'\"")
        if u and u not in seen:
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
            if isinstance(v, str) and ((hit := _is_protected(v, roots)) or _is_protected_tail(v)):
                return f"it would change scamgate's protected files ({hit or v})"
    if t in CODE_TOOLS or (t not in QUIET_TOOLS and NET_TOOL_HINT.search(t)):
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


def _feed_status() -> str | None:
    """None when the feeds are fine, else a short warning for the human."""
    f = _feeds()
    if not f:
        return ("No known-bad-link feeds are cached, so scamgate is checking without its phishing lists. "
                "Run `scamgate update-feeds`.")
    if stale := f.stale_feeds(hours=STALE_FOR_HOOK_HOURS):
        return f"scamgate's phishing lists are out of date ({', '.join(sorted(stale))}). Run `scamgate update-feeds`."
    return None


def _feeds_policy() -> str:
    return (os.environ.get("SCAMGATE_NO_FEEDS") or "ask").strip().lower()


def _key(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()[:10]


def _check(url: str, reason: str) -> Any:
    """Score a URL. The agent's stated reason may add risk, never remove it."""
    base = engine.check_url(url, None, feeds=_feeds())
    if not reason:
        return base
    with_reason = engine.check_url(url, reason, feeds=_feeds())
    return with_reason if with_reason.risk_score > base.risk_score else base


def _evaluate(g: Gate) -> Result:
    rank = {Decision.allow: 0, Decision.ask: 1, Decision.deny: 2}
    worst, worst_v, worst_url = Decision.allow, None, None
    hosts, rules = [], []
    for u in g.urls:
        v = _check(u, g.stated_reason)
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
    if len(g.urls) > MAX_URLS:
        return Result("approve", f"scamgate: this call opens {len(g.urls)} links at once. None is on a known-bad "
                                 "list, but that's too many to review one by one. Approve once, only if you expect this.",
                      f"scamgate:bulk:{_key(*sorted(g.urls))}", ["hook.bulk"], 0, hosts)
    if worst is Decision.ask:
        h = parse(worst_url).host
        fired = sorted({r.rule_id for r in worst_v.reasons})
        return Result("approve", f"scamgate: {worst_v.summary} (score {worst_v.risk_score}/100). "
                                 "Approve only if you trust where this link goes.",
                      f"scamgate:{h}:{_key(*fired)}", rules, worst_v.risk_score, hosts)
    if g.opaque_network:
        what = f" ({g.opaque_detail})" if g.opaque_detail else ""
        return Result("approve", f"scamgate: this call can reach the network, but scamgate can't see where it "
                                 f"goes{what}, so it can't check it. Approve once, only if you know the destination.",
                      f"scamgate:opaque:{_canon_tool(g.tool)}:{_key(g.opaque_detail, *sorted(g.urls))}",
                      ["hook.opaque_network"], 0, hosts)
    remote = [u for u in g.urls if not _is_local(u)]
    if remote and not _feeds() and _feeds_policy() == "ask":
        return Result("approve", f"scamgate: {_feed_status()} Approve once, only if you trust these links.",
                      f"scamgate:nofeeds:{_key(*sorted(hosts))}", ["hook.no_feeds"], 0, hosts)
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
                outcome = "ran"  # PostToolUse and PostToolUseFailure both fire after the tool ran
            else:
                # Hermes model_tools.py: "ok" | "error" (ran, maybe failed) | "blocked" (hook or human said no)
                outcome = "not_run" if status == "blocked" else "ran"
            asklog.record_outcome(asklog.make_key(session, call_id), outcome)
        return {}

    if not event and tool:
        event = "pre_tool_call"  # a tool call with no event name: gate it rather than wave it through
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
    if r.decision != "none" and (warn := _feed_status()) and warn not in r.message:
        r.message = f"{r.message} Note: {warn}"
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
    raw = stdin.read(MAX_INPUT_BYTES + 1)
    payload: Any = None
    try:
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError(f"hook input too large (over {MAX_INPUT_BYTES // (1024 * 1024)} MB)")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("hook payload must be a JSON object")
        text, code = json.dumps(handle(payload)), 0
    except Exception as exc:  # fail closed on pre events (and on unreadable input)
        event = payload.get("hook_event_name") if isinstance(payload, dict) else None
        if event in POST_EVENTS or (event and event not in PRE_EVENTS):
            stdout.write("{}")
            return 0
        msg = f"scamgate hook error, failing closed: {type(exc).__name__}: {str(exc)[:200]}"
        dialect = PRE_EVENTS.get(event or "", "hermes")
        stdout.write(json.dumps(_render(dialect, Result("block", msg))))
        print(msg, file=sys.stderr)
        return 2
    stdout.write(text)
    return code
