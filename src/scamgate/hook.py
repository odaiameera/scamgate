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

from . import asklog, engine, integrity
from .models import Decision
from .rules.url import parse, repair_schemes as _repair_schemes
from .state import state_dir

MAX_URLS = 20
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 64
MAX_SCRIPT_BYTES = 256 * 1024
MAX_SCRIPT_DEPTH = 4
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

_URL_RE = re.compile(r"""(?i)\b(?:https?|wss?|ftp)://(?:\[[0-9a-f:.]+\]|[^\s'"<>`)\]}\\])+""")  # [::1] stays whole
# A URL whose host is built at run time: variables, templates, string concatenation.
_DYNAMIC_URL_RE = re.compile(
    r"""(?ix)\b(?:https?|wss?|ftp)://
        (?: [^\s/'"`]*[$%{}`]                  # $H, ${H}, %H%, {host}, `cmd` in the host part
          | [^\s/'"`]*['"`]\s*(?:\+|\.\s|['"])  # 'https://evil'+'shop', "https://evil""shop"
          | ['"`] )""")
_NET_RE = re.compile(
    r"(?i)(?:(?<![\w.-])(?:curl|wget|aria2c|httpie|http|nc|ncat|telnet|ssh|sftp|ftp|tftp|socat|gnutls-cli|"
    r"test-netconnection|tnc|"
    r"nslookup|dig|host|ping|traceroute|"
    r"invoke-webrequest|invoke-restmethod|iwr|irm|start-bitstransfer|start-process|certutil|bitsadmin|"
    r"xdg-open|explorer|"
    r"pipx|uvx|npx|bunx)(?![\w.-])|"
    r"(?:^|(?<=[;&|(]\s)|(?<=[;&|(]))\s*(?:open|start)\s+(?!-\w*\s*$)|"   # macOS open / Windows start as a command
    r"(?<![\w.-])(?:rsync|scp|sftp)(?![\w.-])|"     # only with a host:path argument
    r"\bopenssl\s+s_client\b|"
    # Package managers: only the subcommands that download something.
    r"(?<![\w.-])(?:pip3?|poetry|conda|npm|yarn|pnpm|bun|deno|gem|cargo|go|brew|winget|choco|scoop|apt|apt-get|"
    r"docker|podman|helm)\s+(?:install|i|add|ci|update|upgrade|fetch|get|pull|download|publish|push|dlx|"
    r"create|search|source|run\s+https?)\b|"
    r"(?<![\w.-])(?:yarn|pnpm|bun)(?:\s*$|\s+--)|"           # bare 'yarn' / 'pnpm' installs
    r"(?<![\w.-])kubectl\s+(?:apply|create)\s+-f\s+https?|"
    # git fetch/pull/push go to remotes already configured (adding one with a URL is checked).
    r"\bgit\s+(?:clone|ls-remote|remote\s+(?:add|set-url)|submodule\s+add)\b|"
    r"\buv\s+(?:pip\s+install|add|tool\s+(?:install|run)|run\s+--with)\b|"
    r"requests\.|httpx\.|urllib|urlopen|aiohttp|socket\.|http\.client|ftplib|smtplib|"
    r"\bfetch\(|xmlhttprequest|websocket|navigator\.sendbeacon|"
    r"new_tab\(|goto_url\(|goto\(|navigate\(|page\.goto|window\.open|location\.(?:href|assign|replace)|"
    r"web_search\(|web_extract\(|webbrowser\.open|net\.webclient|downloadstring|downloadfile|"
    r"/dev/(?:tcp|udp)/)"  # bash opens a socket for these paths
)
# Signs a network step's destination is hidden in a variable, a file, a subshell or stdin.
_INDIRECT_RE = re.compile(r"""(?ix)\$\{?\w|\$\(|`|<\(|%\w+%|\bopen\(|\.read\(\)|\bxargs\b|
                              \s-K\s|--config\b|\s-i\s|--input-file|
                              b64decode|b32decode|a85decode|fromhex|unhexlify|codecs\.|atob\(|fromcharcode|
                              \[::-1\]|['"]\.join\(|\bchr\(|rot13|reverse\(\)|\bbase64\s+-d|\bxxd\s+-r""")
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
    r"\b(?:vim?|nvim|ed|ex|emacs|nano|pico|micro|joe|notepad(?:\+\+)?|code|subl|gedit|kate|rsync|patch)\b|"
    r"\s-exec\b|\s-execdir\b|\s-delete\b|"
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
    from .feeds import cache_dir

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
    ("hermes/profiles", "hermes/profiles"), (".hermes/profiles", ".hermes/profiles"),
)
_TAIL_RE = re.compile(r"""(?ix)
    (?:\.claude|\.cl\*|\.c\*)[/\\]+(?:settings[\w.*]*|sett\*[\w.*]*|hooks)\b
  | \bhermes[/\\]+(?:config\.ya?ml|agent-hooks|plugins|hooks|profiles)\b
  | \.hermes[/\\]+profiles\b
  | shell-hooks-allowlist
  | ['"]\.claude['"]\s*[)/]\s*(?:/\s*)?['"]settings
  | \bcd\s+\S*\.claude\b[^\n]*\bsettings
  | \bcd\s+\S*hermes\b[^\n]*\bconfig\.ya?ml
  | \.claude\b[^\n]{0,80}\bsettings
  | \bsettings[\w.*'"]*[^\n]{0,80}\.claude\b""")


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


# Common generic TLDs. Any two-letter label also counts (country codes), except ones that are
# far more often code: user.id, re.search's "re", file.py, os.path's "os"...
_GTLDS = set("""com net org edu gov mil int info biz name pro io co ai app dev me tv cc xyz top site online shop
store tech cloud live link click page blog news club space website fun icu buzz lol cam sbs cfd rest bar mobi asia
tel travel jobs email digital agency solutions services support network systems software security finance bank
money pay credit loan tickets events zip mov ink one world today life plus host global wiki chat social art design
studio media gg network center group company business market exchange trade tokyo london dublin irish""".split())
_CODE_2 = {"id", "re", "py", "js", "ts", "sh", "md", "rs", "pl", "os", "np", "pd", "tf", "db", "fs", "el", "go",
           "rb", "cs", "pm", "ps", "mk", "am", "in", "is", "it", "to", "at", "as", "do", "no", "on", "or", "so", "up"}
_IMPORT_BEFORE = re.compile(r"(?:\bimport|\bfrom)\s+[\w., ]*$|\bas\s+$|\brequire\(\s*['\"]$")


def _plausible_host(host: str) -> bool:
    labels = host.lower().split(".")
    tld = labels[-1]
    if len(labels) < 2 or not all(labels):
        return False
    return tld in _GTLDS or (len(tld) == 2 and tld.isalpha() and tld not in _CODE_2)


_REMOTE_TRANSFER = re.compile(r"(?i)(?<![\w.-])(?:scp|sftp|rsync)(?![\w.-])")
_TRANSFER_VALUE_FLAGS = {"-P", "-p", "-S", "-F", "-i", "-c", "-o", "-J", "-l", "-B", "-D", "-R", "-b", "-e", "--rsh", "--port"}
_TRANSFER_HOST = re.compile(r"(?i)^(?:[\w.+~-]+@)?(?P<host>(?:[a-z0-9-]+\.)+[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:]+\])(?::.*)?$")
_TRANSFER_URL = re.compile(r"(?i)^(?:scp|sftp|rsync)://(?:[^/@\s]+@)?(?P<host>[^/:\s]+)")


def _transfer_hosts(segment: str) -> list[str]:
    """Hosts named by scp, sftp and rsync, including absolute user@host:/path destinations."""
    import shlex
    if not _REMOTE_TRANSFER.search(segment):
        return []
    try:
        toks = shlex.split(segment, posix=True)
    except ValueError:
        return []
    while toks and toks[0] in ("sudo", "command"):
        toks = toks[1:]
    if not toks or toks[0].lower() not in ("scp", "sftp", "rsync"):
        return []
    out, i = [], 1
    while i < len(toks):
        tok = toks[i]
        if tok in _TRANSFER_VALUE_FLAGS and i + 1 < len(toks):
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        m = _TRANSFER_URL.match(tok) or _TRANSFER_HOST.match(tok)
        if m:
            host = m.group("host").strip("[]")
            if _plausible_host(host):
                out.append("https://" + host)
        i += 1
    return ["local-transfer"] if not out else out


_SOCAT_ADDR = re.compile(r"(?i)\b(?:tcp[46]?|udp[46]?|openssl|ssl|tls|proxy|socks[45]a?)"
                         r"(?:-connect)?:(localhost|(?:[a-z0-9-]+\.)+[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:]+\])"
                         r"(?::(\d+))?")


def _bare_hosts(segment: str) -> list[str]:
    out = [f"https://{m.group(1)}" + (f":{m.group(2)}" if m.group(2) else "") for m in _SOCAT_ADDR.finditer(segment)]
    if out:
        return out
    out.extend(_transfer_hosts(segment))
    for m in _HOST_TOKEN.finditer(segment):
        tok = m.group(1)
        host = tok.split("/", 1)[0].split(":", 1)[0]
        after = segment[m.end():m.end() + 1]
        if (_NOT_A_HOST.search(host) or not _plausible_host(host) or after in ("(", "[", "=")
                or _IMPORT_BEFORE.search(segment[max(0, m.start() - 60):m.start()])):
            continue
        out.append("https://" + tok)
    return out


_WORD_RUN = re.compile(r"[\w.]+")
_NAME_START = re.compile(r"[A-Za-z_]")


def _code_like(s: str) -> bool:
    r"""Same answer as `re.compile(r"[A-Za-z_][\w.]*\(").search(s)`, without the quadratic scan.

    That pattern backtracks from every start position to the end of the string, so one long
    identifier with no parenthesis in it costs O(n^2): a 100k-character command takes about 40 s
    inside the hook, and the hook input cap is 2 MiB. Scanning whole word/dot runs once gives the
    identical answer in O(n).
    """
    for m in _WORD_RUN.finditer(s):
        end = m.end()
        if end < len(s) and s[end] == "(" and _NAME_START.search(s, m.start(), end):
            return True
    return False


_PIP_VALUE_FLAGS = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url",
                    "--extra-index-url", "-f", "--find-links", "-t", "--target", "--prefix", "--python", "-p",
                    "--root", "--platform", "--python-version", "--implementation", "--abi", "--only-binary",
                    "--no-binary", "--progress-bar", "--log", "--cache-dir", "--src", "--upgrade-strategy"}
_PATHISH = re.compile(r"^(?:[.~/\\]|[a-zA-Z]:[/\\])|[/\\]|\.(?:whl|tar\.gz|zip|txt|in|toml|lock|cfg)$")
_LOCAL_ONLY = re.compile(r"""(?ix)^(?:sudo\s+)?(?:
    uv\s+(?:sync|lock)\b | poetry\s+(?:install|lock)\b | bundle(?:\s+install)?\b | cargo\s+(?:build|fetch|test|check)\b |
    go\s+mod\s+(?:download|tidy|vendor)\b | go\s+(?:build|test)\b | composer\s+install\b | pipenv\s+(?:install|sync)\s*$ |
    pipenv\s+sync\b)""")


# Commands that only read or print text: "grep requests.get" or "echo curl" mention the network, they
# don't use it. Pipes and ; already split segments, so "grep x | curl ..." is judged per part.
_TEXT_ONLY = re.compile(r"(?i)^(?:grep|egrep|fgrep|rg|ag|ack|cat|bat|head|tail|less|more|wc|sort|uniq|cut|ls|dir|"
                        r"echo|printf|type|file|stat|sed\s+-n|awk\s+'[^']*'\s+[\w./-]+$|"
                        r"git\s+(?:log|grep|diff|show|status|blame))\b")
_SUBST = re.compile(r"\$\(|`|<\(|>\(")
# Anything a shell could rewrite: quotes, backslash escapes. Without them, word splitting is whitespace.
_NEEDS_SHELL = re.compile(r"""['"\\]""")
_WHITESPACE_SPLIT = re.compile(r"[ \t\r\n]+")


def _words(seg: str) -> list[str] | None:
    """The segment's words after the shell removes quotes and escapes. None if it can't be split.

    shlex is pure Python and builds its tokens one character at a time, so it costs seconds on a
    megabyte-sized segment. With no quote and no backslash there is nothing for it to remove, and
    splitting on the shell's own whitespace set gives the same words at C speed.
    """
    if _NEEDS_SHELL.search(seg) is None:
        return [w for w in _WHITESPACE_SPLIT.split(seg) if w]
    import shlex

    try:
        return shlex.split(seg, posix=True)
    except ValueError:
        return None


def _local_install(seg: str, words: list[str] | None) -> bool:
    """Installs from a lockfile, manifest or local path: the destination is the configured registry and
    the packages are already declared in the repo, so there's nothing new for a human to judge."""
    if _LOCAL_ONLY.search(seg):  # the caller checks this before splitting; kept so the answer stands alone
        return True
    if words is None:
        return False
    toks = list(words)
    while toks and toks[0] in ("sudo", "python", "python3", "py", "-m"):
        toks = toks[1:]
    if not toks:
        return False
    tool = toks[0].lower()
    if tool in ("open", "start", "xdg-open", "explorer") and len(toks) >= 2:
        # Opening a local file or app. A URL or a bare host is handled (and checked) as a link.
        arg = toks[-1]
        return ("://" not in arg and not _INDIRECT_RE.search(seg)
                and (_NOT_A_HOST.search(arg) is not None or not _plausible_host(arg.split("/")[0])))
    if tool == "uv" and len(toks) > 1 and toks[1] == "pip":
        tool, toks = "pip", toks[1:]
    args = toks[1:]
    if tool in ("pip", "pip3"):
        if not args or args[0] not in ("install", "sync"):
            return False
        it = iter(args[1:])
        for a in it:
            if a in _PIP_VALUE_FLAGS:
                v = next(it, "")
                if a in ("-r", "--requirement", "-c", "--constraint", "-e", "--editable") and "://" not in v \
                        and not _PATHISH.search(v):
                    return False
                continue
            if a.startswith("-"):
                continue
            if "://" in a or not _PATHISH.search(a):
                return False  # a named package (or a URL, which is checked on its own)
        return True
    if tool in ("npm", "pnpm", "yarn", "bun"):
        if not args:
            return tool == "yarn"
        if args[0] not in ("install", "i", "ci"):
            return False
        return all(a.startswith("-") for a in args[1:])
    return False


def _is_local(url: str) -> bool:
    import ipaddress

    h = parse(url).host.strip("[]")
    if h in _LOCAL_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


_WORD_URL = re.compile(r"(?i)^(?:--?[\w-]+=)?((?:https?|wss?|ftp)://.+)$")
_DEV_SOCKET = re.compile(r"/dev/(?:tcp|udp)/([^/\s]+)/\d+")
_RUNTIME_PART = re.compile(r"[$`]|%\w+%")


def _shell_destinations(seg: str, words: list[str] | None) -> tuple[list[str], bool]:
    """Destinations a shell command names, read from its words after the shell removes quotes and
    escapes, so a quoted '@' or ')' can't cut the link short. (urls, could_not_split)."""
    if words is None:
        return [], True
    out = []
    for w in words:
        if (m := _WORD_URL.match(w)) and not _RUNTIME_PART.search(m.group(1)):
            out.append(m.group(1))  # the whole word is one destination
        out += [f"https://{h}" for h in _DEV_SOCKET.findall(w) if not _RUNTIME_PART.search(h)]
    return out, False


def _segments(code: str) -> list[str]:
    return [s.strip() for s in _SEGMENT_SPLIT.split(code) if s.strip()]


# Code that is decoded or downloaded and then run: scamgate can't read what it does, so a human
# approves it. Either half alone (decoding a file, running a script) is ordinary.
_DECODE = r"""(?:(?:base(?:32|64)|b32|b64)\s+(?:-d|-D|--decode)\b|openssl\s+(?:base64|enc)\b[^|;&]*\s-d\b|xxd\s+-r|\b(?:b(?:64|32|16|85)decode|decode_base64|decode64)\b|\ba85decode|\bfromhex\b|\bunhexlify|codecs\.decode|\bdecompress\(|rot13|\batob\(|Buffer\.from\([^)]*['"](?:base64|hex)['"]|FromBase64String|\bcurl\b|\bwget\b|\binvoke-webrequest\b|\biwr\b|\birm\b|downloadstring)"""
_RUNNER = r"(?:ba|z|k|da|fi|c|tc)?sh|python[\d.]*|py|perl|ruby|node|php|pwsh|powershell|iex|invoke-expression"
_DECODE_RUN = re.compile(
    rf"""(?ix)
      {_DECODE}[^\n;&]*\|\s*(?:sudo\s+)?(?:{_RUNNER})\b(?!\s+-?\w*\.\w)           # ... | base64 -d | bash
    | (?:(?:{_RUNNER})\s+(?:-c\s+)?|\beval\s+|\bsource\s+|\.\s+)["']?(?:\$\(|<\(|`)[^\n]*{_DECODE}  # bash -c "$(... -d)"
    | \b(?:exec|eval|compile|system|os\.system)\s*\([^\n]*{_DECODE}                                  # exec(b64decode(..))
    | new\s+Function\s*\([^\n]*{_DECODE}
    | (?:iex|invoke-expression)\b[^\n]*{_DECODE}
    | {_DECODE}[^\n]*\|\s*(?:iex|invoke-expression)\b
    | (?:pwsh|powershell)(?:\.exe)?\b[^\n]*\s-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{{8,}}
    | {_DECODE}[^\n;&]*>>?\s*\S+\s*(?:&&|;)\s*(?:{_RUNNER})\b
    """)
def _decoded_write_then_run(code: str) -> bool:
    """Decoded bytes written to a file and a shell execution in the same command."""
    import re
    return all(re.search(part, code, re.I | re.S) for part in
               (_DECODE, r"write_bytes|write_text", r"os\s*\.\s*system|subprocess"))


def _scan_code(code: str, g: Gate) -> None:
    """URLs, bare hosts after network commands, and opaque network steps, judged per segment."""
    code = _repair_schemes(code)
    if m := _DECODE_RUN.search(code):
        g.opaque(f"code that is decoded or downloaded and then run ('{m.group(0).strip()[:50]}')")
    elif _decoded_write_then_run(code):
        g.opaque("decoded content written to a file and then run")
    g.urls += _URL_RE.findall(code)
    if m := _DYNAMIC_URL_RE.search(code):
        g.opaque(f"a link built at run time ({m.group(0).strip()[:40]})")
    is_program = any(k in code for k in ("import ", "def ", "const ", "await ", "=>", "require("))
    has_literal = bool(_URL_RE.search(code))
    for seg in _segments(code):
        # The cheap questions first, in the order that costs least: a comment, a segment with no
        # network program in it, or a local install is answered without splitting the segment into
        # words, and splitting a multi-megabyte segment for nothing is the slow path this avoids.
        if (seg.lstrip().startswith(("#", "//")) or not _NET_RE.search(seg)
                or _LOCAL_ONLY.search(seg)):
            continue
        words = _words(seg)
        if _local_install(seg, words) or (_TEXT_ONLY.match(seg) and not _SUBST.search(seg)):
            continue
        if not is_program:  # program source is read by the literal/run-time checks, not as shell words
            dests, unsplittable = _shell_destinations(seg, words)
            if unsplittable:
                g.opaque(f"'{seg[:60]}'")
                continue
            g.urls += dests
        else:
            dests = []
        seg_urls = _URL_RE.findall(seg) or dests
        bare = _bare_hosts(seg) if not seg_urls else []
        if bare == ["local-transfer"]:
            continue
        g.urls += bare
        if bare and all(_is_local(u) for u in bare):
            continue
        indirect = bool(_INDIRECT_RE.search(seg))
        if seg_urls and not indirect:
            continue
        if bare and not indirect and not _code_like(seg):
            continue  # a shell command naming its host; in code, only a literal URL counts as readable
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
                s = _repair_schemes(s)
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
                g.urls += _URL_RE.findall(_repair_schemes(s))
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
        from .feeds import LazyFeedIndex

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
        h = parse(worst_url).host or f"unreadable-{_key(worst_url)}"  # one "always" never covers other links
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


_RANK = {"none": 0, "approve": 1, "block": 2}
_PAYMENT_HELP = ("Before paying, confirm the payee and account through a channel you already trust (not one "
                 "from this conversation). After a real payment, run `scamgate record-payment` yourself so "
                 "next time it counts as a known payee.")


def _payment_result(tool: str, tool_input: dict) -> Result | None:
    """Payments: score money-moving tool calls; payments hidden in shell/code go to a human."""
    from . import paygate
    from .models import PaymentCheck

    t = _canon_tool(tool)
    if t in QUIET_TOOLS or t in WRITE_TOOLS:
        return None
    if t in CODE_TOOLS or NET_TOOL_HINT.search(t):
        code = "\n".join(_strings({k: tool_input.get(k) for k in CODE_KEYS}))
        if code and (cp := paygate.scan_code(code)):
            return Result("approve", f"scamgate: this call makes a payment ({cp.detail}), and scamgate can't read "
                                     f"who gets paid or how much. Approve once, only if you started this payment. "
                                     + _PAYMENT_HELP,
                          f"scamgate:paycode:{_canon_tool(tool)}:{_key(code)}", ["hook.payment_in_code"], 0, cp.hosts)
    p = paygate.detect(tool, t, tool_input)
    if p is None:
        return None
    if not p.payee_account or not p.amount_known:
        missing = "who gets paid" if not p.payee_account else "how much"
        return Result("approve", f"scamgate: '{tool}' looks like a payment (from {p.why}), but scamgate can't read "
                                 f"{missing}, so it can't check it. Approve once, only if you started this payment. "
                                 + _PAYMENT_HELP,
                      f"scamgate:payopaque:{t}:{_key(_canonical_json(tool_input))}", ["hook.payment_unreadable"])
    v = engine.check_payment(PaymentCheck(payee_name=p.payee_name, payee_account=p.payee_account, amount=p.amount,
                                          currency=p.currency or "?", method=p.method, context_text=p.context or None))
    rules = [r.rule_id for r in v.reasons]
    what = f"{p.amount:g} {p.currency}".strip() + f" to '{p.payee_name[:40]}'"
    warn = (" " + " ".join(v.warnings)) if v.warnings else ""
    if v.decision is Decision.deny:
        return Result("block", f"scamgate blocked this payment ({what}): {v.summary} (score {v.risk_score}/100).{warn} "
                               "Don't retry it another way. Tell the user what was blocked and why.",
                      None, rules, v.risk_score)
    if v.decision is Decision.ask:
        return Result("approve", f"scamgate: check this payment ({what}): {v.summary} (score {v.risk_score}/100).{warn} "
                                 + _PAYMENT_HELP,
                      f"scamgate:pay:{_key(p.payee_account.upper(), f'{p.amount:.2f}', *sorted(set(rules)))}",
                      rules, v.risk_score)
    return None


def _canonical_json(v: Any) -> str:
    return json.dumps(v, sort_keys=True, default=str)[:20000]


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

    from .harden import gate_extra, own_check

    if own_check(tool):
        return {}

    if reason := _tamper_reason(tool, tool_input):
        return _render(dialect, Result("block", f"scamgate blocked this because {reason}. "
                                                "Agents can't change the scam gate. Don't retry it another way; "
                                                "tell the user they must make this change themselves, outside "
                                                "the agent."))

    extra = gate_extra(tool, tool_input)
    g = extract(tool, tool_input)
    pay = _payment_result(tool, tool_input)
    r = _evaluate(g) if (g.urls or g.opaque_network) else Result("none")
    if extra is not None and _RANK[extra.decision] > _RANK[r.decision]:
        r = extra
    if pay is not None and _RANK[pay.decision] >= _RANK[r.decision]:  # on a tie the payment reason is clearer
        r = pay
    if r.decision == "none":
        return {}
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
