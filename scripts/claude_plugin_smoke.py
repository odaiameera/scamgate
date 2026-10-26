"""Smoke test for the Claude Code plugin's two commands, run from a built wheel through uvx.

The plugin runs `uvx scamgate==X hook` and `uvx scamgate==X serve`. This runs the same entry points from a
wheel (`uvx --from <wheel> scamgate ...`) with a small test phishing list, and checks what Claude Code
would get back. Needs only uv; it talks to the MCP server with plain JSON-RPC over stdio.

usage: python scripts/claude_plugin_smoke.py dist/scamgate-X-py3-none-any.whl
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BAD = "login-verify.example"  # reserved name, never resolves


def make_cache(root: Path) -> Path:
    cache = root / "cache"
    cache.mkdir()
    now = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    (cache / "meta.json").write_text(json.dumps({"phishing_database_domains": {"fetched_at": now},
                                                 "openphish": {"fetched_at": now}}))
    (cache / "phishing_database_domains.hosts.txt").write_text(BAD + "\n")
    for name in ("phishing_database_domains.urls.txt", "openphish.urls.txt", "openphish.hosts.txt"):
        (cache / name).write_text("")
    return cache


def hook(wheel: str, env: dict, payload: dict) -> tuple[int, dict]:
    p = subprocess.run(["uvx", "--from", wheel, "scamgate", "hook"], input=json.dumps(payload),
                       capture_output=True, text=True, env=env, timeout=300)
    return p.returncode, json.loads(p.stdout or "null")


def pre(command: str) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command},
            "session_id": "smoke", "tool_use_id": "t1", "cwd": os.getcwd()}


def mcp_tools(wheel: str, env: dict) -> list[dict]:
    server = subprocess.Popen(["uvx", "--from", wheel, "scamgate", "serve"], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=env)
    assert server.stdin and server.stdout
    stdin, stdout = server.stdin, server.stdout

    def send(msg: dict) -> None:
        stdin.write(json.dumps(msg) + "\n")
        stdin.flush()

    def reply(want_id: int) -> dict:
        while True:
            line = stdout.readline()
            if not line:
                raise SystemExit("scamgate serve exited before answering")
            msg = json.loads(line)
            if msg.get("id") == want_id:
                return msg

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                         "clientInfo": {"name": "scamgate-smoke", "version": "1"}}})
        init = reply(1)
        assert init["result"]["serverInfo"]["name"] == "scamgate", init
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        return reply(2)["result"]["tools"]
    finally:
        stdin.close()
        try:
            server.wait(timeout=30)
        except subprocess.TimeoutExpired:
            server.kill()


def main() -> int:
    wheel = Path(sys.argv[1]).resolve().as_posix()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        state = root / "state"
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env.update({"SCAMGATE_CACHE_DIR": str(make_cache(root)), "SCAMGATE_STATE_DIR": str(state),
                    "SCAMGATE_AUTO_UPDATE": "0"})

        code, out = hook(wheel, env, {"hook_event_name": "SessionStart", "source": "startup",
                                      "session_id": "smoke", "cwd": os.getcwd()})
        assert (code, out) == (0, {}), ("SessionStart", code, out)

        code, out = hook(wheel, env, pre(f"curl -sI https://{BAD}/account"))
        decision = out["hookSpecificOutput"]["permissionDecision"]
        assert code == 0 and decision == "deny", ("listed host", code, out)
        assert "scamgate blocked this" in out["hookSpecificOutput"]["permissionDecisionReason"]

        code, out = hook(wheel, env, pre("git status"))
        assert code == 0 and "hookSpecificOutput" not in out, ("git status", code, out)

        tools = {t["name"]: t for t in mcp_tools(wheel, env)}
        assert set(tools) == {"check_url", "check_payment", "update_feeds"}, sorted(tools)
        assert not tools["update_feeds"]["inputSchema"].get("properties"), tools["update_feeds"]
    print("claude plugin smoke: hook denies a listed host, stays quiet on git status, serve lists 3 tools")
    return 0


if __name__ == "__main__":
    sys.exit(main())
