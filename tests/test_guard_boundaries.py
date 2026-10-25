"""Tamper guard: folder boundaries, read-only commands, and feed-cache poisoning.

Found on a real Hermes install: a log file next to the cache (`~/.cache/scamgate-feeds.log`) was
treated as part of the cache, and read-only commands such as `ls ... 2>/dev/null` or
`grep -n patch ...` on the plugin folder were blocked as writes. Both must stay quiet, while every
real write to the same folders is still blocked.
"""

import json
import os
import shutil

import pytest

from scamgate import feeds, hook


def claude(tool, tool_input):
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input,
            "session_id": "s", "tool_use_id": "t1", "cwd": os.getcwd()}


def hermes(tool, tool_input):
    return {"hook_event_name": "pre_tool_call", "tool_name": tool, "tool_input": tool_input,
            "session_id": "s", "extra": {"tool_call_id": "c1"}}


def decision(payload):
    out = hook.run(payload)[0]
    if not out.strip():
        return "silent"
    o = json.loads(out)
    if "hookSpecificOutput" in o:
        return o["hookSpecificOutput"]["permissionDecision"]
    return {"block": "deny", "approve": "ask"}.get(o.get("action"), "silent")


@pytest.fixture
def home(tmp_path, monkeypatch, fresh_feeds):
    h = tmp_path / "home"
    plugin_dir = h / ".hermes" / "plugins" / "scamgate"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "plugin.yaml").write_text("name: scamgate\n")
    (plugin_dir / "hook.py").write_text("# patch\n")
    cache = h / ".cache" / "scamgate"
    shutil.copytree(fresh_feeds, cache)
    (h / ".cache" / "scamgate-feeds.log").write_text("")
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("USERPROFILE", str(h))
    monkeypatch.setenv("HERMES_HOME", str(h / ".hermes"))
    monkeypatch.setenv(feeds.ENV_CACHE_DIR, str(cache))
    monkeypatch.setattr(hook, "_FEEDS", None)
    return h


QUIET = [
    # a file beside the cache folder is not inside it
    "echo done >> ~/.cache/scamgate-feeds.log",
    "date >> ~/.cache/scamgate-feeds.log 2>&1",
    "tail -n 20 ~/.cache/scamgate-feeds.log",
    # reading the plugin and the cache
    "ls -la ~/.cache/scamgate 2>/dev/null",
    "ls -la ~/.hermes/plugins/scamgate",
    "ls ~/.hermes/plugins/scamgate 2>/dev/null",
    "cat ~/.hermes/plugins/scamgate/plugin.yaml",
    "grep -n patch ~/.hermes/plugins/scamgate/hook.py",
    "grep -rn 'code' ~/.hermes/plugins/scamgate | head -5",
    "find ~/.hermes/plugins/scamgate -name '*.py' | wc -l",
    "stat ~/.cache/scamgate/meta.json",
    "which scamgate",
    "cd ~/.hermes/plugins/scamgate && ls && cat plugin.yaml",
    "sha256sum ~/.hermes/plugins/scamgate/*.py 2>&1",
    "head -c 300 ~/.cache/scamgate/meta.json; echo",
    # reading the downloader's source is not calling it
    "grep -n 'update_feeds(names' ~/.hermes/plugins/scamgate/feeds.py",
]


@pytest.mark.parametrize("cmd", QUIET)
def test_reads_and_neighbouring_files_stay_quiet(home, cmd):
    assert decision(claude("Bash", {"command": cmd})) == "silent", cmd
    assert decision(hermes("terminal", {"command": cmd})) == "silent", cmd


DENY = [
    "echo x > ~/.cache/scamgate/meta.json",
    "echo x > ~/.cache/scamgate",
    "echo x >> ~/.cache/scamgate-a/../scamgate/meta.json",
    "echo x > ~/.cache/./scamgate/meta.json",
    "echo x > ~/.cache//scamgate/meta.json",
    "rm -rf ~/.cache/scamgate*",
    "ls ~/.hermes/plugins/scamgate; rm -rf ~/.hermes/plugins/scamgate",
    "ls ~/.cache/scamgate 2>/dev/null && cp /tmp/meta.json ~/.cache/scamgate/",
    "ls ~/.cache/scamgate 2>/dev/null >~/.cache/scamgate/meta.json",
    "ls ~/.cache/scamgate 2>/dev/null & rm -rf ~/.cache/scamgate",
    "cat /tmp/evil.py > ~/.hermes/plugins/scamgate/plugin.py",
    "cat /tmp/evil.py | tee ~/.hermes/plugins/scamgate/plugin.py",
    "find ~/.hermes/plugins/scamgate -delete",
    "find ~/.hermes/plugins/scamgate -name '*.py' -exec rm {} +",
    "sed -i s/deny/allow/ ~/.hermes/plugins/scamgate/hook.py",
    "cat $(rm -rf ~/.cache/scamgate)",
    "cd ~/.hermes/plugins/scamgate && echo pass > plugin.py",
    "ls ~/.cache/scamgate-feeds.log ~/.cache/scamgate >/dev/null; rm -rf ~/.cache/scamgate",
    "rm -rf ~/.cache/scamgate/..",
    "echo x > ~/.hermes/./plugins/scamgate/plugin.py",
    "cat ~/.cache/scamgate/meta.json > /dev/null/../../tmp/x; rm ~/.cache/scamgate/meta.json",
    "ls ~/.cache/scamgate `rm -rf ~/.cache/scamgate`",
]


@pytest.mark.parametrize("cmd", DENY)
def test_writes_to_protected_folders_still_blocked(home, cmd):
    assert decision(claude("Bash", {"command": cmd})) == "deny", cmd
    assert decision(hermes("terminal", {"command": cmd})) == "deny", cmd


POISON = [
    "cd ~/.hermes/plugins && python -B -c \"from scamgate import feeds; feeds.update_feeds(fetch=lambda u: 'x.example')\"",
    "python -c \"import scamgate.feeds as f; f.update_feeds(['openphish'], fetch=str)\"",
    "python -c \"from scamgate import feeds; feeds.update_feeds(directory='/tmp/c')\"",
    "python -c \"from scamgate import feeds as f; f._atomic_write(f.cache_dir() / 'openphish.hosts.txt', '')\"",
]


@pytest.mark.parametrize("cmd", POISON)
def test_agent_cannot_choose_what_lands_in_the_feed_cache(home, cmd):
    assert decision(claude("Bash", {"command": cmd})) == "deny", cmd
    assert decision(hermes("execute_code", {"code": cmd})) == "deny", cmd


def test_write_tool_path_check_respects_folder_boundaries(home):
    log = str(home / ".cache" / "scamgate-feeds.log")
    meta = str(home / ".cache" / "scamgate" / "meta.json")
    assert decision(claude("Write", {"file_path": log, "content": "ok"})) == "silent"
    assert decision(claude("Write", {"file_path": meta, "content": "{}"})) == "deny"
