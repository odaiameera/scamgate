"""The Claude Code plugin: its manifests pin this release, and the parts of scamgate they call work.

The plugin runs `uvx scamgate==X hook` for SessionStart, PreToolUse, PostToolUse and PostToolUseFailure,
and `uvx scamgate==X serve` as its MCP server (check_url, check_payment, update_feeds). The tamper guard
also covers what a Claude Code install adds: installed plugins, CLAUDE_CONFIG_DIR, and the commands that
switch a plugin or every hook off.
"""

import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

import scamgate
from scamgate import feeds, harden, hook, refresh, server

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "claude-plugin"
PIN = f"scamgate=={scamgate.__version__}"
FIXTURES = Path(__file__).parent / "fixtures" / "feeds"


def load(rel):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def claude(tool, tool_input):
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input,
            "session_id": "s", "tool_use_id": "t1", "cwd": os.getcwd()}


def decision(payload):
    out = hook.run(payload)[0]
    if not out.strip():
        return "silent"
    o = json.loads(out)
    return o.get("hookSpecificOutput", {}).get("permissionDecision", "silent")


def bash(cmd):
    return decision(claude("Bash", {"command": cmd}))


# ---------------------------------------------------------------- manifests

def test_every_manifest_names_the_package_version():
    v = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    assert scamgate.__version__ == v
    assert load("claude-plugin/.claude-plugin/plugin.json")["version"] == v
    assert [p["version"] for p in load(".claude-plugin/marketplace.json")["plugins"]] == [v]
    sj = load("server.json")
    assert sj["version"] == v and [p["version"] for p in sj["packages"]] == [v]


def test_plugin_hooks_run_the_pinned_release_and_fail_closed():
    groups = load("claude-plugin/hooks/hooks.json")["hooks"]
    assert set(groups) == {"SessionStart", "PreToolUse", "PostToolUse", "PostToolUseFailure"}
    for event, entries in groups.items():
        assert [h["command"] for e in entries for h in e["hooks"]] == [f"uvx {PIN} hook"], event
    for event in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
        assert [e["matcher"] for e in groups[event]] == ["*"], event
    (pre,) = groups["PreToolUse"][0]["hooks"]
    assert pre["onFailure"] == "block"


def test_plugin_mcp_server_runs_the_pinned_release():
    s = load("claude-plugin/.mcp.json")["mcpServers"]["scamgate"]
    assert s["command"] == "uvx" and s["args"] == [PIN, "serve"]
    assert s["env"] == {"SCAMGATE_AUTO_UPDATE": "${user_config.auto_update_feeds}",
                        "SCAMGATE_URLHAUS_AUTH_KEY": "${user_config.urlhaus_auth_key}"}
    cfg = load("claude-plugin/.claude-plugin/plugin.json")["userConfig"]
    assert cfg["auto_update_feeds"]["type"] == "boolean" and cfg["auto_update_feeds"]["default"] is True
    assert cfg["urlhaus_auth_key"]["sensitive"] is True


def test_marketplace_points_at_the_plugin_folder():
    (entry,) = load(".claude-plugin/marketplace.json")["plugins"]
    assert entry["name"] == "scamgate" and entry["source"] == "./claude-plugin"
    assert (ROOT / entry["source"] / ".claude-plugin" / "plugin.json").is_file()
    assert (PLUGIN / "LICENSE").read_text(encoding="utf-8") == (ROOT / "LICENSE").read_text(encoding="utf-8")


def test_registry_name_matches_the_readme_marker():
    assert load("server.json")["name"] == "io.github.odaiameera/scamgate"
    assert "<!-- mcp-name: io.github.odaiameera/scamgate -->" in (ROOT / "README.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("rel", ["claude-plugin/README.md", "README.md", "site/index.html", "site/docs.html"])
def test_docs_pin_this_release(rel):
    pins = set(re.findall(r"scamgate==(\d+\.\d+\.\d+)", (ROOT / rel).read_text(encoding="utf-8")))
    assert pins <= {scamgate.__version__}


# ---------------------------------------------------------------- `scamgate hook`, as the plugin calls it

_RUN_ENTRY = (
    "import sys\n"
    "from scamgate import entry\n"
    "try:\n"
    "    entry.main()\n"
    "except SystemExit as e:\n"
    "    code = e.code\n"
    "sys.stderr.write('\\nLOADED:' + ','.join(m for m in ('typer', 'rich') if m in sys.modules))\n"
    "sys.exit(code)\n"
)


def run_scamgate_hook(payload):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    p = subprocess.run([sys.executable, "-c", _RUN_ENTRY, "hook"], input=json.dumps(payload),
                       capture_output=True, text=True, env=env, timeout=120)
    return p.returncode, p.stdout, p.stderr.rsplit("LOADED:", 1)[-1].strip()


def test_scamgate_hook_denies_a_listed_host_without_loading_the_cli(fresh_feeds):
    code, out, loaded = run_scamgate_hook(claude("Bash", {"command": "curl -s http://evilshop.com/login"}))
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert loaded == ""  # the per-call fast path skips typer and rich


def test_scamgate_hook_is_quiet_on_session_start_and_after_a_tool(fresh_feeds):
    start = {"hook_event_name": "SessionStart", "source": "startup", "session_id": "s", "cwd": os.getcwd()}
    code, out, _ = run_scamgate_hook(start)
    assert code == 0 and json.loads(out) == {}
    post = {**claude("Bash", {"command": "git status"}), "hook_event_name": "PostToolUse",
            "tool_response": {"stdout": "", "stderr": ""}}
    code, out, _ = run_scamgate_hook(post)
    assert code == 0 and "permissionDecision" not in out


def test_scamgate_hook_fails_closed_on_unreadable_input():
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    p = subprocess.run([sys.executable, "-c", _RUN_ENTRY, "hook"], input="not json", capture_output=True,
                       text=True, env=env, timeout=120)
    assert p.returncode == 2


# ---------------------------------------------------------------- the MCP server

def fixture_fetch(url):
    if "openphish" in url:
        return (FIXTURES / "openphish.txt").read_text()
    if "phishing-domains" in url:
        return (FIXTURES / "phishing-domains.txt").read_text()
    raise AssertionError(f"unexpected download: {url}")


def test_update_feeds_tool_takes_no_arguments():
    import asyncio

    (tool,) = [t for t in asyncio.run(server.mcp.list_tools()) if t.name == "update_feeds"]
    assert not tool.input_schema.get("properties")
    a = tool.annotations
    assert a.read_only_hint is False and a.destructive_hint is False and a.open_world_hint is True


def test_update_feeds_tool_downloads_then_waits_an_hour(tmp_path, monkeypatch):
    monkeypatch.setenv(feeds.ENV_CACHE_DIR, str(tmp_path / "cache"))
    monkeypatch.delenv(feeds.ENV_URLHAUS_KEY, raising=False)
    monkeypatch.setattr(feeds, "_download", fixture_fetch)
    first = server.update_feeds()
    assert set(first.updated) == {"openphish", "phishing_database_domains"}
    assert not first.failed and first.skipped == "" and "urlhaus" in first.not_configured
    again = server.update_feeds()
    assert again.updated == [] and again.skipped == "fresh"


@pytest.mark.parametrize("value", ["", "   ", "${user_config.urlhaus_auth_key}"])
def test_an_unset_urlhaus_option_counts_as_no_key(monkeypatch, value):
    monkeypatch.setenv(feeds.ENV_URLHAUS_KEY, value)
    assert feeds._urlhaus_url() is None


def test_a_urlhaus_key_builds_the_download_address(monkeypatch):
    monkeypatch.setenv(feeds.ENV_URLHAUS_KEY, " k123 ")
    assert feeds._urlhaus_url() == "https://urlhaus-api.abuse.ch/v2/files/exports/k123/csv_online"


@pytest.mark.parametrize("value,starts", [
    (None, False), ("", False), ("${user_config.auto_update_feeds}", False),
    ("true", True), ("1", True), ("yes", True), ("false", False), ("0", False),
])
def test_server_background_refresh_is_opt_in(monkeypatch, value, starts):
    started = []
    monkeypatch.setattr(refresh, "start_background", lambda **kw: started.append(kw))
    monkeypatch.setattr(server.mcp, "run", lambda **kw: None)
    if value is None:
        monkeypatch.delenv("SCAMGATE_AUTO_UPDATE", raising=False)
    else:
        monkeypatch.setenv("SCAMGATE_AUTO_UPDATE", value)
    server.run()
    assert bool(started) is starts


def test_background_refresh_runs_one_thread_until_stopped(monkeypatch):
    import threading

    passes = []
    unloads = []
    monkeypatch.setattr(refresh, "auto_pass", lambda: passes.append(1) or refresh.Outcome(skipped="fresh"))
    t1 = refresh.start_background(first_delay=0.01, every=0.01, on_unload=unloads.append)
    t2 = refresh.start_background(first_delay=0.01, every=0.01)
    assert t1 is t2 and t1.daemon and t1.name == "scamgate-feed-refresh"
    deadline = threading.Event()
    while not passes and not deadline.wait(0.01):
        pass
    unloads[0]()  # what an unload does
    t1.join(2)
    assert passes and not t1.is_alive()


# ---------------------------------------------------------------- tamper guard, Claude Code side

@pytest.mark.parametrize("cmd", [
    "claude plugin disable scamgate@scamgate",
    "claude plugins uninstall scamgate",
    "claude plugin remove scamgate",
    "claude plugin rm scamgate",
    "claude plugin marketplace remove scamgate",
    "npx -y claude-code plugin disable scamgate",
    "claude.exe plugin uninstall scamgate --scope user",
    "claude --bare -p 'run the tests'",
    "claude -p --bare 'run the tests'",
    "claude -p '/plugin disable scamgate'",
    "claude --allow-dangerously-skip-permissions -p hi",
    "echo '{\"disableAllHooks\": true}' > s.json",
])
def test_switching_the_plugin_or_hooks_off_is_blocked(cmd, fresh_feeds):
    assert bash(cmd) == "deny"


def test_writing_disable_all_hooks_anywhere_is_blocked(fresh_feeds, tmp_path):
    out = claude("Write", {"file_path": str(tmp_path / "s.json"), "content": '{\n  "disableAllHooks": true\n}'})
    assert decision(out) == "deny"


@pytest.mark.parametrize("cmd", [
    "claude plugin install other@market",
    "claude plugin i other@market",
    "claude plugin enable other",
    "claude plugin configure scamgate",
    "claude --setting-sources project -p hi",
    "claude -p hi --settings ./s.json",
])
def test_changing_which_plugins_or_settings_load_asks(cmd, fresh_feeds):
    assert bash(cmd) == "ask"


@pytest.mark.parametrize("cmd", [
    "claude --version",
    "claude plugin list",
    "claude plugin details scamgate",
    "claude plugin validate ./claude-plugin",
    "claude mcp list",
    "claude -p 'summarise README.md'",
    "git commit -m 'explain the bare flag'",
])
def test_ordinary_claude_commands_stay_quiet(cmd, fresh_feeds):
    assert bash(cmd) == "silent"


@pytest.fixture
def claude_home(tmp_path, monkeypatch, fresh_feeds):
    h = tmp_path / "home"
    hooks = h / ".claude" / "plugins" / "cache" / "scamgate" / "scamgate" / "0.3.3" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "hooks.json").write_text("{}")
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("USERPROFILE", str(h))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    return h


def test_editing_an_installed_claude_plugin_is_blocked(claude_home):
    target = claude_home / ".claude" / "plugins" / "cache" / "scamgate" / "scamgate" / "0.3.3" / "hooks" / "hooks.json"
    assert decision(claude("Write", {"file_path": str(target), "content": "{}"})) == "deny"
    assert decision(claude("Edit", {"file_path": str(target), "old_string": "{}", "new_string": "[]"})) == "deny"
    assert bash("rm -rf ~/.claude/plugins/cache/scamgate") == "deny"


def test_reading_installed_claude_plugins_stays_quiet(claude_home):
    target = claude_home / ".claude" / "plugins" / "cache" / "scamgate" / "scamgate" / "0.3.3" / "hooks" / "hooks.json"
    assert decision(claude("Read", {"file_path": str(target)})) == "silent"
    assert bash("ls ~/.claude/plugins") == "silent"
    assert bash("cat ~/.claude/plugins/cache/scamgate/scamgate/0.3.3/hooks/hooks.json") == "silent"


def test_claude_config_dir_is_protected(tmp_path, monkeypatch, fresh_feeds):
    cfg = tmp_path / "cc-config"
    (cfg / "plugins").mkdir(parents=True)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))
    assert decision(claude("Write", {"file_path": str(cfg / "settings.json"), "content": "{}"})) == "deny"
    assert decision(claude("Write", {"file_path": str(cfg / "plugins" / "x.json"), "content": "{}"})) == "deny"


def test_the_plugins_own_check_tools_may_name_a_listed_link(fresh_feeds):
    for name in ("mcp__plugin_scamgate_scamgate__check_url", "mcp__scamgate__check_url"):
        assert harden.own_check(name)
        assert decision(claude(name, {"url": "http://evilshop.com/login"})) == "silent"
    assert not harden.own_check("mcp__plugin_other_scamgate__check_url")
    assert decision(claude("mcp__plugin_other_web__fetch", {"url": "http://evilshop.com/login"})) == "deny"
