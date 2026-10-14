"""The Hermes plugin is the hook, called in-process, plus two check tools."""

import json

import pytest

from scamgate import plugin


class Ctx:
    def __init__(self):
        self.hooks = {}
        self.tools = {}
        self.commands = {}
        self.settings = {}

    def register_hook(self, name, fn):
        self.hooks[name] = fn

    def register_tool(self, **kw):
        self.tools[kw["name"]] = kw

    def register_command(self, name, handler, **kw):
        self.commands[name] = handler

    def get_config(self, key, default=None):
        return self.settings.get(key, default)


@pytest.fixture(autouse=True)
def _feeds(fresh_feeds):
    pass


def test_register_wires_the_gate():
    ctx = Ctx()
    plugin.register(ctx)
    assert set(ctx.hooks) == {"pre_tool_call", "post_tool_call"}
    assert set(ctx.tools) == {"scamgate_check_url", "scamgate_check_payment"}
    assert "scamgate" in ctx.commands


def test_plugin_blocks_a_known_bad_link():
    out = plugin.on_pre_tool_call(tool_name="browser_navigate", args={"url": "https://evilshop.com/x"},
                                  session_id="s", tool_call_id="c")
    assert out["action"] == "block"
    assert "evilshop" in out["message"]


def test_plugin_stays_quiet_on_an_ordinary_command():
    assert plugin.on_pre_tool_call(tool_name="terminal", args={"command": "git status"}, session_id="s") is None


def test_an_ask_becomes_a_block_when_approvals_are_off(monkeypatch):
    monkeypatch.setattr(plugin, "approvals_bypassed", lambda session_id="": True)
    out = plugin.on_pre_tool_call(tool_name="terminal", args={"command": "curl $URL"}, session_id="s")
    assert out["action"] == "block"
    assert "Approvals are off" in out["message"]


def test_an_ask_stays_an_ask_when_the_user_opts_out(monkeypatch):
    monkeypatch.setattr(plugin, "approvals_bypassed", lambda session_id="": True)
    monkeypatch.setenv("SCAMGATE_WHEN_APPROVALS_OFF", "allow")
    plugin._CTX = None
    out = plugin.on_pre_tool_call(tool_name="terminal", args={"command": "curl $URL"}, session_id="s")
    assert out["action"] == "approve"


def test_check_url_tool_denies_a_listed_host():
    body = json.loads(plugin.check_url({"url": "https://evilshop.com/x"}))
    assert body["decision"] == "deny"


def test_post_hook_records_without_raising():
    assert plugin.on_post_tool_call(tool_name="terminal", session_id="s", tool_call_id="c", status="ok") is None


def test_slash_status_sees_the_test_feeds():
    text = plugin.slash("status")
    assert "scamgate" in text
    assert "no phishing lists" not in text
