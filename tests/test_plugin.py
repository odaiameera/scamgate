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


def _schemas():
    ctx = Ctx()
    plugin.register(ctx)
    return {name: t["schema"]["parameters"] for name, t in ctx.tools.items()}


def test_plugin_tools_take_the_same_fields_as_the_mcp_tools():
    import asyncio

    from scamgate.server import mcp

    mcp_tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
    for plugin_name, mcp_name in (("scamgate_check_url", "check_url"), ("scamgate_check_payment", "check_payment")):
        assert set(_schemas()[plugin_name]["properties"]) == set(mcp_tools[mcp_name].input_schema["properties"])
        assert set(_schemas()[plugin_name]["required"]) == set(mcp_tools[mcp_name].input_schema["required"])


def test_plugin_payment_check_uses_the_budget():
    body = json.loads(plugin.check_payment({"payee_name": "Shop", "payee_account": "GB33BUKB20201555555555",
                                            "amount": 500, "currency": "EUR", "method": "card", "budget": 100}))
    assert "pay.over_budget" in {r["rule_id"] for r in body["reasons"]}


def test_plugin_tools_report_bad_arguments_instead_of_crashing():
    bad_amount = {"payee_name": "Shop", "payee_account": "x", "amount": "1,000", "currency": "EUR", "method": "card"}
    assert "error" in json.loads(plugin.check_payment(bad_amount))
    assert "error" in json.loads(plugin.check_url({}))


def test_slash_review_lists_each_host_and_what_you_did():
    from scamgate import asklog

    asklog.log_check(tool="terminal", decision="approve", risk_score=40, rule_ids=["url.ip_host"],
                     targets=["http://203.0.113.9/"], hosts=["203.0.113.9"], stated_reason="", session="s",
                     call_id="c")
    lines = plugin.slash("review").splitlines()
    assert any("203.0.113.9" in line and "1 asked" in line and "url.ip_host" in line for line in lines), lines


def test_plugin_fails_closed_when_the_gate_errors(monkeypatch):
    from scamgate import hook

    def broken(payload):
        raise RuntimeError("boom")

    monkeypatch.setattr(hook, "handle", broken)
    out = plugin.on_pre_tool_call(tool_name="terminal", args={"command": "git status"}, session_id="s")
    assert out["action"] == "block" and "failing closed" in out["message"]
    assert plugin.on_post_tool_call(tool_name="terminal", session_id="s", tool_call_id="c") is None
