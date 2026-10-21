import asyncio

import pytest

from typer.testing import CliRunner

from scamgate.bench import run_all, summarize
from scamgate.cli import app
from scamgate.registry import all_rules


def test_scenarios_all_match_expected(scenarios_dir):
    results = run_all(scenarios_dir)
    assert len(results) >= 15
    bad = [(r.scenario_id, r.expected.value, r.verdict.decision.value) for r in results if not r.exact]
    assert bad == []
    s = summarize(results)
    assert s["missed"] == 0 and s["false_positives"] == 0


def test_bench_cli_strict(scenarios_dir):
    res = CliRunner().invoke(app, ["bench", "--dir", str(scenarios_dir), "--strict"])
    assert res.exit_code == 0, res.output
    assert "caught" in res.output and "false positives" in res.output


def test_every_rule_has_config_entry():
    from scamgate.config import load_config

    cfg = load_config()["rules"]
    for rule in all_rules():
        assert rule.rule_id in cfg, f"{rule.rule_id} missing from rules.yaml"


def test_mcp_tools_registered_and_callable():
    from scamgate.server import mcp

    tools = {t.name for t in asyncio.run(mcp.list_tools())}
    assert {"check_url", "check_payment"} <= tools

    from scamgate.server import check_payment, check_url

    assert check_url("https://paypa1.com/login", "buy shoes").decision.value == "deny"
    out = check_payment("X", "Y", 50, "EUR", "card")
    assert out.decision.value == "allow" and out.advisory


# ---------------------------------------------------------------- what an MCP client sees

def _tool(name):
    from scamgate.server import mcp

    return next(t for t in asyncio.run(mcp.list_tools()) if t.name == name)


def _call(name, args):
    from scamgate.server import mcp

    return asyncio.run(mcp.call_tool(name, args))


@pytest.mark.parametrize("name", ["check_url", "check_payment"])
def test_mcp_tools_say_they_only_read(name):
    a = _tool(name).annotations
    assert a.read_only_hint is True and a.destructive_hint is False and a.idempotent_hint is True
    assert a.open_world_hint is False  # no network unless domain-age lookups are switched on


def test_check_url_says_it_goes_online_when_domain_age_is_live(monkeypatch):
    import importlib

    import scamgate.server

    monkeypatch.setenv("SCAMGATE_RDAP", "live")
    try:
        assert importlib.reload(scamgate.server).mcp is not None
        assert _tool("check_url").annotations.open_world_hint is True
    finally:
        monkeypatch.delenv("SCAMGATE_RDAP")
        importlib.reload(scamgate.server)


@pytest.mark.parametrize("name", ["check_url", "check_payment"])
def test_mcp_tools_publish_the_verdict_schema(name):
    props = _tool(name).output_schema["properties"]
    assert {"decision", "risk_score", "reasons", "summary", "warnings", "advisory", "checked_host"} <= set(props)


def test_mcp_check_url_returns_the_verdict_and_the_host_it_judged():
    r = _call("check_url", {"url": "https://paypal.com@evil.example/login"})
    assert r.structured_content["decision"] == "deny"
    assert r.structured_content["checked_host"] == "evil.example"


def test_mcp_check_url_bounds_its_input():
    from mcp.server.mcpserver.exceptions import ToolError

    with pytest.raises(ToolError):  # the SDK sends this to the client as an error result
        _call("check_url", {"url": "https://a.example/" + "a" * 70000})
    # Under the protocol limit, an oversized link gets a verdict ("can't read it, ask"), not an error.
    r = _call("check_url", {"url": "https://a.example/" + "a" * 9000})
    assert r.structured_content["decision"] == "ask" and r.structured_content["checked_host"] is None


def test_mcp_check_payment_returns_a_verdict_without_a_host():
    r = _call("check_payment", {"payee_name": "Electric Ireland", "payee_account": "IE29AIBK93115212345678",
                                "amount": 85, "currency": "EUR", "method": "card"})
    assert r.structured_content["decision"] == "allow" and r.structured_content["checked_host"] is None
