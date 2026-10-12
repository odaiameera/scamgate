import asyncio

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

    assert check_url("https://paypa1.com/login", "buy shoes")["decision"] == "deny"
    out = check_payment("X", "Y", 50, "EUR", "card")
    assert out["decision"] == "allow" and "advisory" in out
