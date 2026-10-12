"""Payment facts come from local history, not from what the agent claims; ask review/promote."""

import json

import pytest
from typer.testing import CliRunner

from scamgate import asklog, engine, overrides, payees
from scamgate.cli import app
from scamgate.models import Decision, PaymentCheck

runner = CliRunner()


def pay(**kw):
    base = dict(payee_name="Acme Ltd", payee_account="IE29 AIBK 9311 5212 3456 78", amount=120,
                currency="EUR", method="bank_transfer")
    base.update(kw)
    return PaymentCheck(**base)


def ids(v):
    return {r.rule_id for r in v.reasons}


# ---------------------------------------------------------------- payee history

def test_history_overrides_agent_claim_of_known_payee():
    # Agent claims "not new", but we've never recorded this payee: treat as new.
    v = engine.check_payment(pay(is_new_payee=False, context_text="please pay urgently today"))
    assert "pay.new_payee_urgency" in ids(v)
    assert any("never paid" in w for w in v.warnings)


def test_recorded_payee_is_known_and_account_change_detected():
    payees.record("Acme Ltd", "IE29 AIBK 9311 5212 3456 78")
    v = engine.check_payment(pay(is_new_payee=True))
    assert "pay.irreversible_method" not in ids(v)  # known payee: transfer weight not added
    v = engine.check_payment(pay(payee_account="GB33 BUKB 2020 1555 5555 55", bank_details_changed=False))
    assert "pay.bank_details_changed" in ids(v)
    assert v.decision is not Decision.allow


def test_payee_matching_ignores_case_spacing_and_company_suffix():
    payees.record("ACME LIMITED", "ie29aibk93115212345678")
    assert payees.lookup("acme ltd", "IE29 AIBK 9311 5212 3456 78").known_account


def test_history_stores_hashes_not_account_numbers():
    payees.record("Acme Ltd", "IE29 AIBK 9311 5212 3456 78")
    raw = payees.history_path().read_text("utf-8")
    assert "93115212345678" not in raw and "Acme" not in raw


def test_record_payment_cli():
    r = runner.invoke(app, ["record-payment", "--payee", "Acme Ltd", "--account", "IE29AIBK93115212345678"])
    assert r.exit_code == 0
    assert payees.lookup("Acme Ltd", "IE29AIBK93115212345678").known_account


# ---------------------------------------------------------------- review / promote

def _ask(host, outcome, n=1, rule="url.userinfo"):
    for i in range(n):
        key = asklog.log_check(tool="browser_navigate", decision="approve", risk_score=40,
                               rule_ids=[rule], targets=[f"https://{host}/x"], hosts=[host],
                               stated_reason="check order", session="s", call_id=f"{host}-{outcome}-{i}")
        asklog.record_outcome(key, outcome)


def test_review_groups_by_host_and_shows_human_outcomes():
    _ask("shop.example", "ran", 3)
    _ask("shop.example", "not_run", 1)
    _ask("other.example", "not_run", 2)
    rows = asklog.summarize(days=7)
    top = rows[0]
    assert top.host == "shop.example" and top.asks == 4 and top.ran == 3 and top.not_run == 1
    r = runner.invoke(app, ["review", "--days", "7"])
    assert r.exit_code == 0 and "shop.example" in r.stdout and "untrusted" in r.stdout


def test_promote_allow_is_narrow_and_requires_confirmation():
    r = runner.invoke(app, ["promote", "--host", "shop.example", "--decision", "allow"], input="n\n")
    assert r.exit_code != 0
    assert overrides.load() == []
    r = runner.invoke(app, ["promote", "--host", "shop.example", "--decision", "allow",
                            "--rule", "url.userinfo"], input="y\n")
    assert r.exit_code == 0
    o = overrides.load()[0]
    assert o["host"] == "shop.example" and o["rule"] == "url.userinfo" and o["decision"] == "allow"


def test_promote_allow_without_rule_is_refused():
    r = runner.invoke(app, ["promote", "--host", "shop.example", "--decision", "allow"], input="y\n")
    assert r.exit_code != 0 and "--rule" in r.stdout
    assert overrides.load() == []


def test_allow_override_only_waives_that_rule_on_that_exact_host():
    overrides.add("shop.example", "allow", rule="url.userinfo")
    assert engine.check_url("https://someone@shop.example/basket").decision is Decision.allow
    # same host, different red flag: still flagged
    assert engine.check_url("https://someone@shop.example/basket?seed-phrase=1").decision is Decision.deny
    # subdomain is a different host
    assert engine.check_url("https://someone@pay.shop.example/").decision is not Decision.allow


def _signed_line(**rec):
    from scamgate import guard

    guard.append_private(overrides.overrides_path(), json.dumps(guard.sign(rec)))


def test_allow_override_never_waives_feed_or_blocklist_hits():
    with pytest.raises(ValueError):
        overrides.add("crypto-doubler.example", "allow", rule="url.blocklist")
    _signed_line(host="crypto-doubler.example", decision="allow", rule="url.blocklist")  # even if one existed
    assert engine.check_url("https://crypto-doubler.example/").decision is Decision.deny


def test_deny_override_blocks_whole_host_and_subdomains():
    overrides.add("annoying.example", "deny")
    v = engine.check_url("https://cdn.annoying.example/a.js")
    assert v.decision is Decision.deny and "url.override" in ids(v)


def test_override_file_is_json_lines_with_who_and_when():
    overrides.add("shop.example", "deny")
    raw = overrides.overrides_path().read_text("utf-8").strip().splitlines()
    rec = json.loads(raw[0])
    assert rec["added_by"] == "human-cli" and rec["added_at"]


@pytest.mark.parametrize("bad", ["*.example", "example", "", "https://x.example/"])
def test_promote_rejects_wildcards_and_non_hosts(bad):
    with pytest.raises(ValueError):
        overrides.add(bad, "deny")


def test_allow_override_cannot_waive_your_own_deny():
    overrides.add("shop.example", "deny")
    with pytest.raises(ValueError):
        overrides.add("shop.example", "allow", rule="url.override")
    _signed_line(host="shop.example", decision="allow", rule="url.override")
    assert engine.check_url("https://shop.example/").decision is Decision.deny
