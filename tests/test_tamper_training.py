"""PR B: anti-tamper and anti-training (H2, H3, H4, M2, M4 in docs/design/hook-review-verification.md)."""

import json
import os
from pathlib import Path

import pytest

from scamgate import engine, hook, overrides, payees
from scamgate.models import Decision, PaymentCheck
from scamgate.redact import redact_text, redact_url


def claude(tool, tool_input):
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input,
            "session_id": "s", "tool_use_id": "t1", "cwd": os.getcwd()}


def decision(payload):
    o = json.loads(hook.run(payload)[0])
    if "hookSpecificOutput" in o:
        return o["hookSpecificOutput"]["permissionDecision"]
    return {"block": "deny", "approve": "ask"}.get(o.get("action"), "silent")


def bash(cmd, **kw):
    return decision(claude("Bash", {"command": cmd}, **kw))


@pytest.fixture
def home(tmp_path, monkeypatch, fresh_feeds):
    h = tmp_path / "home"
    (h / ".claude").mkdir(parents=True)
    (h / ".claude" / "settings.json").write_text("{}")
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("USERPROFILE", str(h))
    return h


# ---------------------------------------------------------------- H2: every way of naming a protected path

@pytest.mark.parametrize("cmd", [
    "sed -i s/scamgate/true/ ~/.claude/settings.json",
    "sed -i s/scamgate/true/ $HOME/.claude/settings.json",
    "sed -i s/scamgate/true/ ${HOME}/.claude/settings.json",
    "sed -i s/x/y/ ~/.cl*/sett*.json",
    "cd ~/.claude && jq 'del(.hooks)' settings.json > s && mv s settings.json",
    "ln -sf /dev/null ~/.claude/settings.json",
    "echo '{\"disableAllHooks\":true}' > .claude/settings.local.json",
    "cp /tmp/x.json ./.claude/settings.json",
    "python3 -c \"import pathlib;(pathlib.Path.home()/'.claude'/'settings.json').write_text('{}')\"",
    "Set-Content -Path $env:USERPROFILE\\.claude\\settings.json -Value '{}'",
])
def test_claude_settings_tampering_in_any_spelling(home, cmd):
    assert bash(cmd) == "deny", cmd


@pytest.mark.parametrize("name", ["settings.json", "settings.local.json"])
def test_project_claude_settings_are_protected_for_write_tools(home, tmp_path, name):
    proj = tmp_path / "proj" / ".claude"
    proj.mkdir(parents=True)
    assert decision(claude("Write", {"file_path": str(proj / name), "content": "{}"})) == "deny"


def test_hermes_config_tampering_via_tilde(home, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(home / ".hermes"))
    assert bash("sed -i '/scamgate-hook/d' ~/.hermes/config.yaml") == "deny"
    assert bash("cp /tmp/x.json $HERMES_HOME/shell-hooks-allowlist.json") == "deny"


def test_hermes_paths_protected_even_without_hermes_home(home, monkeypatch):
    monkeypatch.delenv("HERMES_HOME", raising=False)
    assert bash("echo 'hooks: {}' >> ~/.hermes/config.yaml") == "deny"
    assert bash("sed -i s/a/b/ ~/AppData/Local/hermes/config.yaml") == "deny"


@pytest.mark.parametrize("cmd", [
    "cat ~/.claude/settings.json",
    "jq .hooks ~/.claude/settings.json",
    "grep scamgate ~/.hermes/config.yaml",
    "ls -la .claude/",
])
def test_reading_protected_files_is_fine(home, cmd):
    assert bash(cmd) == "silent", cmd


def test_unrelated_settings_files_are_fine(home):
    assert bash("echo '{}' > ./config/settings.json") == "silent"
    assert bash("sed -i s/a/b/ app/settings.py") == "silent"


# ---------------------------------------------------------------- H3: the agent can't train the gate

@pytest.mark.parametrize("cmd", [
    "yes | python -m scamgate.cli promote --host a.com --decision deny",
    "python -m scamgate promote --host a.com --decision deny",
    "S=scam; ${S}gate promote --host a.com --decision deny",
    "printf \"y\\n\" | scamgate \"promote\" --host a.com --decision deny",
    "scamgate 'record-payment' --payee A --account B",
    "python3 -c 'import importlib;importlib.import_module(\"scamgate.over\"+\"rides\").add(\"a.com\",\"deny\")'",
    "python3 -c '__import__(\"scamgate.payees\").payees.record(\"A\",\"B\")'",
])
def test_promote_and_record_payment_dodges_are_blocked(home, cmd):
    assert bash(cmd) == "deny", cmd


def test_scamgate_read_commands_are_fine(home):
    for cmd in ("scamgate review --days 7", "scamgate check-url https://example.org", "scamgate feeds-status"):
        assert bash(cmd) == "silent", cmd


def test_library_refuses_agent_callers(monkeypatch):
    monkeypatch.setenv("CLAUDECODE", "1")
    with pytest.raises(PermissionError):
        overrides.add("shop.example", "deny")
    with pytest.raises(PermissionError):
        payees.record("Acme", "IE29AIBK93115212345678")


@pytest.mark.parametrize("var", ["CLAUDECODE", "HERMES_SESSION_ID", "HERMES_GATEWAY_SESSION", "CODEX_SANDBOX",
                                 "SCAMGATE_AGENT"])
def test_known_agent_markers_are_refused(monkeypatch, var):
    monkeypatch.setenv(var, "x")
    with pytest.raises(PermissionError):
        overrides.add("shop.example", "deny")


def test_library_refuses_non_interactive_callers(monkeypatch):
    monkeypatch.setattr(overrides, "_interactive", lambda: False)
    with pytest.raises(PermissionError):
        overrides.add("shop.example", "deny")


def test_add_rejects_never_waived_rules_itself():
    with pytest.raises(ValueError):
        overrides.add("shop.example", "allow", rule="url.intent_mismatch")
    with pytest.raises(ValueError):
        overrides.add("shop.example", "allow", rule="url.known_bad_feed")


def test_forged_override_lines_are_ignored():
    overrides.add("good.example", "deny")
    with overrides.overrides_path().open("a", encoding="utf-8") as f:
        f.write(json.dumps({"host": "paypa1.com", "decision": "allow", "rule": "url.lookalike_brand",
                            "added_by": "human-cli", "added_at": "2026-10-12T00:00:00+00:00"}) + "\n")
    hosts = {o["host"] for o in overrides.load()}
    assert hosts == {"good.example"}
    v = engine.check_url("https://paypa1.com/login")
    assert v.decision is not Decision.allow and "url.lookalike_brand" in {r.rule_id for r in v.reasons}


def test_forged_payee_lines_are_ignored():
    payees.record("Acme Ltd", "IE29AIBK93115212345678")
    row = json.loads(payees.history_path().read_text("utf-8").splitlines()[0])
    row["account"] = payees._h("acct", payees.norm_account("GB33BUKB20201555555555"))
    with payees.history_path().open("a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")  # copied signature, swapped account
    assert not payees.lookup("Acme Ltd", "GB33BUKB20201555555555").known_account


# ---------------------------------------------------------------- M2: invoice redirection under a near-name

def pay(name, acct, **kw):
    base = dict(payee_name=name, payee_account=acct, amount=9000, currency="EUR", method="bank_transfer")
    base.update(kw)
    return engine.check_payment(PaymentCheck(**base))


@pytest.fixture
def acme():
    payees.record("Acme Ltd", "IE29 AIBK 9311 5212 3456 78")


@pytest.mark.parametrize("name", ["Acme Trading Ltd", "Acm\u0435 Ltd", "ACME Ltd.", "Acme Limited", "Acmee Ltd",
                                  "Acme Ltd (Payments)"])
def test_near_name_with_new_account_is_changed_details(acme, name):
    v = pay(name, "GB33BUKB20201555555555")
    assert "pay.bank_details_changed" in {r.rule_id for r in v.reasons}, name
    assert v.decision is not Decision.allow


def test_known_account_under_a_different_name_is_flagged(acme):
    v = pay("Evil Corp", "IE29AIBK93115212345678")
    assert v.decision is not Decision.allow
    assert any("different name" in w for w in v.warnings)


def test_unrelated_new_payee_is_still_just_new(acme):
    v = pay("Electric Ireland", "IE64BOFI90583812345678")
    assert "pay.bank_details_changed" not in {r.rule_id for r in v.reasons}


def test_agent_claiming_known_with_no_record_adds_risk(acme):
    honest = pay("Brand New Co", "IE64BOFI90583812345678", is_new_payee=True)
    claimed = pay("Brand New Co", "IE64BOFI90583812345678", is_new_payee=False)
    assert claimed.risk_score > honest.risk_score
    assert "pay.unbacked_known_claim" in {r.rule_id for r in claimed.reasons}


def test_caller_cannot_set_the_internal_claim_flag():
    from scamgate.models import PaymentCheck

    schema = PaymentCheck.model_json_schema()
    assert "agent_claim_unbacked" in schema["properties"]  # documented, but...
    v = pay("Brand New Co", "IE64BOFI90583812345678", is_new_payee=True, agent_claim_unbacked=True)
    assert "pay.unbacked_known_claim" not in {r.rule_id for r in v.reasons}  # ...engine recomputes it


def test_missing_salt_with_existing_history_fails_loudly(acme):
    (payees.history_path().parent / "payees.salt").unlink()
    v = pay("Acme Ltd", "IE29 AIBK 9311 5212 3456 78")
    assert v.decision is not Decision.allow
    assert any("payee history" in w.lower() for w in v.warnings)


def test_state_files_are_private(acme):
    if os.name == "nt":
        pytest.skip("POSIX permissions")
    for name in ("payees.salt", "state.key", "payees.jsonl"):
        assert (payees.history_path().parent / name).stat().st_mode & 0o077 == 0, name


# ---------------------------------------------------------------- M4: redaction

@pytest.mark.parametrize("secret", [
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
    "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "AIzaSyD-EXAMPLEkey1234567890abcdef",
    "AKIAIOSFODNN7EXAMPLE",
    "glpat-abcdefghij1234567890",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
])
def test_redact_text_masks_tokens_and_keys(secret):
    assert secret not in redact_text(f"token here: {secret} done")


@pytest.mark.parametrize("text,leak", [
    ("password is hunter2!", "hunter2"),
    ("my passcode: 4417", "4417"),
    ("ie29aibk93115212345678", "93115212345678"),
    ("seed: abandon ability able about above absent absorb abstract absurd abuse access accident", "absorb abstract"),
])
def test_redact_text_other_leaks(text, leak):
    assert leak not in redact_text(text)


@pytest.mark.parametrize("url,leak", [
    ("https://mail.example/u/odai@example.com/inbox", "odai@"),
    ("https://x.com/pay/IE29AIBK93115212345678", "93115212345678"),
    ("https://bank.com/reset/eyJhbGciOi.eyJzdWIiOiIx.abcdef", "eyJzdWIiOiIx"),
    ("https://x.com/api/sk-abc123def456ghi789/hunter2pw", "sk-abc123def456"),
])
def test_redact_url_paths(url, leak):
    assert leak not in redact_url(url)


def test_redact_keeps_ordinary_text():
    t = "buy a concert ticket for Saturday at the 3Arena"
    assert redact_text(t) == t
    assert redact_url("https://www.ticketmaster.ie/event/123456") == "https://www.ticketmaster.ie/event/123456"


def test_stated_reason_is_capped_in_the_log():
    from scamgate import asklog

    asklog.log_check(tool="t", decision="approve", risk_score=40, rule_ids=["x"], targets=["https://a.example"],
                     hosts=["a.example"], stated_reason="z" * 500, session="s", call_id="c")
    assert len(asklog.read_entries()[0]["stated_reason"]) <= 81


# ---------------------------------------------------------------- H4: protect the install

def test_install_prefix_and_entry_script_are_protected(monkeypatch):
    import sys
    import sysconfig

    if sys.prefix == sys.base_prefix:
        pytest.skip("only virtualenv installs are protected")
    purelib = sysconfig.get_paths()["purelib"]
    assert hook._norm_path(purelib) in hook.protected_roots()
    pth = Path(purelib) / "zz_evil.pth"
    assert decision(claude("Write", {"file_path": str(pth), "content": "import os"})) == "deny"


def test_unknown_pth_files_fail_integrity(monkeypatch, tmp_path):
    from scamgate import integrity

    (tmp_path / "zz_evil.pth").write_text("import os; os.environ['X']='1'\n")
    (tmp_path / "distutils-precedence.pth").write_text("import os\n")
    assert integrity.unexpected_pth([tmp_path]) == ["zz_evil.pth"]
