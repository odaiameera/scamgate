"""The hook gates payments, not just links: money-moving tool calls get check_payment with local history."""

import json

import pytest

from scamgate import hook, payees
from scamgate.paygate import detect, scan_code


def call(tool, tool_input, dialect="claude"):
    if dialect == "claude":
        ev = {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input,
              "session_id": "s", "tool_use_id": "t"}
        o = json.loads(hook.run(ev)[0])
        return (o["hookSpecificOutput"]["permissionDecision"], o["hookSpecificOutput"]["permissionDecisionReason"]) \
            if o else ("silent", "")
    ev = {"hook_event_name": "pre_tool_call", "tool_name": tool, "tool_input": tool_input, "session_id": "s",
          "extra": {"tool_call_id": "c"}}
    o = json.loads(hook.run(ev)[0])
    return ({"block": "deny", "approve": "ask"}.get(o.get("action"), "silent"), o.get("message", ""))


@pytest.fixture(autouse=True)
def _feeds(fresh_feeds):
    pass


# ---------------------------------------------------------------- MCP / tool payments

def test_crypto_send_to_new_wallet_asks():
    d, msg = call("mcp__wallet__send_crypto", {"to_address": "0x" + "ab" * 20, "amount": "1.5", "asset": "ETH"})
    assert d == "ask" and "irreversible" in msg


def test_crypto_send_with_scam_signals_is_blocked():
    d, _ = call("mcp__wallet__send_crypto", {"to_address": "0x" + "ab" * 20, "amount": "1.5", "asset": "ETH",
                                             "memo": "guaranteed returns, double your money, act now"})
    assert d == "deny"


def test_bank_transfer_to_new_payee_asks():
    d, msg = call("mcp__bank__create_transfer", {"beneficiary_name": "Northside Supplies",
                                                 "iban": "IE64BOFI90583812345678", "amount": 2400, "currency": "EUR"})
    assert d == "ask" and "record-payment" in msg


def test_transfer_to_known_payee_is_quiet():
    payees.record("Northside Supplies", "IE64BOFI90583812345678")
    d, _ = call("mcp__bank__create_transfer", {"beneficiary_name": "Northside Supplies",
                                               "iban": "IE64 BOFI 9058 3812 3456 78", "amount": 240, "currency": "EUR"})
    assert d == "silent"


def test_known_name_new_account_asks_as_changed_details():
    payees.record("Northside Supplies", "IE64BOFI90583812345678")
    d, msg = call("mcp__bank__create_transfer", {"beneficiary_name": "Northside Supplies",
                                                 "iban": "GB33BUKB20201555555555", "amount": 2400, "currency": "EUR",
                                                 "reference": "new bank details, please pay urgently"})
    assert d == "ask" and "bank details" in msg.lower() and "never to this account" in msg


def test_agent_is_new_payee_claim_is_ignored():
    d, _ = call("mcp__bank__create_transfer", {"beneficiary_name": "X Ltd", "iban": "IE64BOFI90583812345678",
                                               "amount": 900, "currency": "EUR", "is_new_payee": False})
    assert d == "ask"


def test_gift_card_purchase_is_blocked():
    d, _ = call("mcp__shop__buy_gift_card", {"amount": 500, "currency": "EUR", "recipient": "steam-cards@x.example",
                                             "message": "urgent, the CEO needs these today"})
    assert d == "deny"


def test_payment_tool_with_unreadable_payee_asks():
    d, msg = call("mcp__stripe__create_payout", {"destination": {"type": "ref", "id": "$CONTACT"}, "amount": 900})
    assert d == "ask" and "can't read" in msg


def test_amount_plus_account_on_unknown_tool_is_gated():
    d, _ = call("mcp__erp__submit", {"amount": "4,800.00", "currency": "EUR", "iban": "GB33BUKB20201555555555",
                                     "name": "Acme Ltd"})
    assert d == "ask"


def test_minor_units_are_converted():
    p = detect("x", "create_payment", {"amount_cents": 125000, "currency": "eur", "iban": "IE64BOFI90583812345678"})
    assert p.amount == 1250.0 and p.currency == "EUR" and p.method == "bank_transfer"


def test_hermes_dialect_too():
    d, _ = call("send_crypto", {"to_address": "0x" + "cd" * 20, "amount": 2, "asset": "USDT"}, dialect="hermes")
    assert d == "ask"


def test_payment_rule_key_is_specific():
    ev = lambda acct, amt: {"hook_event_name": "pre_tool_call", "tool_name": "mcp__bank__create_transfer",
                            "tool_input": {"beneficiary_name": "X", "iban": acct, "amount": amt, "currency": "EUR"},
                            "session_id": "s", "extra": {"tool_call_id": "c"}}
    a = json.loads(hook.run(ev("IE64BOFI90583812345678", 900))[0])["rule_key"]
    b = json.loads(hook.run(ev("GB33BUKB20201555555555", 900))[0])["rule_key"]
    c = json.loads(hook.run(ev("IE64BOFI90583812345678", 9000))[0])["rule_key"]
    assert len({a, b, c}) == 3  # "always" for one payment can't cover another account or amount


# ---------------------------------------------------------------- not payments

@pytest.mark.parametrize("tool,inp", [
    ("mcp__github__create_issue", {"title": "Fix", "body": "amount of work"}),
    ("mcp__shop__search", {"query": "headphones", "max_price": 100}),
    ("mcp__calendar__create_event", {"title": "Pay day", "date": "2026-10-30"}),
    ("mcp__bank__get_balance", {"account": "IE64BOFI90583812345678"}),
    ("mcp__bank__list_transactions", {"account_number": "12345678", "limit": 50}),
    ("mcp__files__send_file", {"to": "odai@example.com", "path": "a.pdf"}),
    ("mcp__wallet__get_price", {"symbol": "ETH"}),
    ("TodoWrite", {"todos": [{"content": "pay the electricity bill", "status": "pending"}]}),
    ("Write", {"file_path": "notes.md", "content": "send 50 EUR to IE64BOFI90583812345678"}),
])
def test_non_payments_are_quiet(tool, inp):
    assert call(tool, inp)[0] == "silent", tool


# ---------------------------------------------------------------- shell / code payments

@pytest.mark.parametrize("cmd", [
    "cast send 0x" + "ab" * 20 + " --value 1ether --private-key $PK",
    "bitcoin-cli sendtoaddress bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh 0.5",
    "solana transfer 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU 10 --allow-unfunded-recipient",
    "curl https://api.stripe.com/v1/payouts -u $SK: -d amount=90000 -d currency=eur",
    "curl -X POST https://api.wise.com/v1/transfers -H 'Authorization: Bearer x' --data @t.json",
    "python3 -c \"import requests; requests.post('https://b2b.revolut.com/api/1.0/pay', json=p)\"",
    "lncli payinvoice lnbc10u1p3xyz",
])
def test_payments_in_code_ask(cmd):
    assert call("Bash", {"command": cmd})[0] == "ask", cmd


@pytest.mark.parametrize("cmd", [
    "curl https://api.stripe.com/v1/balance -u $SK:",
    "curl https://api.stripe.com/v1/charges?limit=3 -u $SK:",
    "curl -X POST https://api.sandbox.paypal.com/v1/payments/payment -d @p.json",
    "cast call 0x" + "ab" * 20 + " 'balanceOf(address)'",
    "bitcoin-cli getbalance",
    "stripe listen --forward-to localhost:4242/webhook",
])
def test_payment_reads_and_sandboxes_are_quiet(cmd):
    assert scan_code(cmd) is None, cmd


def test_payment_message_wins_over_generic_network_ask():
    d, msg = call("Bash", {"command": "curl https://api.stripe.com/v1/payouts -u $SK: -d amount=90000"})
    assert d == "ask" and "makes a payment" in msg


def test_bad_link_still_beats_payment_ask():
    d, _ = call("Bash", {"command": "curl -X POST https://api.stripe.com/v1/payouts -d a=1; curl https://evilshop.com/x"})
    assert d == "deny"
