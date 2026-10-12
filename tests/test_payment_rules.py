from scamgate.engine import check_payment
from scamgate.models import Decision, PaymentCheck


def pay(**kw):
    base = dict(payee_name="Acme Ltd", payee_account="IE29AIBK93115212345678",
                amount=100, currency="EUR", method="card")
    base.update(kw)
    return check_payment(PaymentCheck(**base), use_history=False)


def ids(v):
    return {r.rule_id for r in v.reasons}


def test_clean_payment_allowed():
    v = pay(is_new_payee=False)
    assert v.decision is Decision.allow and v.reasons == []


def test_new_payee_urgency():
    assert "pay.new_payee_urgency" in ids(pay(is_new_payee=True, context_text="Please pay URGENTLY"))
    assert "pay.new_payee_urgency" not in ids(pay(is_new_payee=False, context_text="urgent"))
    assert "pay.new_payee_urgency" not in ids(pay(is_new_payee=True, context_text="thanks"))


def test_bank_details_changed_flag_and_text():
    assert "pay.bank_details_changed" in ids(pay(bank_details_changed=True))
    assert "pay.bank_details_changed" in ids(pay(context_text="Note our NEW bank details below"))
    assert "pay.bank_details_changed" not in ids(pay(bank_details_changed=False))


def test_irreversible_method():
    assert "pay.irreversible_method" in ids(pay(method="crypto"))
    assert "pay.irreversible_method" in ids(pay(method="gift_card"))
    v = pay(method="bank_transfer", is_new_payee=True)
    assert "pay.irreversible_method" in ids(v)
    assert v.decision is Decision.ask  # a new-payee transfer with no name check asks (VoP match lowers it)
    assert "pay.irreversible_method" not in ids(pay(method="bank_transfer", is_new_payee=False))
    assert "pay.irreversible_method" not in ids(pay(method="card"))


def test_method_restricted():
    assert "pay.method_restricted" in ids(pay(context_text="We only accept bitcoin, sorry"))
    assert "pay.method_restricted" not in ids(pay(context_text="Card or PayPal is fine"))


def test_over_budget():
    assert "pay.over_budget" in ids(pay(amount=200, budget=150))
    assert "pay.over_budget" not in ids(pay(amount=150, budget=150))
    assert "pay.over_budget" not in ids(pay(amount=10_000))  # no budget given


def test_pressure_phrases():
    v = pay(context_text="Act now. Do not tell the bank, they'll block it. Guaranteed returns!")
    assert "pay.pressure_phrases" in ids(v)
    assert "pay.pressure_phrases" not in ids(pay(context_text="Invoice for October"))


def test_vop_results():
    assert pay(vop_result="no_match").reasons[0].weight == 60
    assert "pay.vop_mismatch" in ids(pay(vop_result="close_match"))
    assert "pay.vop_mismatch" not in ids(pay(vop_result="match"))
    assert "pay.vop_mismatch" not in ids(pay())


def test_score_capped_and_deny():
    v = pay(method="gift_card", is_new_payee=True, bank_details_changed=True, vop_result="no_match",
            context_text="urgent, keep this confidential, gift cards only")
    assert v.risk_score == 100 and v.decision is Decision.deny
    assert v.reasons == sorted(v.reasons, key=lambda r: r.weight, reverse=True)
