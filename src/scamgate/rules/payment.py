"""Payment rules, based on common push-payment and purchase-scam typologies."""

from __future__ import annotations

import re

from scamgate.config import lst
from scamgate.models import PaymentCheck, PaymentMethod, VopResult
from scamgate.registry import Hit, RuleContext, register


def _text(check: PaymentCheck) -> str:
    return re.sub(r"\s+", " ", (check.context_text or "").lower().replace("’", "'"))


def _find(text: str, phrases: list[str]) -> list[str]:
    return [p for p in phrases if re.search(rf"(?<![a-z]){re.escape(p)}(?![a-z])", text)]


def _quote(found: list[str], n: int = 3) -> str:
    return ", ".join(f"'{f}'" for f in found[:n])


@register("pay.new_payee_urgency", kind="payment")
def new_payee_urgency(check: PaymentCheck, ctx: RuleContext) -> Hit | None:
    """First payment to this payee, and the request is urgent."""
    if not check.is_new_payee:
        return None
    found = _find(_text(check), lst(ctx.config, "urgency_terms"))
    if found:
        return Hit(
            f"This is a new payee and the request is urgent ({_quote(found)}). "
            "Scammers rush people so they skip checks."
        )
    return None


@register("pay.bank_details_changed", kind="payment")
def bank_details_changed(check: PaymentCheck, ctx: RuleContext) -> Hit | None:
    """Payee's bank details changed recently (invoice-redirection pattern)."""
    found = _find(_text(check), lst(ctx.config, "bank_change_phrases"))
    if check.bank_details_changed or found:
        why = f" (message says {_quote(found, 1)})" if found else ""
        return Hit(
            f"The payee's bank details have changed{why}. Invoice-redirection fraud works "
            "exactly like this; confirm the new account by phone using a number you already had."
        )
    return None


@register("pay.irreversible_method", kind="payment")
def irreversible_method(check: PaymentCheck, ctx: RuleContext) -> Hit | None:
    """Payment method is hard or impossible to reverse."""
    if check.method in (PaymentMethod.crypto, PaymentMethod.gift_card):
        label = "crypto" if check.method is PaymentMethod.crypto else "gift cards"
        return Hit(f"Paying by {label} is effectively irreversible, and it's the method scammers ask for most.")
    if check.method is PaymentMethod.bank_transfer and check.is_new_payee:
        if check.vop_result is not None and check.vop_result.value == "match":
            return Hit("A bank transfer to a new payee is hard to recall once sent. Your bank confirmed the "
                       "name matches the account, which helps.",
                       weight=int(ctx.rule_config.get("new_payee_transfer_vop_match_weight", 10)))
        return Hit(
            "A bank transfer to a new payee is hard to recall once sent. Check the name matches the account "
            "with your bank's Verification of Payee, or confirm the details by phone, before sending.",
            weight=int(ctx.rule_config.get("new_payee_transfer_weight", 25)),
        )
    return None


@register("pay.method_restricted", kind="payment")
def method_restricted(check: PaymentCheck, ctx: RuleContext) -> Hit | None:
    """Seller insists on a specific irreversible payment method."""
    found = _find(_text(check), lst(ctx.config, "method_restriction_phrases"))
    if found:
        return Hit(
            f"The seller restricts how you can pay ({_quote(found)}). Legit sellers rarely "
            "refuse protected methods like cards."
        )
    return None


@register("pay.over_budget", kind="payment")
def over_budget(check: PaymentCheck, ctx: RuleContext) -> Hit | None:
    """Amount exceeds the budget the human gave the agent."""
    if check.budget is not None and check.amount > check.budget:
        return Hit(
            f"{check.amount:,.2f} {check.currency} is over the budget of "
            f"{check.budget:,.2f} {check.currency}."
        )
    return None


@register("pay.pressure_phrases", kind="payment")
def pressure_phrases(check: PaymentCheck, ctx: RuleContext) -> Hit | None:
    """Messages use pressure, secrecy, or too-good-to-be-true language."""
    found = _find(_text(check), lst(ctx.config, "pressure_phrases"))
    if found:
        return Hit(
            f"The messages use pressure or secrecy language ({_quote(found)}), "
            "typical of CEO-fraud, impersonation and investment scams."
        )
    return None


@register("pay.vop_mismatch", kind="payment")
def vop_mismatch(check: PaymentCheck, ctx: RuleContext) -> Hit | None:
    """Verification of Payee says the name doesn't match the account."""
    if check.vop_result is None:
        return None
    weights = ctx.rule_config.get("weights", {})
    w = int(weights.get(check.vop_result.value, 0))
    msg = {
        VopResult.no_match: f"Verification of Payee says '{check.payee_name}' does NOT match the account holder.",
        VopResult.close_match: f"Verification of Payee only partly matches '{check.payee_name}'; check the exact name.",
        VopResult.unavailable: "Verification of Payee wasn't available, so the payee name is unconfirmed.",
        VopResult.match: "Verification of Payee matched.",
    }[check.vop_result]
    return Hit(msg, weight=w) if w > 0 else None


@register("pay.unbacked_known_claim", kind="payment")
def unbacked_known_claim(check: PaymentCheck, ctx: RuleContext) -> Hit | None:
    """The agent said this is a known payee, but there's no record of paying them."""
    if check.agent_claim_unbacked:
        return Hit("The agent described this as a payee you know, but you've never paid them from here. "
                   "Scam messages often claim familiarity to skip checks.")
    return None
