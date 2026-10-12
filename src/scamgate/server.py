"""MCP server (stdio) exposing check_url and check_payment."""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from scamgate import engine
from scamgate.models import PaymentCheck

mcp = MCPServer(
    "scamgate",
    instructions=(
        "Call check_url before opening any link and check_payment before making any payment. "
        "If the decision is 'ask', stop and show the reasons to the human. If 'deny', do not proceed. "
        "Results are advisory, not a guarantee."
    ),
)


@mcp.tool()
def check_url(url: str, intent: str | None = None) -> dict[str, Any]:
    """Check a link before opening it.

    Args:
        url: The full URL the agent is about to open.
        intent: What the agent is trying to do, e.g. "book a hotel in Galway".

    Returns a verdict: decision (allow | ask | deny), risk_score 0-100, and plain-English reasons.
    """
    return engine.check_url(url, intent).model_dump(mode="json")


@mcp.tool()
def check_payment(
    payee_name: str,
    payee_account: str,
    amount: float,
    currency: str,
    method: Literal["card", "bank_transfer", "crypto", "gift_card", "other"],
    context_text: str | None = None,
    is_new_payee: bool | None = None,
    bank_details_changed: bool | None = None,
    budget: float | None = None,
    vop_result: Literal["match", "close_match", "no_match", "unavailable"] | None = None,
) -> dict[str, Any]:
    """Check a payment before making it.

    Args:
        payee_name: Who is being paid.
        payee_account: IBAN, wallet address, merchant id, etc.
        amount: Amount to pay.
        currency: e.g. EUR, GBP, USDT.
        method: card, bank_transfer, crypto, gift_card or other.
        context_text: The messages or page text that led to this payment.
        is_new_payee: True if this payee has never been paid before.
        bank_details_changed: True if the payee's account details changed recently.
        budget: The spending limit the human gave for this task.
        vop_result: Verification of Payee result, if available.

    Returns a verdict: decision (allow | ask | deny), risk_score 0-100, and plain-English reasons.
    """
    check = PaymentCheck(
        payee_name=payee_name, payee_account=payee_account, amount=amount, currency=currency,
        method=method, context_text=context_text, is_new_payee=is_new_payee,
        bank_details_changed=bank_details_changed, budget=budget, vop_result=vop_result,
    )
    return engine.check_payment(check).model_dump(mode="json")


def run() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    run()
