"""check_url and check_payment as agent tools, defined once for the MCP server and the Hermes plugin."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field

from . import engine
from .models import PaymentCheck, Verdict

URL_DESCRIPTION = (
    "Check a link before opening it. Returns a verdict: decision (allow | ask | deny), risk_score 0-100, "
    "plain-English reasons, and checked_host, the host the link really opens. If the decision is ask, stop and "
    "show the reasons to the human. If deny, do not proceed. Results are advisory, not a guarantee."
)
PAYMENT_DESCRIPTION = (
    "Check a payment before making it. Returns a verdict: decision (allow | ask | deny), risk_score 0-100 and "
    "plain-English reasons. If the decision is ask, stop and show the reasons to the human. If deny, do not "
    "proceed. Results are advisory, not a guarantee."
)

# Generous protocol limits. A link over 8 KiB but under these still gets a verdict (url.unreadable asks),
# because an error is something an agent might route around.
Url = Annotated[str, Field(max_length=65536, description="The full URL the agent is about to open.")]
Intent = Annotated[str | None, Field(max_length=2000,
                                     description='What the agent is trying to do, e.g. "book a hotel in Galway".')]
PayeeName = Annotated[str, Field(max_length=500, description="Who is being paid.")]
PayeeAccount = Annotated[str, Field(max_length=500, description="IBAN, wallet address, merchant id, etc.")]
Amount = Annotated[float, Field(ge=0, allow_inf_nan=False, description="Amount to pay.")]
Currency = Annotated[str, Field(max_length=16, description="e.g. EUR, GBP, USDT.")]
Method = Annotated[Literal["card", "bank_transfer", "crypto", "gift_card", "other"],
                   Field(description="card, bank_transfer, crypto, gift_card or other.")]
ContextText = Annotated[str | None, Field(max_length=20000,
                                          description="The messages or page text that led to this payment.")]
IsNewPayee = Annotated[bool | None, Field(description="True if this payee has never been paid before. scamgate "
                                                      "checks your payee history rather than taking this on trust.")]
BankDetailsChanged = Annotated[bool | None, Field(description="True if the payee's account details changed recently.")]
Budget = Annotated[float | None, Field(ge=0, allow_inf_nan=False,
                                       description="The spending limit the human gave for this task.")]
Vop = Annotated[Literal["match", "close_match", "no_match", "unavailable"] | None,
                Field(description="Verification of Payee result, if available.")]


class UrlArgs(BaseModel):
    url: Url
    intent: Intent = None


class PaymentArgs(BaseModel):
    payee_name: PayeeName
    payee_account: PayeeAccount
    amount: Amount
    currency: Currency
    method: Method
    context_text: ContextText = None
    is_new_payee: IsNewPayee = None
    bank_details_changed: BankDetailsChanged = None
    budget: Budget = None
    vop_result: Vop = None


def check_url(args: UrlArgs) -> Verdict:
    return engine.check_url(args.url, args.intent)


def check_payment(args: PaymentArgs) -> Verdict:
    return engine.check_payment(PaymentCheck(**args.model_dump()))
