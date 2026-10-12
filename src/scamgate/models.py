"""Shared input and verdict models."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Decision(str, Enum):
    allow = "allow"
    ask = "ask"  # stop and ask the human
    deny = "deny"


class PaymentMethod(str, Enum):
    card = "card"
    bank_transfer = "bank_transfer"
    crypto = "crypto"
    gift_card = "gift_card"
    other = "other"


class VopResult(str, Enum):
    """Verification of Payee (name vs account) result, if the caller has one."""

    match = "match"
    close_match = "close_match"
    no_match = "no_match"
    unavailable = "unavailable"


class Reason(BaseModel):
    rule_id: str
    explanation: str = Field(description="Plain-English reason a human can read")
    weight: int = Field(ge=0, le=100)


class Verdict(BaseModel):
    decision: Decision
    risk_score: int = Field(ge=0, le=100)
    reasons: list[Reason] = Field(default_factory=list)
    summary: str
    warnings: list[str] = Field(default_factory=list, description="Notes about the check itself, e.g. a stale feed cache")
    advisory: str = (
        "scamgate is advisory. It can miss scams and flag legitimate actions; "
        "a human should make the final call on anything flagged."
    )


class UrlCheck(BaseModel):
    url: str
    intent: str | None = None


class PaymentCheck(BaseModel):
    payee_name: str
    payee_account: str = Field(description="IBAN, wallet address, card merchant id, etc.")
    amount: float = Field(ge=0)
    currency: str
    method: PaymentMethod
    context_text: str | None = Field(
        default=None, description="Messages or page text that led to this payment"
    )
    is_new_payee: bool | None = None
    agent_claim_unbacked: bool = Field(
        default=False, exclude=True,
        description="Set by scamgate, not the caller: the agent called a payee known with no record of it",
    )
    bank_details_changed: bool | None = None
    budget: float | None = None
    vop_result: VopResult | None = None
