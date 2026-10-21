"""Payment gating for the hook: money-moving tool calls get the same check as `check_payment`.

Without this, `check_payment` is voluntary: an injected agent can pay through a wallet, banking or
payments MCP tool, or a payments API call in a shell, without ever asking scamgate. The hook now:

1. Spots a payment in a tool call: a tool whose name says it moves money (pay, payout, transfer,
   withdraw, send_crypto...), or any tool whose arguments carry an amount AND a destination
   account (IBAN, wallet address, account number).
2. Pulls out payee, account, amount, currency and method from the arguments, and runs the normal
   payment rules with local payee history (the agent's claims about the payee are ignored).
3. Spots payments in shell/code: crypto CLIs (`cast send`, `bitcoin-cli sendtoaddress`,
   `solana transfer`...) and write calls to payment APIs (Stripe, PayPal, Wise, Revolut Business...).
   Those can't be scored, so a human approves them.

Like the rest of the hook it never says "allow": a low-risk payment passes silently.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------- tool names

_STRONG = re.compile(r"(?:^|_)(?:pay|pays|payment|payments|payout|payouts|send_?money|send_?payment|withdraw|"
                     r"withdrawal|wire|remit|remittance|disburse|sepa|send_?(?:eth|btc|sol|crypto|coin|coins|token|"
                     r"tokens|usdc|usdt|funds|transaction|tx|native)|transfer_?(?:funds|money|eth|btc|sol|token|tokens|"
                     r"crypto|usdc|usdt|native)|sign_?(?:and_?send_?)?transaction|capture_?(?:order|payment)|"
                     r"create_?charge|charge_?card|tip)(?:_|$)")
_WEAK = re.compile(r"(?:^|_)(?:transfer|send|order|buy|purchase|checkout|charge|swap|bridge|deposit|"
                   r"top_?up|refund|invoice)(?:_|$)")

# ---------------------------------------------------------------- argument keys

_AMOUNT_KEYS = ("amount", "amount_value", "value", "sum", "total", "total_amount", "price", "amount_cents",
                "amount_minor", "amount_in_cents", "unit_amount", "quantity_usd")
_MINOR_KEYS = {"amount_cents", "amount_minor", "amount_in_cents", "unit_amount"}
_CURRENCY_KEYS = ("currency", "ccy", "currency_code", "asset", "token", "coin", "symbol", "denom")
_ACCOUNT_KEYS = ("iban", "payee_account", "beneficiary_account", "creditor_account", "account_number",
                 "account", "to_address", "recipient_address", "destination_address", "wallet_address",
                 "receiver_address", "address", "destination", "to", "recipient", "receiver", "payee",
                 "beneficiary", "wallet", "sort_code", "routing_number", "card_number", "merchant_id", "pay_to")
_NAME_KEYS = ("payee_name", "beneficiary_name", "recipient_name", "creditor_name", "account_holder",
              "account_name", "holder_name", "merchant_name", "to_name", "name", "payee", "beneficiary",
              "recipient", "merchant", "counterparty")
_CONTEXT_KEYS = ("reference", "memo", "description", "note", "message", "purpose", "remittance_information",
                 "statement_descriptor", "narrative", "comment", "details", "reason")
_ACCOUNT_RE = re.compile(r"""(?ix)^(?:
    [A-Z]{2}\d{2}[A-Z0-9 ]{10,32}            # IBAN
  | 0x[0-9a-f]{40}                          # EVM address
  | (?:bc1|[13])[a-z0-9]{25,62}             # bitcoin
  | [1-9A-HJ-NP-Za-km-z]{32,44}             # base58 (Solana etc.)
  | \d{6,18}                                # account number
  | (?:acct|ba|card|cus|pm|src)_[A-Za-z0-9]{6,}  # Stripe-style ids
  | [\w.+-]+@[\w-]+(?:\.[\w-]+)+            # email (PayPal payouts)
  | \$[A-Za-z][\w-]{1,30}                   # cashtag
  )$""")
_CRYPTO = {"btc", "eth", "usdt", "usdc", "sol", "bnb", "xrp", "doge", "ada", "trx", "matic", "pol", "dai",
           "ltc", "avax", "ton", "xmr", "arb", "op", "wbtc", "weth", "shib", "link", "dot", "atom"}


@dataclass
class Payment:
    payee_name: str = ""
    payee_account: str = ""
    amount: float = 0.0
    amount_known: bool = False
    currency: str = ""
    method: str = "other"
    context: str = ""
    why: str = ""


@dataclass
class CodePayment:
    detail: str
    hosts: list[str] = field(default_factory=list)


def _flat(value: Any, out: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    """First value seen for each lowercased key, anywhere in the arguments."""
    if depth > 12:
        return out
    if isinstance(value, dict):
        for k, v in value.items():
            key = str(k).lower().replace("-", "_")
            if not isinstance(v, (dict, list)) and key not in out and v not in (None, ""):
                out[key] = v
        for v in value.values():
            if isinstance(v, (dict, list)):
                _flat(v, out, depth + 1)
    elif isinstance(value, list):
        for v in value[:20]:
            _flat(v, out, depth + 1)
    return out


def _first(flat: dict[str, Any], keys: tuple[str, ...]) -> tuple[str, Any]:
    for k in keys:
        if k in flat:
            return k, flat[k]
    return "", None


def _num(v: Any) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v) if math.isfinite(v) else None  # JSON "Infinity"/"NaN" isn't an amount scamgate can read
    if isinstance(v, str):
        s = re.sub(r"[^\d.,-]", "", v)
        if s.count(",") and s.count("."):
            s = s.replace(",", "")
        elif s.count(",") == 1 and len(s.split(",")[1]) in (1, 2):
            s = s.replace(",", ".")
        else:
            s = s.replace(",", "")
        try:
            return float(s)
        except ValueError:
            return None
    return None


def _looks_like_account(v: Any) -> bool:
    return isinstance(v, str) and bool(_ACCOUNT_RE.match(v.strip()))


def _method(tool: str, account: str, currency: str) -> str:
    t, a, c = tool.lower(), account.strip(), currency.lower()
    if c in _CRYPTO or re.match(r"^(?:0x[0-9a-fA-F]{40}|bc1|[13][a-km-zA-HJ-NP-Z1-9]{25,34}$)", a) \
            or re.search(r"crypto|wallet|eth|btc|sol|token|coin|swap|bridge|onchain|web3", t):
        return "crypto"
    if "gift" in t:
        return "gift_card"
    if re.match(r"^[A-Z]{2}\d{2}", a.replace(" ", "")) or re.search(r"transfer|wire|sepa|payout|iban|bank|remit", t):
        return "bank_transfer"
    if re.search(r"card|checkout|charge|purchase|buy|order", t) or a.startswith(("card_", "pm_")):
        return "card"
    return "other"


def detect(tool: str, canon: str, tool_input: dict) -> Payment | None:
    """A Payment if this tool call moves money, else None."""
    flat = _flat(tool_input, {})
    akey, amount = _first(flat, _AMOUNT_KEYS)
    amt = _num(amount)
    if amt is not None and akey in _MINOR_KEYS:
        amt = amt / 100
    acct_key, account = next(((k, flat[k]) for k in _ACCOUNT_KEYS if k in flat and _looks_like_account(flat[k])),
                             ("", None))
    strong = bool(_STRONG.search(canon))
    weak = bool(_WEAK.search(canon))
    money_args = amt is not None and account is not None
    if not (strong or money_args or (weak and amt is not None and (account is not None or
                                                                    _first(flat, _CURRENCY_KEYS)[1]))):
        return None
    _, name = _first(flat, _NAME_KEYS)
    if name is not None and (not isinstance(name, str) or name == account):
        name = None
    _, cur = _first(flat, _CURRENCY_KEYS)
    ctx = " ".join(str(flat[k]) for k in _CONTEXT_KEYS if k in flat and isinstance(flat[k], str))[:2000]
    acct = str(account).strip() if account is not None else ""
    return Payment(
        payee_name=(str(name).strip() if name else acct)[:200],
        payee_account=acct[:200],
        amount=max(amt or 0.0, 0.0),
        amount_known=amt is not None,
        currency=(str(cur).upper()[:12] if cur else ""),
        method=_method(canon + " " + tool, acct, str(cur or "")),
        context=ctx,
        why="the tool name" if strong else "an amount and a destination account in the arguments",
    )


# ---------------------------------------------------------------- shell / code

_CRYPTO_CLI = re.compile(r"""(?ix)\b(?:
    cast\s+(?:send|publish)\b | bitcoin-cli\b[^\n]*\b(?:sendtoaddress|sendmany|sendrawtransaction|send|walletcreatefundedpsbt)\b
  | electrum\b[^\n]*\b(?:payto|paytomany|broadcast)\b | solana\s+transfer\b | spl-token\s+transfer\b
  | near\s+(?:send|tokens)\b | aptos\s+account\s+transfer\b | sui\s+client\s+(?:transfer|pay|pay-sui|pay-all-sui)\b
  | lncli\s+(?:sendpayment|payinvoice|sendcoins)\b | lightning-cli\s+(?:pay|withdraw|keysend)\b
  | eth_sendTransaction | eth_sendRawTransaction | sendRawTransaction\( | sendTransaction\( | signAndSendTransaction
  | web3\.eth\.send | \.functions\.transfer\( | wallet\.send_?(?:transaction|coins)\(
  )""")
_PAY_HOSTS = ("api.stripe.com", "api.paypal.com", "api-m.paypal.com", "api.wise.com", "api.transferwise.com",
              "b2b.revolut.com", "api.revolut.com", "api.coinbase.com", "api.commerce.coinbase.com",
              "api.gocardless.com", "adyenpayments.com", "api.adyen.com", "api.checkout.com", "api.mollie.com",
              "connect.squareup.com", "api.squareup.com", "api.braintreegateway.com", "api.razorpay.com",
              "api.paystack.co", "api.kraken.com", "api.binance.com", "api.circle.com", "api.moonpay.com",
              "api.monzo.com", "api.starlingbank.com", "api.truelayer.com", "api.modulrfinance.com",
              "api.currencycloud.com", "api.airwallex.com", "api.payoneer.com", "api.bitpay.com")
_PAY_PATH = re.compile(r"(?i)/(?:[\w-]*/)*(?:pay|payments?|payouts?|transfers?|charges?|payment_intents|"
                       r"checkout|orders?|withdraw\w*|send\w*|disburse\w*|refunds?|captures?|"
                       r"capital/withdraw|quotes?|batch_payments)\b")
_WRITE = re.compile(r"""(?ix)(?:\s-X\s*['"]?(?:POST|PUT|PATCH)\b|\s--request\s+['"]?(?:POST|PUT|PATCH)\b|\s-d[\s'"@]|
                       \s--data\b|\s--data-\w+\b|\s--json\b|\s-F\s|\.post\(|\.put\(|\.patch\(|
                       method\s*[:=]\s*['"](?:post|put|patch)['"]|request\(\s*['"](?:post|put|patch)['"]|
                       Invoke-(?:RestMethod|WebRequest)\b[^\n]*-Method\s+(?:Post|Put|Patch))""")
_HOST_IN = re.compile(r"(?i)https?://([a-z0-9.-]+)(/[^\s'\"`)]*)?")


_SDK_PAY = re.compile(
    r"(?i)\bstripe\.(?:Payout|PaymentIntent|Transfer|Charge|Refund|Subscription)\.create\b"
    r"|\bpaypal\.Payout\b|\.payouts\(\)\.create\b"
)


def scan_code(code: str) -> CodePayment | None:
    if m := _CRYPTO_CLI.search(code):
        return CodePayment(f"a crypto transaction ('{m.group(0).strip()[:40]}')")
    if m := _SDK_PAY.search(code):
        return CodePayment(f"a payment SDK call ('{m.group(0).strip()[:40]}')")
    if not _WRITE.search(code):
        return None
    hosts = []
    for m in _HOST_IN.finditer(code):
        host, path = m.group(1).lower(), m.group(2) or ""
        if "sandbox" in host or ".test" in host or "-test" in host:
            continue
        if any(host == h or host.endswith("." + h) for h in _PAY_HOSTS) and _PAY_PATH.search(path):
            hosts.append(host)
    if hosts:
        return CodePayment(f"a payment API call to {hosts[0]}", hosts)
    return None
