"""MCP server (stdio) exposing check_url and check_payment."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import domainage, tools
from .models import Verdict

mcp = MCPServer(
    "scamgate",
    instructions=(
        "Call check_url before opening any link and check_payment before making any payment. "
        "If the decision is 'ask', stop and show the reasons to the human. If 'deny', do not proceed. "
        "Results are advisory, not a guarantee."
    ),
)


def _reads_only(title: str, *, online: bool = False) -> ToolAnnotations:
    """Both tools only read local state. check_url goes online only with SCAMGATE_RDAP=live."""
    return ToolAnnotations(title=title, read_only_hint=True, destructive_hint=False, idempotent_hint=True,
                           open_world_hint=online)


@mcp.tool(description=tools.URL_DESCRIPTION,
          annotations=_reads_only("Check a link", online=domainage.mode() == "live"))
def check_url(url: tools.Url, intent: tools.Intent = None) -> Verdict:
    return tools.check_url(tools.UrlArgs(url=url, intent=intent))


@mcp.tool(description=tools.PAYMENT_DESCRIPTION, annotations=_reads_only("Check a payment"))
def check_payment(
    payee_name: tools.PayeeName,
    payee_account: tools.PayeeAccount,
    amount: tools.Amount,
    currency: tools.Currency,
    method: tools.Method,
    context_text: tools.ContextText = None,
    is_new_payee: tools.IsNewPayee = None,
    bank_details_changed: tools.BankDetailsChanged = None,
    budget: tools.Budget = None,
    vop_result: tools.Vop = None,
) -> Verdict:
    return tools.check_payment(tools.PaymentArgs(
        payee_name=payee_name, payee_account=payee_account, amount=amount, currency=currency, method=method,
        context_text=context_text, is_new_payee=is_new_payee, bank_details_changed=bank_details_changed,
        budget=budget, vop_result=vop_result,
    ))


def run() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    run()
