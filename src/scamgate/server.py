"""MCP server (stdio) exposing check_url, check_payment and update_feeds."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import domainage, refresh, tools
from .models import Verdict

mcp = MCPServer(
    "scamgate",
    instructions=(
        "Call check_url before opening any link and check_payment before making any payment. "
        "If the decision is 'ask', stop and show the reasons to the human. If 'deny', do not proceed. "
        "If a verdict warns that the phishing lists are missing or stale, call update_feeds. "
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


@mcp.tool(description=tools.UPDATE_DESCRIPTION,
          annotations=ToolAnnotations(title="Refresh the phishing lists", read_only_hint=False,
                                      destructive_hint=False, idempotent_hint=True, open_world_hint=True))
def update_feeds() -> tools.UpdateResult:
    """No parameters on purpose: an agent can ask for a refresh, not choose what is downloaded."""
    return tools.update_feeds()


SERVER_FIRST_REFRESH_DELAY = 10.0  # seconds after start; a pass downloads only when the lists are 6 hours old
SERVER_REFRESH_EVERY = 30 * 60.0


def run() -> None:
    # Opt-in for the server: an MCP server someone configured by hand keeps today's behaviour (no downloads
    # unless asked). The Claude Code plugin turns it on through its auto_update_feeds setting.
    if refresh.env_flag("SCAMGATE_AUTO_UPDATE", default=False):
        refresh.start_background(first_delay=SERVER_FIRST_REFRESH_DELAY, every=SERVER_REFRESH_EVERY)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    run()
