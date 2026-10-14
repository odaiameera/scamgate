"""Hermes plugin: the same gate as the shell hook, in-process.

Hermes calls `pre_tool_call` before every tool. This returns the hook's decision.
Under `/yolo` or `approvals.mode: off`, Hermes would auto-approve an ask, so an ask
becomes a block unless the user set `when_approvals_off: allow`.
"""

from __future__ import annotations

import json
import os
from typing import Any

from . import asklog, engine, hook
from .models import PaymentCheck

_CTX: Any = None


def approvals_bypassed(session_id: str = "") -> bool:
    """True when this chat will not actually ask a human. Importing Hermes is optional."""
    try:
        from tools.approval import is_approval_bypass_active_for_session
    except Exception:
        return False
    try:
        return bool(is_approval_bypass_active_for_session(session_id or ""))
    except Exception:
        return False


def when_approvals_off() -> str:
    val = None
    if _CTX is not None:
        try:
            val = _CTX.get_config("when_approvals_off", None)
        except Exception:
            val = None
    if not val:
        val = os.environ.get("SCAMGATE_WHEN_APPROVALS_OFF", "block")
    return str(val).strip().lower()


def on_pre_tool_call(tool_name: str = "", args: Any = None, session_id: str = "",
                     tool_call_id: str = "", task_id: str = "", **_: Any) -> dict | None:
    decision = hook.handle({
        "hook_event_name": "pre_tool_call",
        "tool_name": tool_name,
        "tool_input": args if isinstance(args, dict) else {},
        "session_id": session_id or task_id or "",
        "extra": {"tool_call_id": tool_call_id or "", "task_id": task_id or ""},
    })
    if not decision:
        return None
    if decision.get("action") == "approve" and approvals_bypassed(session_id) and when_approvals_off() != "allow":
        message = decision.get("message") or "scamgate would have asked a human."
        return {"action": "block", "message": message + " Approvals are off in this chat, so scamgate blocked it "
                                              "instead of asking. Turn approvals back on, or set "
                                              "plugins.entries.scamgate.settings.when_approvals_off to allow if you "
                                              "accept that risk."}
    return decision


def on_post_tool_call(tool_name: str = "", session_id: str = "", tool_call_id: str = "",
                      task_id: str = "", status: str | None = None, **_: Any) -> None:
    hook.handle({
        "hook_event_name": "post_tool_call",
        "tool_name": tool_name,
        "tool_input": {},
        "session_id": session_id or task_id or "",
        "extra": {"tool_call_id": tool_call_id or "", "task_id": task_id or "", "status": status},
    })
    return None


def check_url(args: dict, **_: Any) -> str:
    url = str((args or {}).get("url") or "")
    intent = (args or {}).get("intent")
    return json.dumps(engine.check_url(url, intent).model_dump(mode="json"))


def check_payment(args: dict, **_: Any) -> str:
    raw = args or {}
    check = PaymentCheck(
        payee_name=str(raw.get("payee_name") or ""),
        payee_account=str(raw.get("payee_account") or ""),
        amount=float(raw.get("amount") or 0),
        currency=str(raw.get("currency") or "?"),
        method=raw.get("method") or "other",
        context_text=raw.get("context_text"),
    )
    return json.dumps(engine.check_payment(check).model_dump(mode="json"))


def slash(raw_args: str = "") -> str:
    cmd = (raw_args or "").strip().lower()
    if cmd in ("", "status"):
        try:
            from .feeds import LazyFeedIndex
            feeds = LazyFeedIndex()
            stale = sorted(feeds.stale_feeds(hours=24)) if feeds else []
            if not feeds:
                return "scamgate: no phishing lists cached. Run `scamgate update-feeds`."
            if stale:
                return "scamgate: lists are stale (" + ", ".join(stale) + "). Run `scamgate update-feeds`."
            return "scamgate: phishing lists are loaded."
        except Exception as exc:
            return f"scamgate: could not read feed status ({type(exc).__name__})."
    if cmd == "review":
        rows = asklog.summarize(days=7)
        if not rows:
            return "scamgate: nothing in the ask log for the last 7 days."
        lines = [f"{getattr(r, 'decision', '?')} {getattr(r, 'tool', '')} {getattr(r, 'summary', '')}".strip()
                 for r in rows[:8]]
        return "scamgate, last 7 days:\n" + "\n".join(lines)
    if cmd == "update":
        return "scamgate: feed updates download data from the internet. Run `scamgate update-feeds` yourself."
    return "Usage: /scamgate status | review | update"


_URL_SCHEMA = {
    "name": "scamgate_check_url",
    "description": "Check a link before opening it. If the decision is ask, stop and show the reasons. If deny, do not proceed.",
    "parameters": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "The full URL about to be opened"},
            "intent": {"type": "string", "description": "What this link is for"},
        },
        "required": ["url"],
    },
}
_PAY_SCHEMA = {
    "name": "scamgate_check_payment",
    "description": "Check a payment before making it. If the decision is ask, stop and show the reasons. If deny, do not proceed.",
    "parameters": {
        "type": "object",
        "properties": {
            "payee_name": {"type": "string"},
            "payee_account": {"type": "string", "description": "IBAN, wallet address, or merchant id"},
            "amount": {"type": "number"},
            "currency": {"type": "string"},
            "method": {"type": "string", "enum": ["card", "bank_transfer", "crypto", "gift_card", "other"]},
            "context_text": {"type": "string"},
        },
        "required": ["payee_name", "payee_account", "amount", "currency", "method"],
    },
}


def register(ctx) -> None:
    global _CTX
    _CTX = ctx
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_tool(name="scamgate_check_url", toolset="scamgate", schema=_URL_SCHEMA, handler=check_url,
                      description=_URL_SCHEMA["description"], emoji="🛡️")
    ctx.register_tool(name="scamgate_check_payment", toolset="scamgate", schema=_PAY_SCHEMA, handler=check_payment,
                      description=_PAY_SCHEMA["description"], emoji="🛡️")
    ctx.register_command("scamgate", slash, description="scamgate status, review, or how to update feeds",
                         args_hint="status|review|update")
