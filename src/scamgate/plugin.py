"""Hermes plugin: the same gate as the shell hook, in-process.

Hermes calls `pre_tool_call` before every tool. This returns the hook's decision.
Under `/yolo` or `approvals.mode: off`, Hermes would auto-approve an ask, so an ask
becomes a block unless the user set `when_approvals_off: allow`.
"""

from __future__ import annotations

import json
import os
from typing import Any

from pydantic import BaseModel, ValidationError

from . import asklog, hook, tools

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
    try:
        decision = hook.handle({
            "hook_event_name": "pre_tool_call",
            "tool_name": tool_name,
            "tool_input": args if isinstance(args, dict) else {},
            "session_id": session_id or task_id or "",
            "extra": {"tool_call_id": tool_call_id or "", "task_id": task_id or ""},
        })
    except Exception as exc:  # fail closed like the shell hook; don't rely on how Hermes treats a raising hook
        return {"action": "block", "message": f"scamgate hook error, failing closed: {type(exc).__name__}: "
                                              f"{str(exc)[:200]}"}
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
    try:
        hook.handle({
            "hook_event_name": "post_tool_call",
            "tool_name": tool_name,
            "tool_input": {},
            "session_id": session_id or task_id or "",
            "extra": {"tool_call_id": tool_call_id or "", "task_id": task_id or "", "status": status},
        })
    except Exception:
        pass  # a post event only records whether you approved; it must never break the tool call
    return None


def _run_tool(fn: Any, model: type[BaseModel], args: Any) -> str:
    """Same arguments and checks as the MCP tool. Bad arguments come back as an error, never a crash."""
    try:
        parsed = model.model_validate(args if isinstance(args, dict) else {})
    except ValidationError as exc:
        problems = "; ".join(f"{'.'.join(map(str, e['loc'])) or 'arguments'}: {e['msg']}" for e in exc.errors())
        return json.dumps({"error": f"scamgate couldn't read these arguments ({problems})."})
    return json.dumps(fn(parsed).model_dump(mode="json"))


def check_url(args: dict, **_: Any) -> str:
    return _run_tool(tools.check_url, tools.UrlArgs, args)


def check_payment(args: dict, **_: Any) -> str:
    return _run_tool(tools.check_payment, tools.PaymentArgs, args)


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
        lines = []
        for r in rows[:8]:
            top = next(iter(r.rules), "")
            lines.append(f"{r.host}: {r.asks} asked ({r.ran} approved, {r.not_run} refused, {r.pending} pending), "
                         f"{r.blocks} blocked" + (f"; top rule {top}" if top else ""))
        return "scamgate, last 7 days:\n" + "\n".join(lines)
    if cmd == "update":
        return "scamgate: feed updates download data from the internet. Run `scamgate update-feeds` yourself."
    return "Usage: /scamgate status | review | update"


def _parameters(model: type[BaseModel]) -> dict:
    """The tool's JSON schema for Hermes, from the same model the MCP tool uses (minus titles and null branches)."""
    schema = model.model_json_schema()
    props = {}
    for name, prop in schema["properties"].items():
        prop = {k: v for k, v in prop.items() if k not in ("title", "default")}
        if "anyOf" in prop:
            branches = [b for b in prop.pop("anyOf") if b.get("type") != "null"]
            if len(branches) == 1:
                prop.update(branches[0])
            else:
                prop["anyOf"] = branches
        props[name] = prop
    return {"type": "object", "properties": props, "required": schema.get("required", [])}


_URL_SCHEMA = {"name": "scamgate_check_url", "description": tools.URL_DESCRIPTION,
               "parameters": _parameters(tools.UrlArgs)}
_PAY_SCHEMA = {"name": "scamgate_check_payment", "description": tools.PAYMENT_DESCRIPTION,
               "parameters": _parameters(tools.PaymentArgs)}


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
