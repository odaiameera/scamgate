"""Hermes plugin: the same gate as the shell hook, in-process.

Hermes calls `pre_tool_call` before every tool. This returns the hook's decision.
Under `/yolo` or `approvals.mode: off`, Hermes would auto-approve an ask, so an ask
becomes a block unless the user set `when_approvals_off: allow`.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any

from pydantic import BaseModel, ValidationError

from . import asklog, hook, refresh, tools

_CTX: Any = None
_log = logging.getLogger("scamgate")


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
    """`/scamgate status | review | update`. Hermes runs this in a worker thread, so `update` can download."""
    cmd = (raw_args or "").strip().lower()
    if cmd in ("", "status"):
        try:
            from .feeds import LazyFeedIndex
            feeds = LazyFeedIndex()
            if not feeds:
                return "scamgate: no phishing lists cached. Run `/scamgate update` to download them."
            _, lines = refresh.status()
            stale = sorted(feeds.stale_feeds(hours=24))
            head = ("scamgate: lists are stale (" + ", ".join(stale) + "). Run `/scamgate update`." if stale
                    else "scamgate: phishing lists are loaded.")
            return head + "\n" + "\n".join(lines)
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
        return refresh.refresh().text()
    return "Usage: /scamgate status | review | update"


def update_feeds_tool(args: Any = None, **_: Any) -> str:
    """The agent's refresh button. It takes no arguments: whatever the agent sends is ignored, the default
    feeds are downloaded from their fixed sources into the configured cache, at most once an hour."""
    try:
        out = refresh.refresh(if_older_than_hours=refresh.TOOL_MIN_GAP_HOURS)
    except Exception as exc:  # a full disk or a broken cache folder must not crash the chat
        return json.dumps({"updated": [], "failed": {"all": f"{type(exc).__name__}: {str(exc)[:200]}"},
                           "skipped": ""})
    return json.dumps({**out.as_dict(), "summary": out.text()})


# ---------------------------------------------------------------- background refresh

AUTO_FIRST_DELAY = 120.0  # seconds; a short-lived `hermes ...` command exits before the first pass
AUTO_EVERY = 30 * 60.0  # seconds between checks; a pass downloads only when the lists are 6 hours old
_AUTO_LOCK = threading.Lock()
_AUTO: tuple[threading.Thread, threading.Event] | None = None


def auto_update_enabled(ctx: Any = None) -> bool:
    env = os.environ.get("SCAMGATE_AUTO_UPDATE")
    if env is not None and env.strip().lower() in ("0", "false", "off", "no"):
        return False
    val = None
    if ctx is not None:
        try:
            val = ctx.get_config("auto_update_feeds", None)
        except Exception:
            val = None
    if isinstance(val, str):
        return val.strip().lower() not in ("0", "false", "off", "no")
    return val is None or bool(val)


def _auto_loop(stop: threading.Event) -> None:
    if stop.wait(AUTO_FIRST_DELAY):
        return
    while True:
        try:
            out = refresh.auto_pass()
            if out.failed:
                _log.warning("scamgate: background feed refresh failed for %s", ", ".join(out.failed))
        except Exception:
            _log.warning("scamgate: background feed refresh failed", exc_info=True)
        if stop.wait(AUTO_EVERY):
            return


def start_auto_update(ctx: Any = None) -> threading.Thread | None:
    """One daemon thread per process. Processes share the lock file, so only one downloads at a time."""
    global _AUTO
    if not auto_update_enabled(ctx):
        return None
    with _AUTO_LOCK:
        if _AUTO is not None and _AUTO[0].is_alive() and not _AUTO[1].is_set():
            return _AUTO[0]
        stop = threading.Event()
        thread = threading.Thread(target=_auto_loop, args=(stop,), name="scamgate-feed-refresh", daemon=True)
        _AUTO = (thread, stop)
        thread.start()
    on_unload = getattr(ctx, "on_unload", None)
    if callable(on_unload):
        try:
            on_unload(stop.set)
        except Exception:
            pass
    return thread


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
UPDATE_DESCRIPTION = (
    "Refresh scamgate's phishing lists now. Use it when a scamgate verdict or /scamgate status says the lists "
    "are missing or stale. Takes no arguments: it always downloads the default lists from their fixed sources, "
    "and does nothing if they were refreshed in the last hour. The lists also refresh by themselves every 6 hours."
)
_UPDATE_SCHEMA = {"name": "scamgate_update_feeds", "description": UPDATE_DESCRIPTION,
                  "parameters": {"type": "object", "properties": {}, "additionalProperties": False}}


def register(ctx) -> None:
    global _CTX
    _CTX = ctx
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_tool(name="scamgate_check_url", toolset="scamgate", schema=_URL_SCHEMA, handler=check_url,
                      description=_URL_SCHEMA["description"], emoji="🛡️")
    ctx.register_tool(name="scamgate_check_payment", toolset="scamgate", schema=_PAY_SCHEMA, handler=check_payment,
                      description=_PAY_SCHEMA["description"], emoji="🛡️")
    ctx.register_tool(name="scamgate_update_feeds", toolset="scamgate", schema=_UPDATE_SCHEMA,
                      handler=update_feeds_tool, description=UPDATE_DESCRIPTION, emoji="🛡️")
    ctx.register_command("scamgate", slash, description="scamgate status, review, or update the phishing lists",
                         args_hint="status|review|update")
    if callable(getattr(ctx, "register_cli_command", None)):  # Hermes builds without it just skip the CLI
        try:
            ctx.register_cli_command("scamgate", help="scamgate phishing lists: update-feeds, feeds-status",
                                     setup_fn=refresh.setup_cli, handler_fn=refresh.cli_main,
                                     description="Refresh or inspect scamgate's cached phishing lists.")
        except Exception:  # a CLI that can't be wired must never stop the gate from loading
            _log.warning("scamgate: could not add `hermes scamgate`", exc_info=True)
    start_auto_update(ctx)
