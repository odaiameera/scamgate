"""Generate the website's demo data from real scamgate output.

    uv run python scripts/site_demo_data.py          # writes site/assets/demo-data.js

Every verdict on the website comes from this file, so the site never shows made-up output.
tests/test_site_demo.py fails if the committed file drifts from what the engine returns.
Feeds are disabled (empty cache) so the output is deterministic.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "site" / "assets" / "demo-data.js"

URLS = [
    ("https://paypal.com@evil.example/login", None),
    ("https://paypal.com.secure-login.xyz/verify", None),
    ("https://paypa1.com/login", "buy a ticket"),
    ("http://xn--pple-43d.com/", None),
    ("https://someone@shop.example/basket", None),
    ("http://203.0.113.9/aib/login", None),
    ("https://crypto-doubler.example/", None),
    ("https://www.revolut.com/", None),
]

PAYMENTS = [
    dict(payee_name="Prize Desk", payee_account="GIFT-CODE", amount=300, currency="EUR", method="gift_card",
         context_text="Pay today or the prize is cancelled. Keep this between us.", is_new_payee=True),
    dict(payee_name="Acme Ltd", payee_account="GB33BUKB20201555555555", amount=4200, currency="EUR",
         method="bank_transfer", context_text="Please note our new bank details", bank_details_changed=True,
         vop_result="no_match"),
    dict(payee_name="Electric Ireland", payee_account="IE29AIBK93115212345678", amount=85, currency="EUR",
         method="card"),
]

HOOK_EVENTS = [
    {"hook_event_name": "pre_tool_call", "tool_name": "browser_navigate",
     "tool_input": {"url": "https://paypal.com@evil.example/login"}, "session_id": "s", "extra": {"tool_call_id": "1"}},
    {"hook_event_name": "pre_tool_call", "tool_name": "web_extract",
     "tool_input": {"urls": ["https://www.revolut.com/"]}, "session_id": "s", "extra": {"tool_call_id": "2"}},
    {"hook_event_name": "pre_tool_call", "tool_name": "terminal",
     "tool_input": {"command": "curl -s \"$PAY_URL\""}, "session_id": "s", "extra": {"tool_call_id": "3"}},
    {"hook_event_name": "pre_tool_call", "tool_name": "browser_navigate",
     "tool_input": {"url": "https://paypal.com.secure-login.xyz/verify"}, "session_id": "s",
     "extra": {"tool_call_id": "4"}},
    {"hook_event_name": "pre_tool_call", "tool_name": "terminal",
     "tool_input": {"command": "hermes hooks revoke scamgate-hook"}, "session_id": "s", "extra": {"tool_call_id": "5"}},
    {"hook_event_name": "PreToolUse", "tool_name": "WebFetch",
     "tool_input": {"url": "https://someone@shop.example/basket", "prompt": "check the price"},
     "session_id": "c", "tool_use_id": "t1"},
    {"hook_event_name": "pre_tool_call", "tool_name": "terminal",
     "tool_input": {"command": "git status"}, "session_id": "s", "extra": {"tool_call_id": "6"}},
    {"hook_event_name": "pre_tool_call", "tool_name": "write_file",
     "tool_input": {"path": "__STATE__/overrides.jsonl", "content": "..."}, "session_id": "s",
     "extra": {"tool_call_id": "7"}},
]


def _verdict(v) -> dict:
    return {"decision": v.decision.value, "score": v.risk_score, "summary": v.summary,
            "reasons": [{"rule": r.rule_id, "weight": r.weight, "text": r.explanation} for r in v.reasons]}


def build() -> dict:
    os.environ["SCAMGATE_CACHE_DIR"] = tempfile.mkdtemp(prefix="sg-site-cache-")
    state = tempfile.mkdtemp(prefix="sg-site-state-")
    os.environ["SCAMGATE_STATE_DIR"] = state
    from scamgate import engine, feeds, hook
    from scamgate.config import load_config
    from scamgate.models import PaymentCheck

    feeds.load_index.cache_clear()
    feeds._index_at.cache_clear()
    hook._FEEDS = None
    cfg = load_config()
    data: dict = {"thresholds": cfg["thresholds"], "urls": [], "payments": [], "hook": []}
    for url, intent in URLS:
        data["urls"].append({"input": url, "intent": intent, **_verdict(engine.check_url(url, intent))})
    for p in PAYMENTS:
        data["payments"].append({"input": p, **_verdict(engine.check_payment(PaymentCheck(**p),
                                                                              use_history=False))})
    for e in HOOK_EVENTS:
        e = json.loads(json.dumps(e).replace("__STATE__", state.replace("\\", "/")))
        text, _ = hook.run(e)
        shown = json.loads(json.dumps(e).replace(state.replace("\\", "/"), "~/.local/state/scamgate"))
        out = json.loads(text.replace(state.replace("\\", "/").lower(), "~/.local/state/scamgate"))
        data["hook"].append({"tool": e["tool_name"], "dialect": "claude" if e["hook_event_name"] == "PreToolUse"
                             else "hermes", "input": shown["tool_input"], "output": out})
    from scamgate.config import rule_cfg
    from scamgate.registry import rules_for

    data["rules"] = []
    for kind in ("url", "payment"):
        for r in rules_for(kind):
            rc = dict(rule_cfg(cfg, r.rule_id))
            enabled = bool(rc.pop("enabled", False))
            doc = " ".join((r.fn.__doc__ or "").split())
            data["rules"].append({"id": r.rule_id, "kind": kind, "enabled": enabled, "doc": doc, "config": rc})
    return data


def render(data: dict) -> str:
    body = json.dumps(data, indent=1, ensure_ascii=False)
    return ("// Generated by scripts/site_demo_data.py from real scamgate output. Do not edit by hand.\n"
            f"window.SCAMGATE_DEMO = {body};\n")


if __name__ == "__main__":
    OUT.write_text(render(build()), encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(ROOT)}", file=sys.stderr)
