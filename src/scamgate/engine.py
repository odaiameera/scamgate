"""Run registered rules and turn hits into a verdict."""

from __future__ import annotations

from typing import Any

from scamgate.config import load_blocklist, load_config, rule_cfg
from scamgate.models import Decision, PaymentCheck, Reason, UrlCheck, Verdict
from scamgate.registry import Hit, Kind, RuleContext, rules_for


def _run(kind: Kind, check: Any, config: dict[str, Any] | None,
         blocklist: frozenset[str] | None) -> Verdict:
    config = config or load_config()
    blocklist = load_blocklist() if blocklist is None else blocklist
    reasons: list[Reason] = []
    for rule in rules_for(kind):
        rc = rule_cfg(config, rule.rule_id)
        if not rc.get("enabled", False):
            continue
        out = rule.fn(check, RuleContext(config=config, rule_config=rc, blocklist=blocklist))
        hits: list[Hit] = [] if out is None else (out if isinstance(out, list) else [out])
        for h in hits:
            w = h.weight if h.weight is not None else int(rc.get("weight", 0))
            if w <= 0:
                continue
            reasons.append(Reason(rule_id=rule.rule_id, explanation=h.explanation, weight=min(w, 100)))

    reasons.sort(key=lambda r: r.weight, reverse=True)
    score = min(100, sum(r.weight for r in reasons))
    th = config.get("thresholds", {})
    if score >= int(th.get("deny", 70)):
        decision = Decision.deny
    elif score >= int(th.get("ask", 25)):
        decision = Decision.ask
    else:
        decision = Decision.allow
    return Verdict(decision=decision, risk_score=score, reasons=reasons,
                   summary=_summary(kind, decision, reasons))


def _summary(kind: Kind, decision: Decision, reasons: list[Reason]) -> str:
    thing = "link" if kind == "url" else "payment"
    if decision is Decision.allow and not reasons:
        return f"No scam signals found for this {thing}."
    top = reasons[0].explanation if reasons else ""
    if decision is Decision.allow:
        return f"Low risk {thing}, but note: {top}"
    if decision is Decision.ask:
        return f"Check with the human before this {thing}. Main concern: {top}"
    return f"Do not proceed with this {thing}. Main concern: {top}"


def check_url(url: str, intent: str | None = None, *, config: dict[str, Any] | None = None,
              blocklist: frozenset[str] | None = None) -> Verdict:
    return _run("url", UrlCheck(url=url, intent=intent), config, blocklist)


def check_payment(check: PaymentCheck, *, config: dict[str, Any] | None = None) -> Verdict:
    return _run("payment", check, config, frozenset())
