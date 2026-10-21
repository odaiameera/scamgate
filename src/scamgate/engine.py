"""Run registered rules and turn hits into a verdict."""

from __future__ import annotations

from typing import Any

from . import feeds as feeds_mod
from . import overrides as overrides_mod
from . import payees as payees_mod
from .config import load_blocklist, load_config, rule_cfg
from .models import Decision, PaymentCheck, Reason, UrlCheck, Verdict
from .registry import Hit, Kind, RuleContext, rules_for


def _apply_overrides(url: str, reasons: list[Reason], items: list[dict], warnings: list[str]) -> list[Reason]:
    from .rules.url import parse

    host = parse(url).host
    if not host:
        return reasons
    if o := overrides_mod.deny_match(host, items):
        reasons.append(Reason(rule_id="url.override", weight=100,
                              explanation=f"You added a deny rule for {o['host']} on {o['added_at'][:10]}."))
    waived = overrides_mod.waived_rules(host, items)
    kept = [r for r in reasons if r.rule_id not in waived]
    if len(kept) != len(reasons):
        names = sorted({r.rule_id for r in reasons} & waived)
        warnings.append(f"Your allow rule for {host} waived: {', '.join(names)}.")
    return kept


def _run(kind: Kind, check: Any, config: dict[str, Any] | None,
         blocklist: frozenset[str] | None, feeds: Any = None,
         extra_warnings: list[str] | None = None) -> Verdict:
    config = config or load_config()
    blocklist = load_blocklist() if blocklist is None else blocklist
    warnings: list[str] = []
    if kind == "url":
        feeds = feeds_mod.current_index() if feeds is None else feeds
        if not feeds:
            warnings.append("No known-bad-link feeds cached; run `scamgate update-feeds`.")
        elif stale := feeds.stale_feeds():
            warnings.append(f"Feed cache older than {feeds_mod.STALE_AFTER_HOURS}h for: "
                            f"{', '.join(sorted(stale))}. Run `scamgate update-feeds`.")
    unreadable, checked_host = False, None
    if kind == "url":
        from .rules.url import parse

        parsed = parse(check.url)
        # Nothing else can judge a link scamgate can't read, and its text must not reach a reason.
        unreadable = bool(parsed.unreadable)
        checked_host = parsed.host or None
    reasons: list[Reason] = []
    for rule in rules_for(kind):
        if unreadable and rule.rule_id != "url.unreadable":
            continue
        rc = rule_cfg(config, rule.rule_id)
        if not rc.get("enabled", False):
            continue
        out = rule.fn(check, RuleContext(config=config, rule_config=rc, blocklist=blocklist, feeds=feeds))
        hits: list[Hit] = [] if out is None else (out if isinstance(out, list) else [out])
        for h in hits:
            w = h.weight if h.weight is not None else int(rc.get("weight", 0))
            if w <= 0:
                continue
            reasons.append(Reason(rule_id=rule.rule_id, explanation=h.explanation, weight=min(w, 100)))

    if kind == "url":
        items, bad = overrides_mod.load_checked()
        if bad:
            warnings.append(f"{bad} of your scamgate override rules can't be verified (its signing key is missing or "
                            "was changed, or the line was edited by hand), so they're ignored. Check the scamgate "
                            "state dir.")
        if items and not unreadable:
            reasons = _apply_overrides(check.url, reasons, items, warnings)
    warnings += extra_warnings or []

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
                   summary=_summary(kind, decision, reasons), checked_host=checked_host, warnings=warnings)


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
              blocklist: frozenset[str] | None = None, feeds: Any = None) -> Verdict:
    """feeds: a FeedIndex; defaults to the local cache (pass FeedIndex() for none)."""
    return _run("url", UrlCheck(url=url, intent=intent), config, blocklist, feeds)


def check_payment(check: PaymentCheck, *, config: dict[str, Any] | None = None,
                  use_history: bool = True) -> Verdict:
    """Payee facts come from local history (`scamgate record-payment`), not the agent's claims."""
    warnings: list[str] = []
    if use_history:
        check, warnings = _with_history(check)
    return _run("payment", check, config, frozenset(), extra_warnings=warnings)


def _with_history(check: PaymentCheck) -> tuple[PaymentCheck, list[str]]:
    facts = payees_mod.lookup(check.payee_name, check.payee_account)
    warnings: list[str] = []
    claimed_known = False
    if facts.history_broken:
        new, changed = True, True
        warnings.append("Your payee history can't be verified (its key or salt is missing or was changed), so "
                        "every payee is treated as new with changed details. Check the scamgate state dir.")
    elif facts.known_account:
        new, changed = False, bool(check.bank_details_changed)
    elif facts.name_seen_with_other_account:
        new, changed = False, True
        warnings.append(f"You've paid '{check.payee_name}' before, but never to this account.")
    elif facts.near_name:
        new, changed = True, True
        warnings.append(f"'{check.payee_name}' looks like a payee you've paid before, but this name and account "
                        "are new. Lookalike payee names are a common invoice-redirection trick.")
    else:
        new, changed = True, bool(check.bank_details_changed)
        if check.is_new_payee is False:
            claimed_known = True
            warnings.append(f"The agent said '{check.payee_name}' is a known payee, but you've never paid them "
                            "from here (no record). Treating them as new.")
    if facts.account_under_other_name:
        changed = True
        warnings.append("You've paid this account before under a different name. Confirm who really owns it.")
    upd = {"is_new_payee": new, "bank_details_changed": changed, "agent_claim_unbacked": claimed_known}
    return check.model_copy(update=upd), warnings
