"""A tiny rule registry.

Add a rule by decorating a function:

    @register("pay.my_rule", kind="payment")
    def my_rule(check: PaymentCheck, ctx: RuleContext) -> Hit | None:
        ...

Then give it an entry under `rules:` in config/rules.yaml (enabled + weight).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal

Kind = Literal["url", "payment"]


@dataclass
class Hit:
    explanation: str
    weight: int | None = None  # None -> use the rule's configured weight


@dataclass
class RuleContext:
    config: dict[str, Any]
    rule_config: dict[str, Any]
    blocklist: frozenset[str] = field(default_factory=frozenset)


RuleFn = Callable[[Any, RuleContext], "Hit | list[Hit] | None"]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    kind: Kind
    fn: RuleFn
    description: str


_REGISTRY: dict[str, Rule] = {}


def register(rule_id: str, kind: Kind) -> Callable[[RuleFn], RuleFn]:
    def deco(fn: RuleFn) -> RuleFn:
        if rule_id in _REGISTRY:
            raise ValueError(f"duplicate rule id: {rule_id}")
        _REGISTRY[rule_id] = Rule(rule_id, kind, fn, (fn.__doc__ or "").strip())
        return fn

    return deco


def rules_for(kind: Kind) -> list[Rule]:
    # Importing the rule modules populates the registry.
    from scamgate.rules import payment, url  # noqa: F401

    return [r for r in _REGISTRY.values() if r.kind == kind]


def all_rules() -> list[Rule]:
    return rules_for("url") + rules_for("payment")
