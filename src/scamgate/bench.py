"""Run YAML scenarios through the engine and score the results."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from scamgate import engine
from scamgate.models import Decision, PaymentCheck, Verdict


@dataclass
class Result:
    scenario_id: str
    name: str
    label: str  # scam | legit
    expected: Decision
    verdict: Verdict

    @property
    def flagged(self) -> bool:
        return self.verdict.decision is not Decision.allow

    @property
    def outcome(self) -> str:
        if self.label == "scam":
            return "caught" if self.flagged else "missed"
        # A legit case may still be *expected* to ask (e.g. over budget); that is not a false positive.
        if self.flagged and self.expected is Decision.allow:
            return "false_positive"
        return "ok"

    @property
    def exact(self) -> bool:
        return self.verdict.decision is self.expected


def load_scenarios(directory: Path) -> list[dict]:
    out = []
    for f in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(f.read_text("utf-8"))
        data.setdefault("id", f.stem)
        out.append(data)
    return out


def run_scenario(s: dict) -> Result:
    kind = s["kind"]
    inp = s["input"]
    if kind == "url":
        verdict = engine.check_url(inp["url"], inp.get("intent"))
    elif kind == "payment":
        verdict = engine.check_payment(PaymentCheck(**inp), use_history=False)  # scenario input is ground truth
    else:
        raise ValueError(f"{s['id']}: unknown kind {kind!r}")
    label = s["label"]
    if label not in ("scam", "legit"):
        raise ValueError(f"{s['id']}: label must be scam or legit")
    return Result(s["id"], s.get("name", s["id"]), label, Decision(s["expected"]), verdict)


def run_all(directory: Path) -> list[Result]:
    return [run_scenario(s) for s in load_scenarios(directory)]


def summarize(results: list[Result]) -> dict[str, int]:
    return {
        "total": len(results),
        "scams": sum(r.label == "scam" for r in results),
        "legit": sum(r.label == "legit" for r in results),
        "caught": sum(r.outcome == "caught" for r in results),
        "missed": sum(r.outcome == "missed" for r in results),
        "false_positives": sum(r.outcome == "false_positive" for r in results),
        "exact_decision_match": sum(r.exact for r in results),
    }
