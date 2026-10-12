"""Load rules config (weights, thresholds, word lists) and the local blocklist."""

from __future__ import annotations

import os
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

ENV_CONFIG = "SCAMGATE_CONFIG"
ENV_BLOCKLIST = "SCAMGATE_BLOCKLIST"


def _default_config_text() -> str:
    return resources.files("scamgate").joinpath("config/rules.yaml").read_text("utf-8")


@lru_cache(maxsize=8)
def load_config(path: str | None = None) -> dict[str, Any]:
    path = path or os.environ.get(ENV_CONFIG)
    text = Path(path).read_text("utf-8") if path else _default_config_text()
    return yaml.safe_load(text)


def _blocklist_candidates() -> list[Path]:
    out: list[Path] = []
    if env := os.environ.get(ENV_BLOCKLIST):
        out.append(Path(env))
    # Source checkout / editable install: <repo>/data/blocklist.txt
    out.append(Path(__file__).resolve().parents[2] / "data" / "blocklist.txt")
    # Installed wheel: bundled copy
    out.append(Path(str(resources.files("scamgate").joinpath("_data/blocklist.txt"))))
    return out


def _parse_domains(text: str) -> set[str]:
    domains = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip().lower().rstrip(".")
        if line:
            domains.add(line)
    return domains


@lru_cache(maxsize=8)
def load_blocklist(path: str | None = None) -> frozenset[str]:
    domains: set[str] = set()
    candidates = [Path(path)] if path else _blocklist_candidates()
    for p in candidates:
        if p.is_file():
            domains |= _parse_domains(p.read_text("utf-8"))
            break
    return frozenset(domains)


def rule_cfg(config: dict[str, Any], rule_id: str) -> dict[str, Any]:
    return config.get("rules", {}).get(rule_id, {}) or {}


def lst(config: dict[str, Any], name: str) -> Any:
    return config.get("lists", {}).get(name, [])
