# AGENTS.md

Guidance for coding agents working on scamgate.

## Commands

```bash
uv sync                          # install deps (incl. dev group)
uv run pytest                    # all tests must pass
uv run scamgate bench --strict   # scenarios must match expected decisions
uv run scamgate bench -v         # show reasons per scenario
uv run scamgate check-url URL --intent "..."
uv run scamgate serve            # MCP server over stdio
```

## Layout

- `src/scamgate/models.py`: input models and the `Verdict` (decision, risk_score, reasons)
- `src/scamgate/registry.py`: `@register(rule_id, kind)` rule registry
- `src/scamgate/rules/url.py`, `rules/payment.py`: rules
- `src/scamgate/config/rules.yaml`: weights, thresholds, word lists
- `src/scamgate/engine.py`: runs rules, scores, decides
- `src/scamgate/server.py`: MCP server (official `mcp` SDK v2, `MCPServer`, stdio)
- `src/scamgate/cli.py`: Typer CLI (`serve`, `bench`, `check-url`)
- `scenarios/*.yaml`: example scenarios (kind, label, expected, input)
- `data/blocklist.txt`: local blocklist (example domains only)

## Rules of the road

- v1 is deterministic and offline: no network calls or LLMs in the default path.
- Every rule needs a `rules.yaml` entry, tests, and a plain-English explanation a non-technical
  person can act on.
- Never bundle third-party blocklist data; feeds go in git-ignored `data/feeds/`.
- No invented statistics in docs. Bench numbers come from example scenarios only.
- Keep the advisory framing: scamgate flags risk; it doesn't certify safety.
