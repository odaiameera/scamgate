# Contributing to scamgate

Anyone can contribute: rules, scenarios, false-positive reports, docs, fixes. scamgate sits in
front of an agent's links and payments, so the rules below are stricter than usual. Each one
comes from how the project works.

## Before you start

- **Small fix** (typo, docs, an obvious bug with a test): just open a PR.
- **Anything bigger** (a new rule, a weight or threshold change in `rules.yaml`, new hook
  behaviour, a new feed or dependency): open an issue first.
- **Rule or scoring changes** need an issue that describes the scam pattern: how it works,
  where it shows up, and a made-up example. "This looks suspicious" is not enough.
- **Security bugs and hook bypasses** (a command that slips past `hook.py`, a tamper path, a way
  to lower a score): don't open a public issue. See [SECURITY.md](SECURITY.md).

## Hard rules

These come from [`AGENTS.md`](AGENTS.md). A PR that breaks one won't be merged.

1. **Deterministic and offline.** No LLM judging and no network calls in the check path. The same
   input always gets the same verdict. Only a feed refresh downloads, and only the default feeds
   from fixed URLs.
2. **Free sources by default.** No paid feed or API key may be required for the default setup.
   Keyed feeds (like URLhaus) stay opt-in. Never commit third-party blocklist data: feeds live in
   the cache dir.
3. **The hook fails closed and never says "allow".** It may only block or ask, and silence means
   no objection. Don't add a path that lets a call through on an error, a timeout or unreadable
   input.
4. **Agent text can only add risk.** Stated intent, `is_new_payee` and reasons must never lower a
   score.
5. **Human-only state stays human-only.** Overrides and payees are written only through
   `guard.require_human` and are signed. No new code path may write them any other way.
6. **Linear on input.** The hook accepts up to 2 MiB, so a padded command must not tie it up
   ([#20](https://github.com/odaiameera/scamgate/issues/20)). No regex that backtracks over the
   whole input, and no per-character Python loop nested inside another. If you touch `hook.py` or
   `harden.py`, run `tests/test_hook_perf.py` and `tests/test_hook_perf_full.py`.
7. **Dependency-light.** A new runtime dependency needs a reason in the PR. The Hermes plugin path
   must work with only `plugin.yaml`'s `python_dependencies` (pydantic, pyyaml): no typer, rich or
   mcp imports there. `scripts/plugin_smoke.py` checks this in CI.

## Tests and scenarios

- **Every behaviour change needs a test.** Every bypass gets a failing test before the fix
  (`tests/test_hook_holes.py`, `test_tamper_training.py`, `test_recheck_gaps.py`).
- **New rules** need a `rules.yaml` entry and a plain-English explanation a non-technical person
  can act on. They also need tests, plus at least one scam and one legit scenario in
  `scenarios/` (copy an existing `*.yaml`: `kind`, `label`, `expected`, `input`).
- **New hook detection** needs a quiet-path test showing everyday dev commands still pass
  (`git push`, `pip install -r`, `uv sync`, `npm ci`, `grep`).
- **The bench stays at full exact match.** If your change moves a scenario's decision on purpose,
  update its `expected` value and explain why in the PR.
- **No real data in tests.** Use `.example` / `.test` domains or defanged links
  (`hxxps://bad-shop[.]test`), made-up names, and test IBANs. No live malicious URLs, real people,
  or real account numbers.
- **Rule or weight change?** Regenerate the site verdicts (`uv run python
  scripts/site_demo_data.py`). `tests/test_site_demo.py` fails if they're stale.

## Before you push

```bash
uv sync --locked
uv run --locked pytest -q                  # all tests, offline
uv run --locked scamgate bench --strict    # every scenario must match its expected decision
```

CI runs these on Python 3.11, 3.12 and 3.13, plus a bare-venv Hermes plugin install. If this is
your first PR here, a maintainer has to approve the CI run first, so expect a short wait.

## The PR itself

- **One concern per PR.** A perf fix and a rule change are two PRs. Small PRs get reviewed faster.
- **Add a line to `CHANGELOG.md` under `## [Unreleased]`.**
- **Say what you ran.** Paste the pytest and bench results.
- **AI-assisted PRs are welcome.** Say so in the PR, and confirm you've read the whole diff and
  run the checks yourself. Unread generated code on a security path will be closed.
- **No invented statistics** in docs or PR text. Bench numbers come from the example scenarios
  only, and scamgate stays advisory: it flags risk, it doesn't certify safety.

## License and conduct

scamgate is [MIT](LICENSE). By contributing, you agree your contribution is released under the
MIT license.

Be decent: assume good faith, critique the code and not the person, and no harassment.
