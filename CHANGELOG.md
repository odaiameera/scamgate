# Changelog

## [0.3.0] - 2026-10-16

Hermes plugin, and the holes found while making it.

### Hermes plugin
- In-process plugin (`src/scamgate/plugin.yaml`): `pre_tool_call`, `post_tool_call`, `scamgate_check_url`, `scamgate_check_payment`, `/scamgate`.
- Same decisions as the shell hook, without a subprocess. Needs Hermes 0.19.1+.
- When `/yolo` or `approvals.mode: off` would auto-approve an ask, the plugin blocks instead. Set `plugins.entries.scamgate.settings.when_approvals_off: allow` to keep the old behaviour.

### Hook
- Blocks Hermes safety switches (`approvals.mode off`, `--yolo`, `plugins uninstall`, `--safe-mode`, `--dangerously-skip-permissions`, and the same idea in code or another tool).
- Blocks reading the signing key and payee salt.
- Reads a script before running it, including scripts a cron job would run later with no agent.
- Checks the body of files other tools run (Makefile, package.json, git hooks, CI, Hermes cron scripts). Notes are still just notes.
- scamgate's own check tools are not gated for naming the link they were asked about.
- Other Hermes profiles' config is protected.
- `https:/host` and `https:///host` are checked as `https://host`.
- `scp`, `sftp` and `rsync` to a blocklisted host are denied, including `user@host:/absolute/path`. Local copies stay quiet.
- `base32 -d`, `b64 -d`, a decoded file that is then run, and Perl or Ruby `eval` of decoded text ask before they run.

Install commands are pinned to `v0.3.0`.

## [0.2.0] - 2026-10-12

First tagged release. Everything since 0.1.0 (the MCP server and rules) is new here.

### Enforcement hook
- `scamgate-hook`: a Hermes `pre_tool_call` / Claude Code `PreToolUse` hook, so the agent can't skip
  the check. Never outputs "allow"; fails closed; asks are logged (redacted) with the outcome.
- Links in any tool call are checked, including disguised hosts (percent-encoding, integer/hex/octal
  IPs), per command segment, so one clean link can't hide a second fetch.
- Destinations it can't read (variables, `$(…)`, string-built, base64/hex-decoded links, named
  package installs, new git remotes) go to a human. Decoded-and-run code (`base64 -d | bash`,
  `exec(b64decode(…))`, `powershell -enc`) always does.
- **Payments are gated**: money-moving tool calls are scored with `check_payment` and local payee
  history; payments in shell/code (crypto CLIs, payment-API writes) go to a human.
- Routine dev commands stay quiet (lockfile installs, `git push/pull`, text-only commands).
- Tamper resistance: agent writes to scamgate, its state, feed cache, venv and the Claude/Hermes hook
  config are blocked however the path is spelled; integrity check against wheel RECORD hashes and
  unknown `.pth` files.

### Human-only state
- `review` / `promote` overrides and `record-payment` payee history: written only by a person at an
  interactive terminal (refused inside known agents), HMAC-signed, salted hashes for payees,
  near-name and account-reuse detection, salt-swap detection.

### Rules
- `url.credential_page`: a sign-in page on an unrecognised site asks; the agent's wording can't clear it.
- `url.domain_age`: RDAP domain age, **opt-in** (`SCAMGATE_RDAP=cache|live`), cached.
- Brand pack of ~50 commonly phished brands plus Irish/UK banks and couriers; brand-inside-a-word
  false positives fixed (applebees, revolution, pineapple); curated public-suffix list incl. shared hosts.
- New-payee bank transfers ask unless Verification of Payee matched; `pay.unbacked_known_claim`.
- 0.0.0.0 / loopback treated as local.

### Docs and site
- GitHub Pages site and docs; Claude Code config uses `"onFailure": "block"`; install commands pinned to `v0.2.0`.

## [0.1.0]

- MCP server with `check_url` and `check_payment`, YAML-configured rules, known-bad-link feeds, bench scenarios.
