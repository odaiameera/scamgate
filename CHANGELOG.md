# Changelog

## [Unreleased]

### Link checks
- New rule `url.unreadable` (40, asks): a link scamgate can't read never gets `allow`. That covers links
  that don't parse, site names with characters a browser refuses (spaces, slashes), site names longer than
  DNS allows, addresses over 8 KiB, and `javascript:`, `data:`, `vbscript:`, `file:` and `blob:` links.
  No other rule runs on such a link, so its text never appears in a reason.
- `\` before the query is read as `/`, as browsers do: `https://a.example\.paypal.com/` is checked as
  `a.example`, not as a PayPal address.
- Ideographic and halfwidth full stops (`。`, `｡`) in a site name count as dots.
- Site names over 253 characters are rejected before the brand checks run (a 24 KB one took 37 s).
- Hook: `http://[::1]:3000/` is read as one link (the address used to be cut at `]`).
- `amazonaws.com` is no longer an official Amazon domain. Its subdomains are customers' buckets and
  servers (583 Public Suffix List entries), so a sign-in page there is judged like any other site, and a
  feed listing of one bucket's host counts.
- A feed listing of a shared suffix such as `s3.amazonaws.com` no longer condemns every site under it:
  a parent-domain listing counts only at or below the site's own registrable domain.
- Three-label shared suffixes in the curated list (`s3.amazonaws.com`) now take effect. Only the last two
  labels used to be compared, so each bucket was treated as part of `amazonaws.com`.
- New `lists.shared_hosting` in `rules.yaml` (`amazonaws.com`, `googleusercontent.com`, `cloudapp.azure.com`):
  a host under one of these is a customer's or user's own site, so it's never an official brand site, and a
  feed listing counts only for that exact host. `googleusercontent.com` is no longer an official Google
  domain (Google uses it to sandbox untrusted user content, such as Apps Script web apps). `azure.com` stays
  official for Microsoft's own portal; only the VM names customers pick under `cloudapp.azure.com` are carved out.
- Faster link checks, same verdicts: the brand-padding search is linear (a 12,000-character word went from
  7.5 s to 0.03 s), the typo check skips words whose length rules out a one-letter edit, each link is
  parsed once per check, and each word's look-alike variants are worked out once instead of once per brand.
  At the 253-character cap the slowest link went from 23 ms to 1.4 ms. Verdicts on 16,050 generated
  brand-shaped links are unchanged.
- The fake-address check (`paypal.com@evil.example`) now fires however the scheme is written:
  `https:/…` and `https:\\…` reach the same host as `https://…`, so they're judged the same.

### Hook
- Shell commands are read the way the shell passes them: quotes and escapes are removed first, and each
  word that is a link is checked whole. A quoted `@` or `)` can no longer cut a link short and hide its
  real host.
- `curl "https://evil""shop.com/"` is now checked as `https://evilshop.com/` (it used to ask as a link
  built at run time). Variables and `$(…)` still ask.
- A network command the shell can't split (an unbalanced quote) asks.
- Bash `/dev/tcp/HOST/PORT` and `/dev/udp/HOST/PORT` are checked like any other destination.
- Only scamgate's own check tools skip the gate (`mcp__scamgate__check_url`, `mcp_scamgate_check_url`,
  `scamgate_check_url` and the `check_payment` forms). A tool whose name merely contains them, like
  `mcp__notscamgate__check_url`, used to skip every check, tamper checks included. If you registered the
  MCP server under another name, asking it about a bad link may now ask you first.

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
