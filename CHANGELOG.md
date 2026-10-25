# Changelog

## [Unreleased]

Feed refreshes that work on a plain Hermes plugin install, and fewer false blocks from the tamper guard.
Reported from a real install, where `/scamgate update` told people to run a `scamgate update-feeds`
command a plugin install doesn't have.

### Hermes plugin
- `/scamgate update` now downloads the phishing lists instead of pointing at a missing command, and
  `/scamgate status` lists each feed with its age.
- New `hermes scamgate update-feeds` and `hermes scamgate feeds-status`. They use Hermes' own command line, so
  they need no extra packages (no typer, no `scamgate` on `PATH`).
- New agent tool `scamgate_update_feeds`. It takes no arguments: it always downloads the default feeds from
  their fixed sources into the configured cache, and does nothing if they were refreshed in the last hour.
  An agent can ask for a refresh, but can't choose what lands in the cache.
- Background refresh: about two minutes after Hermes starts, then every 6 hours. A lock file keeps
  Hermes processes from downloading at the same time. Off with `auto_update_feeds: false` or
  `SCAMGATE_AUTO_UPDATE=0`. No cron line needed.
- Stale-list warnings now name the plugin commands as well as `scamgate update-feeds`.

### Tamper guard
- A path in a command only counts when it names the protected folder itself: a log file next to the feed
  cache folder (`scamgate-feeds.log`) is no longer treated as inside it. `./`, `//` and `..` spellings of a
  protected path are now caught too.
- Read-only commands on protected paths pass: `ls`, `cat`, `head`, `tail`, `grep`, `rg`, `find`, `stat`,
  `which`, `wc`, `du`, `sha256sum` (and a few more), with `2>/dev/null` or `2>&1` allowed. A redirect,
  `$(...)`, backticks, `-exec`, `-delete`, `-fprint`, `--pre` or any other command in the line makes it a
  write check again, as before.
- Commands that call the feed downloader with their own arguments (`update_feeds(fetch=...)`,
  `_atomic_write`, swapping the downloader) are blocked: use the update tool or `/scamgate update`.

### Tests and CI
- New `tests/test_guard_boundaries.py` (quiet reads, the log file next to the cache, writes that must still
  block, cache poisoning), `tests/test_plugin_feed_updates.py` and `tests/test_update_feeds_cli.py`.
- CI runs `update-feeds` and `feeds-status` on sample feed data, and a new `plugin-install` job runs
  `scripts/plugin_smoke.py` in a venv that has only the plugin's dependencies.

## [0.3.1] - 2026-10-22

Security fixes from two review rounds (PRs #17 and #18). Install commands are pinned to `v0.3.1`.

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
  `https:/…`, `https:\\…` and tabs or newlines inside the scheme reach the same host as `https://…`, so
  they're judged the same. A domain or brand before the `@` counts as a disguise on any scheme
  (`sftp://`, `git+https://`, `hxxps://`); a plain username is flagged only on web links, so
  `ssh://git@github.com/…` no longer asks.

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

### Local state
- The state dir is created private (0700), and an existing `…/scamgate` state dir from an older install is
  tightened to 0700. A custom `SCAMGATE_STATE_DIR` is left as you set it. The ask log (`asks.jsonl`,
  `outcomes.jsonl`) is written 0600: it shows which sites your agent tried to visit.
- The signing key and payee salt are created once, even when two scamgate processes start together. One
  used to overwrite the other's key, and records already signed with it stopped verifying.
- If override rules can't be verified (the signing key is missing or was changed, or a line was edited),
  checks now warn instead of dropping your deny rules silently.

### Input checks
- Payment `amount` and `budget` must be real numbers: `inf`, `nan` and a negative budget are rejected.
- In the hook, a payment tool call whose amount is JSON `Infinity` or `NaN`, or a digit string too long
  to be a number, asks ("can't read how much") instead of failing with an internal error.
- The Hermes plugin fails closed: if the gate itself errors on a pre-tool call, the call is blocked, as
  the shell hook already did.
- Domain-age lookups (`SCAMGATE_RDAP=live`) send only a plain host name to the registry, and look up
  international names in their `xn--` form (they used to fail). A name Python's older IDNA rules would
  change (`faß` to `fass`) isn't looked up at all, rather than looked up wrong.
- `update-feeds` refuses a feed download over 256 MB and keeps the old cache.

### MCP server and Hermes plugin
- Both MCP tools are marked read-only (`readOnlyHint`, not destructive, idempotent). `check_url` reports
  `openWorldHint` only when domain-age lookups go online (`SCAMGATE_RDAP=live`).
- Both tools return a typed `Verdict` with a published output schema, so clients get structured content.
- New `checked_host` in every link verdict: the host a browser would open. Empty for payments and for
  links scamgate can't read.
- Input limits on the MCP tools (a 64 KiB link, 2,000-character intent, 20,000-character context). A link
  over 8 KiB but under the limit still gets a verdict (`url.unreadable` asks) rather than an error.
- The Hermes plugin's tools now take the same arguments as the MCP tools, from one shared definition
  (`scamgate.tools`). `scamgate_check_payment` used to drop `budget`, `is_new_payee`,
  `bank_details_changed` and `vop_result`, so the over-budget check never ran there. Bad arguments come
  back as an error instead of crashing the tool.
- Hermes `/scamgate review` lists each host with how many times it asked, what you did, and the top rule.
  It used to print a line of `?` per host.

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
