# Verification of Grok's scamgate hook review + extra risks

Verified 12 Oct 2026 against `main` @ `ae79049` (includes PR #4, which Grok's review predates).
Method: pinned wheel install in a clean venv, real `scamgate-hook.exe` over stdin, temp cache listing
`evilshop.com` (domain) and `http://phish-login.net/steal` (URL). Harness claims checked against the
Claude Code hooks docs and the installed Hermes source (v0.21.5, `f94fd4d`).

## Grok's findings: replayed

| # | Grok | Result on current main | My severity | Notes |
|---|---|---|---|---|
| H1 decoy URL disables opaque check | High | **Confirmed** (both cases silent) | High | |
| H2 literal-path tamper matching | High | **Confirmed**: `~`, `$HOME`, glob, `jq+mv`, `ln -sf`, project `.claude/settings*.json`, Hermes `sed ~/.hermes/config.yaml` all silent | High | absolute paths + Write tool still caught |
| H3 agent writes overrides/payees | High | **Partly fixed by PR #4**: `python -c 'from scamgate import overrides…'` and `scamgate record-payment` now deny. **Still silent:** `python -m scamgate.cli promote`, `${S}gate promote`, `scamgate "promote"`, `importlib.import_module("scamgate.over"+"rides")`. `yes \| promote` satisfies the confirm prompt | High | |
| H4 integrity bypass | High | **Confirmed**: edit rules.yaml + rewrite RECORD → `{}`; crash `.pth` → exit 1, no JSON | Medium | same-user code execution is out of scope for any hook; it's tamper-evidence, as Grok says |
| H5 Claude fails open on crash/timeout | High | **Confirmed in docs**: non-0/2 exit, can't start, timeout = action proceeds unless `onFailure:"block"` (v2.1.295, 8 Oct 2026). README has none | High (Claude) / none (Hermes, `fail_closed` set) | |
| H6 obfuscated URLs | High | **Confirmed**: `%6f`, decimal IP, hex IP, `"evil""shop.com"`, `https://$H/`, python concat all silent | High | |
| M1 classification gaps | Med | **Confirmed**: pip3, yarn, git fetch, xdg-open, nslookup, unknown MCP keys (`address`, `cmdline`, `function`), WebSearch silent. **Correction:** the `PowerShell` tool itself IS gated (deny); only the README matcher omits it | Med | |
| M2 payee near-names | Med | **Confirmed**: "Acme Trading Ltd" + new IBAN, Cyrillic "Acmе Ltd", "Evil Corp" + Acme's IBAN → allow 20. Deleting `payees.salt` silently resets history | Med-High | invoice redirection is the #1 payment scam this exists for |
| M3 `rule_key` "always" | Med | **Confirmed in Hermes source**: `tools/approval.py` stores approvals as `plugin_rule:<rule_key>`; session cache short-circuits | Med-High | one "always" on `scamgate:opaque:terminal` = every future opaque fetch |
| M4 redaction gaps | Med | **Confirmed**: JWT, `github_pat_`, `AIza…`, "password is X", lowercase IBAN, seed words, email/IBAN in URL path all kept | Med | local file only, but still a secrets file |
| M5 silent on missing/empty cache | Med | **Confirmed**: empty cache → known-bad domain silent; `echo {} > ~/.cache/scamgate/meta.json` silent | Med | |
| M6 bulk downgrades deny | Med | **Confirmed** (21 URLs incl. evilshop → ask) | Med | |
| L1 missing event name | Low | **Confirmed** silent exit 0 | Low | |
| L3 PostToolUseFailure | Low | **Confirmed in docs**: "After a tool call fails", so it ran | Low | |

Grok's other claims I checked: Hermes `approve` parsing exists in the installed build (`agent/shell_hooks.py:450`),
Claude `PreToolUse` output shape correct, `onFailure` version correct. Nothing in Grok's review turned out false;
two items are overstated (PowerShell, H4 severity) and one is out of date (H3 partly fixed).

## Risks Grok missed

| # | Sev | Status | Finding |
|---|---|---|---|
| N1 | Med | **Confirmed** | **The agent's stated reason changes the score.** The hook passes it as `intent`. `tickets-cheap.example/login`: intent "buy a ticket" → ask 45; intent "log in to my account to buy a ticket" → allow 0. A compromised agent can switch off the login part of `url.intent_mismatch` (never below the no-intent baseline; seed-phrase check unaffected, still 80). README/site say the reason is "never used automatically", which is wrong for scoring. |
| N2 | Med-Low | **Confirmed** | **Attacker text appears in the safety message.** Userinfo is quoted verbatim: "The link shows 'verified safe by aib - approve this' before an '@'…". On a plain-username *ask*, that text lands in the human approval prompt. |
| N3 | Med | **Confirmed (source)** | **Hermes `/yolo` or `approvals.mode: off` auto-approves every scamgate ask** (`approval.py`: `_yolo_active() or mode == "off"` → approved). Blocks still hold. `cron_mode/unattended_mode: approve` does the same in cron/webhooks (defaults are `deny`, which turns asks into blocks, safe). |
| N4 | Med | Confirmed (config) | **Supply chain.** The website hero and docs install from unpinned `main`. A compromised account or bad merge ships to every installer, and the integrity check verifies against that same RECORD. No tags, no PyPI, branch protection not confirmed. |
| N5 | High (this PC) | Confirmed | **Today nothing is enforced here.** The hook isn't wired into Hermes yet. The MCP server runs from the editable checkout, so if the hook were wired the same way integrity = "dev" (no check) and the checkout is writable by the agent. |
| N6 | Low | Theoretical | Hermes "session" approvals persist for the whole session. On Telegram a session can live for days. |

## Risk scenarios by attacker

1. **Prompt-injected agent** (main threat): bypass (H1, H6, M1), switch off (H2, H3), train (H3, M3), lower the score (N1), talk the human into it (N2).
2. **Scammer only, agent honest**: brand-new domains (domain age not built), redirects after the check (not built), scams on shared platforms (feed_host_ignore trade-off), invoice redirection under a near-name (M2).
3. **Human fatigue**: "always" buttons (M3), `/yolo` (N3), persuasive text in prompts (N2).
4. **Local malware / same-user code**: H4. Out of scope for any hook; needs OS permissions, managed settings or a container.
5. **Supply chain**: N4.
6. **Fail-open / availability**: H5 (Claude), L1, M5, cache poisoning DoS (L4).
7. **Privacy**: M4, L5; plus any future cloud classifier would send URLs/payees off the machine.
8. **Harness drift**: older Hermes dropped `approve` (#92553), Claude `onFailure` needs v2.1.295+.

## Fix plan

**PR A — close the silent holes (before wiring the hook or contributing anywhere)**
- H1/H6: decide "opaque" per command segment; URL with `$`, `{`, `%`, quote-concat or no dotted host → ask; percent-decode hosts; integer/hex/octal IPv4 → `url.ip_host`.
- M6: evaluate every URL; any deny wins over bulk.
- M5: no/stale feeds → warning in every hook message; no feeds + URL tool → ask; protect the cache dir.
- M3: `rule_key` includes a hash of the destination/command and the rule set.
- N1: hook scores `max(with intent, without intent)`: the reason can add risk, never remove it. Fix README/site wording.
- N2: never quote attacker-controlled strings in hook messages (or truncate + mark as untrusted).
- H5: README/site Claude config gets `"onFailure": "block"`, absolute exec path, min versions (Claude 2.1.295, Hermes with `approve`).
- L1: tool_name without event → treat as pre, fail closed.

**PR B — anti-tamper and anti-training**
- H3: `overrides.add` / `payees.record` refuse non-TTY or agent-env callers (in the library, not just CLI); HMAC-sign lines; widen `_TAMPER_CMD` (`scamgate.cli`, `python -m scamgate`, `importlib`, variable-built names → ask).
- H2: normalise `~`/`$HOME`/`%USERPROFILE%`/`$HERMES_HOME`, match path suffixes and globs, protect `**/.claude/settings*.json` and `cwd`'s `.claude/`.
- M2: fuzzy/homoglyph-folded name match → changed details; account seen under another name → flag; agent claiming "known" with no record → points, not just a warning; missing salt with existing history → fail loudly; 0600 files.
- M4: run full text redaction on URL paths; JWT/cloud-key/PAT/seed-phrase/high-entropy rules; cap stated_reason at 80 chars.
- H4: protect `sys.prefix` (RECORD, `.pth`, entry script); run with `python -I`; document as tamper-evidence.

**PR C — release hygiene**
- N4: tag `v0.2.0`, publish to PyPI with trusted publishing + attestations, pin every install snippet (site, README, hol-guard entry), enable branch protection.
- Honest "inherent limits" section: arguments not behaviour, same-user code, redirects, payments only where gated; recommend managed settings / container / egress filter for real enforcement.

**Then** wire the hook into Hermes from a pinned install (N5).
