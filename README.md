# scamgate

[![M8ven Score](https://m8ven.ai/badge/mcp/odaiameera/scamgate)](https://m8ven.ai/mcp/odaiameera/scamgate?s=readme)

A self-hosted scam check for AI agents: verify links and payments before the agent acts.

**Website and docs:** https://odaiameera.github.io/scamgate/

AI agents now click links and make payments for people, and scammers follow the money. Text
planted in pages, listings or messages can steer an agent to a fake shop, a credential prompt or
a "pay by bank transfer" request. Agent payment rails secure *the payment* (tokens, limits,
authentication). They don't judge whether the payee or the site is a scam. scamgate does that
check, runs locally as an MCP server, and makes no network calls while checking.

## How it decides

- Deterministic rules, no LLM judging. The same input always gets the same verdict.
- Each rule that fires adds points and a plain-English reason. The total (capped at 100) decides:
  - **allow**: under 25
  - **ask** (stop and check with the human): 25 to 69
  - **deny**: 70 or more
- The agent gets the decision, the score, every reason, and any warnings (for example a stale feed cache).

**Link rules:** known-bad-link feeds, your own blocklist, brand look-alikes (typosquats,
homoglyphs, brand names on unofficial domains, real domains used as a prefix like
`paypal.com.secure-login.xyz`), addresses hidden before an `@` (`paypal.com@evil.example`), raw
IP hosts, punycode, cheap abused TLDs, and pages asking for a seed phrase or a login the task
doesn't need. A link it can't read (an invalid site name, a `javascript:` or `data:` link, an
oversized address) asks: it never gets an `allow`.

**Payment rules:** new payee plus urgency, changed bank details, irreversible methods (crypto,
gift cards, transfer to a new payee), sellers insisting on a method, over budget, pressure or
secrecy phrases, and Verification of Payee results.

## Quickstart

Requires Python 3.11+.

```bash
# with uv
git clone https://github.com/odaiameera/scamgate.git
cd scamgate
uv sync
uv run scamgate update-feeds      # download the known-bad-link feeds into ~/.cache/scamgate

# or with pip, pinned to a release
pip install "git+https://github.com/odaiameera/scamgate.git@v0.3.1"
scamgate update-feeds
```

Check a link (real output):

```console
$ uv run scamgate check-url "https://paypa1.com/login" --intent "buy a ticket"
{
  "decision": "deny",
  "risk_score": 100,
  "reasons": [
    {
      "rule_id": "url.lookalike_brand",
      "explanation": "'paypa1.com' disguises 'paypal' with look-alike characters ('paypa1'). The real site is paypal.com.",
      "weight": 60
    },
    {
      "rule_id": "url.intent_mismatch",
      "explanation": "The task is 'buy a ticket', but the link goes to a 'login' page. A credential prompt the task doesn't need is a classic phishing step.",
      "weight": 45
    }
  ],
  "summary": "Do not proceed with this link. Main concern: 'paypa1.com' disguises 'paypal' with look-alike characters ('paypa1'). The real site is paypal.com.",
  "checked_host": "paypa1.com",
  "warnings": [],
  "advisory": "scamgate is advisory. It can miss scams and flag legitimate actions; a human should make the final call on anything flagged."
}
```

(`warnings` is empty once feeds are cached. Before `update-feeds` it says no feed is cached.)

A link listed in a feed comes back with the feed named in the reason:

```json
{
  "rule_id": "url.known_bad_feed",
  "explanation": "This exact link is listed as phishing/malware by OpenPhish community feed.",
  "weight": 100
}
```

Other commands: `scamgate feeds-status`, `scamgate bench`, `scamgate serve` (MCP over stdio),
plus `hook`, `review`, `promote` and `record-payment` (see [Enforce it with a hook](#enforce-it-with-a-hook)).

## Add it to your agent

Replace `/path/to/scamgate` with your checkout.

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "scamgate": {
      "command": "uv",
      "args": ["--directory", "/path/to/scamgate", "run", "scamgate", "serve"]
    }
  }
}
```

**Claude Code:**

```bash
claude mcp add scamgate -- uv --directory /path/to/scamgate run scamgate serve
```

**Hermes** (`~/.hermes/config.yaml`):

```yaml
mcp_servers:
  scamgate:
    command: "uv"
    args: ["--directory", "/path/to/scamgate", "run", "scamgate", "serve"]
```

Then tell the agent: *"Call `check_url` before opening any link and `check_payment` before any
payment. On `ask`, stop and show me the reasons. On `deny`, don't proceed."*

### MCP tools

```text
check_url(url: str, intent: str | None = None) -> Verdict

check_payment(payee_name: str, payee_account: str, amount: float, currency: str,
              method: "card" | "bank_transfer" | "crypto" | "gift_card" | "other",
              context_text: str | None = None, is_new_payee: bool | None = None,
              bank_details_changed: bool | None = None, budget: float | None = None,
              vop_result: "match" | "close_match" | "no_match" | "unavailable" | None = None) -> Verdict
```

`Verdict` = `decision`, `risk_score`, `reasons[]` (`rule_id`, `explanation`, `weight`),
`summary`, `checked_host` (for links: the host a browser would open), `warnings[]`, `advisory`.
Both tools are marked read-only and publish this as their output schema, so MCP clients get it as
structured content.

## Enforce it with a hook

The MCP tools only work when the agent chooses to call them, and a prompt injection can tell
it not to. The hook moves the check into the harness: the agent can't skip it.

`scamgate-hook` (or `scamgate hook`) reads one hook event as JSON on stdin and writes a decision.
It speaks Hermes shell hooks and Claude Code `PreToolUse` hooks.

- **Links:** every URL in a web, browser, media, terminal, code or unknown MCP tool call is
  checked, including disguised forms (`evilsh%6fp.com`, `http://3405803781`). `deny` blocks the
  call, `ask` sends it to you for approval. One bad link in a batch blocks the whole batch.
- **Payments:** money-moving tool calls (wallet, banking or payments MCP tools, or any tool whose
  arguments carry an amount and an IBAN, wallet or account) get the same check as
  `check_payment`, with your payee history, whatever the agent claims. `deny` blocks, `ask` sends
  it to you. A payment whose payee or amount can't be read, crypto CLIs (`cast send`,
  `bitcoin-cli sendtoaddress`, `solana transfer`…) and write calls to payment APIs (Stripe,
  PayPal, Wise, Revolut Business…) go to you. Each approval covers one account and amount.
- **Hidden code:** code that's decoded or downloaded and then run (`… | base64 -d | bash`,
  `exec(b64decode(…))`, `curl … | sh`, `powershell -enc`) goes to you, network keyword or not.
- **Hidden destinations:** a network step scamgate can't read goes to you, judged per command
  (`curl https://example.org; curl "$URL"` still asks): variables, `$(…)`, string-built,
  base64/hex-decoded or reversed links, `requests.get(open(…).read())`, installs of named
  packages, `git clone`, new git remotes. In code, only a literal URL counts as readable.
- **Routine dev work stays quiet:** installs from a lockfile, manifest or local path
  (`pip install -r requirements.txt`, `uv sync`, `npm ci`), `git push/pull/fetch` to remotes you
  already have, and commands that only read text (`grep requests.get src/`). Any URL in them is
  still checked.
- **Running blind:** with no feeds cached, links go to you for approval (`SCAMGATE_NO_FEEDS=warn`
  turns that into a warning). Stale feeds are mentioned in every ask and block.
- **Tampering:** blocks agent writes (including editors like vim/ed/nano and `find -exec`,
  `rsync`, `patch`) to scamgate's own code, state and feed cache and to the hook config, plus commands or code that revoke the hook, remove the server, promote rules, record
  payees or call scamgate's state APIs directly.
- **The agent's stated reason can only add risk.** It's scored with and without the reason, and
  the higher score wins.
- **Approvals stay narrow.** Hermes remembers "always" per `rule_key`; scamgate's keys include the
  host and the rules that fired (or a hash of the hidden command), so one "always" can't
  pre-approve other destinations. Still, pick "once" for asks you don't expect to repeat.
- **Fails closed:** bad input, input over 2 MB, deep nesting or an internal error blocks the call
  (exit 2).
- **Never says "allow".** Silence means "no objection", so it can only tighten your agent's
  permissions, never loosen them.

### Pipeline

`hook.handle()` is the only enforcement function. The shell hook and the Hermes plugin both call it. MCP does not.

1. Integrity check on a wheel install. A mismatch blocks every gated call. Editable and unpackaged installs pass as `dev`.
2. scamgate's own `check_url` / `check_payment` tools return silence, so asking the gate is not itself blocked.
3. Tamper: writes to the package, state, feed cache, hook config, and other Hermes profiles, plus commands that uninstall the gate or call `promote` / `record-payment`.
4. Extra checks: reading the signing key; Hermes safety switches (`approvals.mode off`, `--yolo`, `plugins uninstall`, `--safe-mode`, `--dangerously-skip-permissions`); writes to files other tools run; cron scripts under `$HERMES_HOME/scripts`; script files named by `bash` / `python` / `node` / `pwsh` / `uv run`, followed a few levels deep.
5. URL extraction. `https:/host` and `https:///host` are rewritten to `https://host`. Hosts are NFKC-normalised, percent-decoded, and numeric IPv4 is expanded. Segments split on newlines, `;`, `&&`, `||` and `|`.
6. Score each URL with and without the agent's reason. Take the higher score, then the worst decision. An unreadable destination asks. More than 20 clean URLs asks.
7. A payment result wins a tie with a generic network ask. A URL deny still beats a payment ask.
8. Render `{}` for silence, Hermes `block`/`approve`, or Claude `deny`/`ask`. Log the ask or deny.

`rule_key` is the host plus the rule ids, or a hash of the opaque command. One "always" does not cover another host.

The plugin sees per-chat `/yolo` and `approvals.mode: off`, and turns an ask into a block unless `when_approvals_off` is `allow`. The shell hook cannot see that session state. Measured on one Windows machine: about 0.5–0.7 s per shell-hook process, about 10 ms in-process. Not a benchmark suite.

It does not see a redirect after the request has left, the behaviour of a compiled binary, or a script that is not named in the call. Same-user code outside the agent can still read the signing key. Details: [docs, Mechanics](https://odaiameera.github.io/scamgate/docs.html#mechanics).

**Hermes** (`~/.hermes/config.yaml`). Needs a Hermes build whose shell hooks understand
`"action": "approve"` (older builds dropped it, turning every ask into a pass; fixed in issue
#92553, Sep 2026). Hermes asks you to approve a new hook the first time it runs in an interactive
session. Check it with `hermes hooks list` or `hermes hooks doctor`:

```yaml
hooks:
  pre_tool_call:
    - matcher: ".*"          # scamgate passes non-network tools straight through
      command: "scamgate-hook"
      timeout: 15
      fail_closed: true
  post_tool_call:   # optional: records whether you approved each ask
    - matcher: ".*"
      command: "scamgate-hook"
      timeout: 15
```

Note: with the shell hook, `/yolo` or `approvals.mode: off` auto-approves every scamgate **ask**
(blocks still hold). The Hermes plugin below turns those asks into blocks instead, unless you set
`plugins.entries.scamgate.settings.when_approvals_off: allow`.

**Hermes plugin** (preferred once it is in the catalog). Same checks as the shell hook, in-process,
about 50× faster, and it can see a per-chat `/yolo`. Needs Hermes 0.19.1+. Until the catalog entry
lands, install the `src/scamgate` directory as a plugin. It registers `pre_tool_call`,
`scamgate_check_url`, `scamgate_check_payment`, and `/scamgate status`.

**Claude Code** (`.claude/settings.json`). Needs Claude Code **v2.1.295+** for `onFailure`.
Without it, a hook that crashes, times out or can't start lets the tool call through:

```json
{"hooks": {
  "PreToolUse":  [{"matcher": ".*",
                   "hooks": [{"type": "command", "command": "/absolute/path/to/scamgate-hook",
                              "timeout": 15, "onFailure": "block"}]}],
  "PostToolUse": [{"matcher": ".*",
                   "hooks": [{"type": "command", "command": "/absolute/path/to/scamgate-hook"}]}]
}}
```

Use the absolute path (`uv tool dir --bin` shows it) so nothing earlier on `PATH` can stand in for
the hook.

Install a pinned copy for the hook (`uv tool install git+https://github.com/odaiameera/scamgate@v0.3.1`, or a commit hash)
rather than running from a source checkout: an installed copy checks its own files against the
hashes recorded at install time on every call, and blocks everything if they changed. A source
checkout has nothing to check against.

Each gated call costs one process start (about 0.7 s on Windows). Calls that don't touch
the network, or scamgate's files, pass straight through.

### Ask log, review and promote

Every `ask` and `deny` is logged to `$SCAMGATE_STATE_DIR` (default `~/.local/state/scamgate`)
with redacted targets, the rules that fired, the score, the agent's stated reason (stored for
you to read and marked **untrusted**; in scoring it can only add risk) and whether you then let it run.

```bash
scamgate review --days 7                       # which hosts keep tripping it, and what you did
scamgate promote --host shop.example --decision deny
scamgate promote --host shop.example --decision allow --rule url.userinfo
```

Only a person can add an override. `promote` asks for confirmation, and refuses to run without an
interactive terminal or inside a known agent (Claude Code, Hermes, Codex), even when an agent
imports scamgate's code directly. Every override line is signed with a key in the state dir, so a
line typed into the file any other way is ignored. A `deny` covers the host and its subdomains.
An `allow` is narrow: it waives **one rule on one exact host**, and can never waive known-bad
feeds, your blocklist, intent checks or your own deny rules, so an attacker can't train the gate
into trusting a whole domain.

### Payee history

`check_payment` doesn't take the agent's word for `is_new_payee`. It looks the payee up in a
local history of people you've actually paid (stored as salted hashes, never names or account
numbers). It flags:

- a payee you've paid before showing up with a different account (changed bank details);
- a **near-name** with a new account ("Acme Trading Ltd", "Acmee Ltd", a Cyrillic "е" in "Acme"):
  the classic invoice-redirection trick;
- an account you've paid before under a different name;
- an agent calling a payee "known" when there's no record of paying them (adds risk).

Only you add to it, after a real payment, the same way as overrides: interactive, not inside an
agent, signed lines. If the history's key or salt goes missing, every payee is treated as new
with changed details, rather than silently forgetting everyone.

```bash
scamgate record-payment --payee "Acme Ltd" --account IE29AIBK93115212345678
```

### Domain age (opt-in)

New domains are a strong scam-shop signal (`url.domain_age`, 30 points under 30 days old). Looking
one up asks the domain's registry over RDAP, which tells the registry which site you're checking,
so it's off unless you choose:

| `SCAMGATE_RDAP` | What happens |
| --- | --- |
| `off` (default) | No lookups. The rule never fires. |
| `cache` | Uses ages already cached; never goes online. Fill the cache with `scamgate domain-age HOST`. |
| `live` | Looks up unknown domains (3 s timeout) and caches the answer for a year (failures for 7 days). |

Official brand domains, shared platforms, IPs and localhost are never looked up. Registries come
from IANA's RDAP bootstrap list, cached in the feed cache dir.

## Known-bad-link feeds

Only `scamgate update-feeds` touches the network. Checks read a local cache. No feed data is
bundled in this repo.

```bash
scamgate update-feeds            # default feeds
scamgate update-feeds --all      # also the large opt-in feed
scamgate update-feeds -f openphish
scamgate feeds-status
```

The cache lives in `$SCAMGATE_CACHE_DIR`, else `$XDG_CACHE_HOME/scamgate`, else `~/.cache/scamgate`.
Each feed keeps its own files, and `meta.json` records fetch time, source and counts. A failed
download keeps that feed's previous cache. Verdicts warn when no feed is cached or a feed is older
than 24 hours. A running MCP server picks up a refreshed cache without a restart.

| Feed | Default | Source | License / terms |
| --- | --- | --- | --- |
| `openphish` | yes | [OpenPhish community feed](https://openphish.com/feed.txt) | [OpenPhish Terms](https://openphish.com/terms.html): **personal, non-commercial use only**, no redistribution. Commercial use needs OpenPhish's written consent |
| `phishing_database_domains` | yes | [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) active domains | MIT |
| `phishing_database_links` | `--all` | Phishing.Database active links (~65 MB download) | MIT |
| `urlhaus` | if key set | [abuse.ch URLhaus](https://urlhaus.abuse.ch/api/) online malware URLs | Free [abuse.ch Auth-Key](https://auth.abuse.ch/) required (`SCAMGATE_URLHAUS_AUTH_KEY`). Fair-use terms; commercial use may need a paid plan |

You are responsible for following each feed's terms. Not used: PhishTank (new registrations are
disabled) and Google Safe Browsing / Web Risk (non-commercial only, or paid).

Matching: an exact listed URL scores 100, an exact listed host 75, and a subdomain of a listed
domain (domain feeds only) 50.

Refresh with cron, for example every 6 hours:

```cron
0 */6 * * * cd /path/to/scamgate && uv run scamgate update-feeds >> ~/.cache/scamgate/update.log 2>&1
```

Your own blocklist: [`src/scamgate/data/blocklist.txt`](src/scamgate/data/blocklist.txt) (or `$SCAMGATE_BLOCKLIST`). It
ships with a few made-up `.example` domains.

## False positives

Feeds list single bad pages on big shared platforms (Google Docs and Sites, Firebase storage,
Microsoft login, Discord CDN, link shorteners). Flagging those whole hosts would block normal
sites. For domains under `lists.feed_host_ignore` in
[`rules.yaml`](src/scamgate/config/rules.yaml) (and their subdomains), and for official brand
domains, only an exact URL listing counts. One phishing page on `x.vercel.app` never flags
`vercel.app`. The trade-off: a scam on a subdomain of an ignored platform is only caught by exact URL.

## Configuration

Weights, thresholds, brand lists and word lists live in
[`src/scamgate/config/rules.yaml`](src/scamgate/config/rules.yaml). Point `SCAMGATE_CONFIG` at
your own copy to override it. To add a rule, write a function in
[`src/scamgate/rules/`](src/scamgate/rules/) decorated with `@register("url.my_rule", kind="url")`,
give it an entry under `rules:` in `rules.yaml`, and add tests and a scenario.

## Bench and tests

[`scenarios/`](scenarios/) holds 24 hand-written **example** cases (17 scam, 7 legit), each with
an expected decision.

```console
$ uv run scamgate bench
...
Scams: 17  caught: 17  missed: 0
Legit: 7  false positives: 0
Exact decision match: 24/24
```

This is a regression check for the rules, not a real-world detection rate. `uv run pytest`
runs the unit tests (CI runs them on Python 3.11–3.13). They use fixtures and never touch the network.

## Limits

- **Advisory by default.** Over MCP it only warns, and the agent has to call it. Install the
  [hook](#enforce-it-with-a-hook) to enforce it. Even then it only sees tool calls: a link the
  agent reaches by a redirect, or a destination hidden in a variable, needs your approval
  rather than a check.
- Heuristic rules miss scams that don't match them and sometimes flag legitimate actions.
  Treat `allow` as "no known red flags", not "safe".
- Domain age needs opting in (`SCAMGATE_RDAP=cache` or `live`, see below), because a live
  lookup tells the domain's registry which site you're checking.
- Known trade-offs: a word one letter off a long brand (`stripes.com` vs `stripe`) still asks. A
  bank transfer to a new payee **asks** (25) unless your bank's Verification of Payee matched the
  name; card payments to new payees don't.
- The hook sees a tool call's arguments, not what a program does once it runs: a local script,
  binary or package install script that opens the network is invisible unless the command line
  shows it. Code that is decoded or downloaded and then run (`base64 -d | bash`,
  `exec(b64decode(…))`, `powershell -enc`) asks.
- The brand pack covers about 50 of the most-phished brands plus Irish/UK banks, couriers and
  services; add your own under `lists.brands`. Registrable domains use a curated suffix list
  (country second-levels and shared hosts like `github.io`, `vercel.app`), not the full PSL.
- Payee history only knows payees you've recorded with `record-payment`. scamgate doesn't
  verify IBANs or call your bank.
- Tamper protection stops an agent's normal tools: writes to scamgate, its state and feed
  cache, its virtualenv (a new `.pth` file fails the integrity check), `~/.claude` and project
  `.claude/settings*.json`, and the Hermes config, however the path is spelled (`~`, `$HOME`,
  globs, `cd` + relative). It isn't a sandbox: code running as you can read the signing key and
  rewrite any file, and code can be written to slip past pattern matching. For the strongest
  setup, give the agent no direct shell access, install scamgate where the agent's user can't
  write (`uv tool install` as another user, or read-only), and for Claude Code put the hook in
  managed settings with `allowManagedHooksOnly`.
- Hermes trusts a hook by its command string, not its file hash, so it won't notice if the
  installed scamgate is replaced. The integrity check covers edits to the installed files.

**Disclaimer:** scamgate is not financial, legal or security advice, and it doesn't replace your
bank's fraud controls, Verification of Payee, or human judgement.

## Roadmap

- IBAN checksum validation and Verification of Payee integration
- Redirect after-check: re-check the page a browser actually landed on
- Optional local model as a tie-breaker on vague cases only, never overruling a hard rule
- Full Public Suffix List (optional, cached)
- More scenarios based on real fraud typologies

## Contributing

Issues and pull requests are welcome, especially new rules, scenarios (scam and legit) and
false-positive reports. Please include a test or scenario with each rule change, and keep checks
offline and deterministic. See [`AGENTS.md`](AGENTS.md) for repo conventions.

## License

[MIT](LICENSE). Feed data is not included and stays under each provider's own terms.

[![M8ven Score](https://m8ven.ai/badge/mcp/odaiameera-scamgate-1aer5u?v=14922257c317d320ce1f7cf19ade881e)](https://m8ven.ai/mcp/odaiameera-scamgate-1aer5u?s=readme)
