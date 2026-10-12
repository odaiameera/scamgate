# scamgate

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
doesn't need.

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

# or with pip
pip install "git+https://github.com/odaiameera/scamgate.git"
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
`summary`, `warnings[]`, `advisory`.

## Enforce it with a hook

The MCP tools only work when the agent chooses to call them, and a prompt injection can tell
it not to. The hook moves the check into the harness: the agent can't skip it.

`scamgate-hook` (or `scamgate hook`) reads one hook event as JSON on stdin and writes a decision.
It speaks Hermes shell hooks and Claude Code `PreToolUse` hooks.

- **Links:** every URL in a web, browser, media, terminal, code or unknown MCP tool call is
  checked, including disguised forms (`evilsh%6fp.com`, `http://3405803781`). `deny` blocks the
  call, `ask` sends it to you for approval. One bad link in a batch blocks the whole batch.
- **Hidden destinations:** a network step scamgate can't read goes to you, judged per command
  (`curl https://example.org; curl "$URL"` still asks): variables, `$(…)`, string-built links,
  `requests.get(open(…).read())`, package installs, `git fetch`.
- **Running blind:** with no feeds cached, links go to you for approval (`SCAMGATE_NO_FEEDS=warn`
  turns that into a warning). Stale feeds are mentioned in every ask and block.
- **Tampering:** blocks agent writes to scamgate's own code, state and feed cache and to the hook
  config, plus commands or code that revoke the hook, remove the server, promote rules, record
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

Note: `/yolo` or `approvals.mode: off` in Hermes auto-approves every scamgate **ask** (blocks still
hold).

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

Install a pinned copy for the hook (`uv tool install git+https://github.com/odaiameera/scamgate@<commit>`)
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

`promote` asks for confirmation and the hook blocks agents from running it. A `deny` covers the
host and its subdomains. An `allow` is narrow: it waives **one rule on one exact host**, and can
never waive known-bad feeds, your blocklist, intent checks or your own deny rules, so an attacker
can't train the gate into trusting a whole domain.

### Payee history

`check_payment` doesn't take the agent's word for `is_new_payee`. It looks the payee up in a
local history of people you've actually paid (stored as salted hashes, never names or account
numbers). A payee you've paid before showing up with a different account is treated as changed
bank details. Only you add to it, after a real payment; the hook blocks agents from doing so.

```bash
scamgate record-payment --payee "Acme Ltd" --account IE29AIBK93115212345678
```

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

Your own blocklist: [`data/blocklist.txt`](data/blocklist.txt) (or `$SCAMGATE_BLOCKLIST`). It
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

[`scenarios/`](scenarios/) holds 19 hand-written **example** cases (13 scam, 6 legit), each with
an expected decision.

```console
$ uv run scamgate bench
...
Scams: 13  caught: 13  missed: 0
Legit: 6  false positives: 0
Exact decision match: 19/19
```

This is a regression check for the rules, not a real-world detection rate. `uv run pytest`
runs the unit tests (211 passing). They use fixtures and never touch the network.

## Limits

- **Advisory by default.** Over MCP it only warns, and the agent has to call it. Install the
  [hook](#enforce-it-with-a-hook) to enforce it. Even then it only sees tool calls: a link the
  agent reaches by a redirect, or a destination hidden in a variable, needs your approval
  rather than a check.
- Heuristic rules miss scams that don't match them and sometimes flag legitimate actions.
  Treat `allow` as "no known red flags", not "safe".
- The domain-age check (`url.domain_age`) is a stub and off by default.
- Known misses: `applebees.com` scores 60 (**ask**) because it contains "apple". A bank
  transfer to a new payee with no other signals scores 20 (**allow**).
- The brand list is small, and there's no full Public Suffix List handling yet.
- Payee history only knows payees you've recorded with `record-payment`. scamgate doesn't
  verify IBANs or call your bank.
- Tamper protection stops an agent's normal tools. It isn't a sandbox: anything with full
  control of your account can still change scamgate's files, and code can be written to slip
  past pattern matching. For the strongest setup, give the agent no direct shell access.
- Hermes trusts a hook by its command string, not its file hash, so it won't notice if the
  installed scamgate is replaced. The integrity check covers edits to the installed files.

**Disclaimer:** scamgate is not financial, legal or security advice, and it doesn't replace your
bank's fraud controls, Verification of Payee, or human judgement.

## Roadmap

- Domain age via RDAP, behind the existing `url.domain_age` hook
- IBAN checksum validation and Verification of Payee integration
- Redirect after-check: re-check the page a browser actually landed on
- Optional local model as a tie-breaker on vague cases only, never overruling a hard rule
- Bigger, configurable brand list and proper Public Suffix List handling
- More scenarios based on real fraud typologies

## Contributing

Issues and pull requests are welcome, especially new rules, scenarios (scam and legit) and
false-positive reports. Please include a test or scenario with each rule change, and keep checks
offline and deterministic. See [`AGENTS.md`](AGENTS.md) for repo conventions.

## License

[MIT](LICENSE). Feed data is not included and stays under each provider's own terms.
