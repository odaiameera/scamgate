# scamgate

**Self-hosted scam check for AI agents: verify links and payments before they act.**

scamgate is a small, open MCP server. Before an agent opens a link or makes a payment, it
calls scamgate and gets back a verdict:

- `allow`: no meaningful scam signals
- `ask`: stop and show the reasons to the human
- `deny`: don't proceed

Every verdict comes with a 0–100 risk score and plain-English reasons, each tied to a rule id.
v1 is deterministic: local rules, no LLM, no network calls.

> **Status:** early scaffold (v0.1). Private repo. License TBD.

## Why

AI agents now browse, shop and pay for people, and they can be steered. Text planted in pages,
listings or messages (prompt injection) can push an agent toward a fake shop, a credential
prompt or a "pay by transfer" request. Look-alike domains and urgent payment requests, the
same tricks that work on humans, work on agents too.

Agent payment protocols and card-network programs secure *the payment* (tokens, limits,
authentication). They don't judge whether *the decision to pay* makes sense: is this payee
new, did the bank details just change, why does the seller only take crypto? Those are fraud
typology questions, and that's the gap scamgate covers. It also covers bank transfers and plain
links, not just one payment network.

## What v1 checks

**Links (`check_url`)**

| Rule | Fires when |
| --- | --- |
| `url.blocklist` | Domain or a parent domain is in `data/blocklist.txt` (or fetched feeds) |
| `url.lookalike_brand` | Typosquat or homoglyph of a known brand (`paypa1`, `amaz0n`, `arnazon`, Cyrillic letters), or a brand name on an unofficial domain. Brands: PayPal, Revolut, AIB, Bank of Ireland, Stripe, Amazon, Apple |
| `url.ip_host` | Link goes to a raw IP address |
| `url.punycode` | Host uses punycode / non-ASCII characters |
| `url.suspicious_tld` | Cheap, commonly abused TLD (`.top`, `.xyz`, `.shop`, …) |
| `url.intent_mismatch` | Page asks for a seed phrase / private key (always), or a login the agent's stated intent doesn't need |
| `url.domain_age` | *Stub, off by default.* Plug in a WHOIS/RDAP provider to flag brand-new domains |

**Payments (`check_payment`)**

| Rule | Fires when |
| --- | --- |
| `pay.new_payee_urgency` | New payee + urgency language ("urgent", "today", "immediately") |
| `pay.bank_details_changed` | Flag passed in, or messages say the bank details changed (invoice redirection) |
| `pay.irreversible_method` | Crypto or gift cards; bank transfer to a new payee (lower weight) |
| `pay.method_restricted` | Seller insists on a method ("crypto only", "no cards", "gift cards") |
| `pay.over_budget` | Amount is over the budget the human set |
| `pay.pressure_phrases` | Secrecy or pressure ("keep this confidential", "do not tell the bank", "guaranteed returns") |
| `pay.vop_mismatch` | Verification of Payee result is `no_match`, `close_match` or `unavailable` |

Weights, thresholds and word lists live in [`src/scamgate/config/rules.yaml`](src/scamgate/config/rules.yaml).
The risk score is the sum of fired rule weights, capped at 100. Defaults: `ask` at 25, `deny` at 70.

## Install

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone git@github.com:odaiameera/scamgate.git
cd scamgate
uv sync
uv run scamgate bench                      # run the example scenarios
uv run scamgate check-url "https://paypa1.com/login" --intent "buy a ticket"
uv run scamgate serve                      # MCP server on stdio
```

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

Then tell the agent, in its system prompt or instructions:
*"Call `check_url` before opening any link and `check_payment` before any payment. On `ask`, stop
and show me the reasons. On `deny`, don't proceed."*

### Tools

```text
check_url(url: str, intent: str | None) -> Verdict
check_payment(payee_name, payee_account, amount, currency,
              method: card | bank_transfer | crypto | gift_card | other,
              context_text=None, is_new_payee=None, bank_details_changed=None,
              budget=None, vop_result: match | close_match | no_match | unavailable = None) -> Verdict
```

Example verdict:

```json
{
  "decision": "deny",
  "risk_score": 80,
  "reasons": [
    {"rule_id": "url.lookalike_brand", "weight": 60,
     "explanation": "'amaz0n-deals.shop' disguises 'amazon' with look-alike characters ('amaz0n'). The real site is amazon.com."},
    {"rule_id": "url.suspicious_tld", "weight": 20,
     "explanation": "The domain ends in '.shop', a cheap ending often used by throwaway scam sites."}
  ],
  "summary": "Do not proceed with this link. Main concern: ...",
  "advisory": "scamgate is advisory. ..."
}
```

## Scenarios and bench

`scenarios/` holds **example** cases written for this project (not real incidents), each with
a `label` (`scam` / `legit`) and the `expected` decision. `scamgate bench` runs them and reports
caught, missed and false positives. Add `--strict` to fail on any mismatch, `-v` to see reasons.

The bench is a regression check for the rules. Scores on hand-written scenarios say nothing about
real-world detection rates.

## Adding a rule

1. Write a function in `src/scamgate/rules/url.py` or `payment.py` and decorate it with
   `@register("pay.my_rule", kind="payment")`. Return a `Hit(explanation)` or `None`.
2. Add `pay.my_rule: { enabled: true, weight: 30 }` under `rules:` in `rules.yaml`.
3. Add tests and at least one scenario.

## Blocklist feeds

`data/blocklist.txt` ships with a few made-up `.example` domains only. `scripts/fetch_feeds.py`
is a stub for pulling community feeds (e.g. OpenPhish community feed, phishdestroy/destroylist)
into `data/feeds/`, which is git-ignored and loaded automatically. No third-party feed data is
bundled; check each feed's terms before use.

## Roadmap

- Optional Google Web Risk / Safe Browsing lookup (opt-in, needs an API key)
- Domain age via RDAP, behind the existing `url.domain_age` hook
- Optional local LLM check for manipulation and prompt injection in page or message text
- Proper Public Suffix List handling and a bigger, configurable brand list
- Many more scenarios, including real-world-inspired fraud typologies
- HTTP transport for shared/homelab deployments

## Limits (please read)

scamgate is **advisory, not a guarantee.** It uses simple heuristics: it will miss scams that
don't match its rules, and it will sometimes flag legitimate links or payments. It does not
replace your bank's fraud controls, Verification of Payee, or human judgement, and it isn't
financial or legal advice. Treat `allow` as "no known red flags", not "safe".

## License

TBD (private repo for now).
