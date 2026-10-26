# scamgate for Claude Code

scamgate checks what Claude is about to do before it does it. A hook reads every tool call: the links in a
command, a page Claude is about to open, a file it is about to write. It blocks known phishing and malware
links and risky payments, and asks you first when it can't see where a command is going (a link built from a
variable, a downloaded script piped into a shell). Three tools let Claude check a link or a payment itself,
and refresh the phishing lists. Checks run on your machine: nothing about the links or payments you check is
sent anywhere.

## Requirements

- [uv](https://docs.astral.sh/uv/), so that `uvx` is on your `PATH`. The plugin runs scamgate from PyPI with
  `uvx scamgate==0.3.3`, pinned to one version.
- Claude Code v2.1.295 or later. From that version a hook that can't start blocks the tool call instead of
  letting it through. On older versions a broken hook (for example, `uvx` missing) lets calls through.

## Install

```text
/plugin install scamgate --marketplace odaiameera/scamgate
```

On Claude Code before 2.1.275, add the marketplace first:

```text
/plugin marketplace add odaiameera/scamgate
/plugin install scamgate@scamgate
```

The first session after installing takes longer to start: uv downloads scamgate 0.3.3 and its dependencies
from PyPI once.

## What it runs

| Part | Command | When |
| --- | --- | --- |
| Hook | `uvx scamgate==0.3.3 hook` | Session start (prepares the cached install, no output), before every tool call (decides), after every tool call (records whether you approved an ask) |
| MCP server | `uvx scamgate==0.3.3 serve` | While Claude Code runs. Tools: `check_url`, `check_payment`, `update_feeds` |

The hook answers with "deny" (blocked, with a plain-English reason), "ask" (Claude Code asks you) or nothing.
It never answers "allow", so it can't loosen your own permission settings.

## What it downloads, sends and stores

- **Phishing lists.** The [OpenPhish community feed](https://openphish.com/feed.txt) and the
  [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) active-domains list from
  raw.githubusercontent.com. They download about 10 seconds after a session starts if the copy on disk is
  older than 6 hours, then every 6 hours while Claude Code runs, and when Claude calls `update_feeds` (at most
  once an hour). Turn the automatic refresh off in `/config` (`auto_update_feeds`). The downloads are whole
  lists: they carry nothing about the links you check.
- **URLhaus**, only if you enter an abuse.ch key in the plugin's settings. The key is stored in your system's
  secure credential store and sent only to urlhaus-api.abuse.ch, as part of that list's download address.
- **Nothing else leaves your machine.** Domain-age lookups (RDAP), which would tell a registry which site you
  check, are off in this plugin.
- **Stored locally:** the phishing lists in a `scamgate` folder in your cache folder (`$XDG_CACHE_HOME`, by
  default `~/.cache`), and in a private `scamgate` folder in your state folder (`$XDG_STATE_HOME`, by default
  `~/.local/state`): a log of what was blocked or asked (links redacted, with the agent's stated reason
  marked untrusted), a signing key for your own allow and deny rules, and salted hashes of payees you
  recorded.

## What it protects

So that an agent can't switch it off, scamgate blocks agent tool calls that would edit its own files, its
cache and state, Claude Code's settings, hooks or installed plugins, or that would disable or remove a Claude
Code plugin or start Claude in a mode that skips hooks. Removing scamgate is something you do yourself, in
`/plugin`.

## Settings

| Setting | Default | What it does |
| --- | --- | --- |
| `auto_update_feeds` | on | Refresh the phishing lists automatically, as described above |
| `urlhaus_auth_key` | empty | Optional [abuse.ch Auth-Key](https://auth.abuse.ch/) that adds the URLhaus list |

## Limits

scamgate flags risk; it doesn't certify that anything is safe. Its rules miss scams that don't match them and
sometimes flag legitimate actions. The hook sees a tool call's arguments, not what a program does once it
runs. It stops an agent's normal tools; it is not a sandbox against code already running as you. Each checked
tool call starts one short process: about 0.8 seconds on a Windows PC with the full phishing lists loaded.

Source, full documentation and the rule list: <https://github.com/odaiameera/scamgate>. License: MIT.
