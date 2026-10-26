# Security policy

scamgate is a security control, so a bypass is a real bug. Please report it privately.

## Reporting

- **Don't open a public issue or PR** for a hook bypass, a tamper path, a score that agent text can
  lower, an integrity-check escape, or anything that turns a block into silence.
- Report it via [GitHub private vulnerability reporting](https://github.com/odaiameera/scamgate/security/advisories/new)
  (Security tab → "Report a vulnerability").
- Include the scamgate version or commit, the exact tool call or command, and what you expected
  (block or ask) versus what happened.

## What to expect

- An acknowledgement within a few days. A fix lands with a regression test, and you're credited
  in the CHANGELOG unless you'd rather not be.
- Only the latest release is supported.

## Out of scope

Things the README's [Limits](README.md#limits) already say scamgate can't see: redirects after a
request leaves, what a compiled binary or an unnamed script does, and same-user code reading
the signing key. Heuristic misses and false positives are normal issues, not security reports.
