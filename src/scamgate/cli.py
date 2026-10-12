"""scamgate command line."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from scamgate import bench as bench_mod
from scamgate import engine

app = typer.Typer(help="Self-hosted scam check for AI agents.", no_args_is_help=True)
console = Console()


@app.command()
def serve() -> None:
    """Run the MCP server over stdio."""
    from scamgate.server import run

    run()


@app.command("check-url")
def check_url_cmd(url: str, intent: Optional[str] = typer.Option(None, help="What the agent is trying to do")) -> None:
    """Check one URL and print the verdict as JSON."""
    console.print_json(json.dumps(engine.check_url(url, intent).model_dump(mode="json")))


@app.command("update-feeds")
def update_feeds_cmd(
    feed: list[str] = typer.Option(None, "--feed", "-f", help="Feed(s) to fetch; default: all default feeds"),
    all_feeds: bool = typer.Option(False, "--all", help="Also fetch opt-in feeds (large Phishing.Database links list)"),
    cache: Optional[Path] = typer.Option(None, "--cache-dir", help="Cache folder (default $SCAMGATE_CACHE_DIR or ~/.cache/scamgate)"),
) -> None:
    """Download known-bad-link feeds into the local cache. Failed feeds keep their old cache."""
    from scamgate import feeds as feeds_mod

    names = list(feed) if feed else ([*feeds_mod.FEEDS] if all_feeds else None)
    results = feeds_mod.update_feeds(names, directory=cache)
    table = Table(title=f"feeds -> {cache or feeds_mod.cache_dir()}")
    for col in ("feed", "status", "urls", "hosts", "note"):
        table.add_column(col)
    for r in results:
        table.add_row(r.name, "[green]ok[/green]" if r.ok else "[yellow]not updated[/yellow]",
                      str(r.urls) if r.ok else "", str(r.hosts) if r.ok else "", r.message)
    console.print(table)
    if not any(r.ok for r in results):
        raise typer.Exit(1)


@app.command("feeds-status")
def feeds_status(cache: Optional[Path] = typer.Option(None, "--cache-dir")) -> None:
    """Show cached feeds, their entry counts and age."""
    from scamgate import feeds as feeds_mod

    meta = feeds_mod.read_meta(cache)
    if not meta:
        console.print("No feeds cached yet. Run `scamgate update-feeds`.")
        raise typer.Exit(1)
    idx = feeds_mod.FeedIndex(fetched_at={k: v.get("fetched_at", "") for k, v in meta.items()})
    stale = set(idx.stale_feeds())
    for name, m in meta.items():
        flag = " [yellow](stale)[/yellow]" if name in stale else ""
        console.print(f"{name}: {m.get('urls', 0)} urls, {m.get('hosts', 0)} hosts, fetched {m.get('fetched_at')}{flag}")


@app.command()
def hook() -> None:
    """Enforcement hook: read a Hermes or Claude Code hook event (JSON) on stdin, print the decision."""
    from scamgate import hook as hook_mod

    raise typer.Exit(hook_mod.main())


@app.command()
def review(days: int = typer.Option(7, help="Look back this many days"),
           limit: int = typer.Option(15, help="Show at most this many hosts")) -> None:
    """Show which links keep tripping the gate, and what you did with each ask."""
    from scamgate import asklog

    rows = asklog.summarize(days=days)[:limit]
    if not rows:
        console.print(f"No asks or blocks in the last {days} days.")
        return
    table = Table(title=f"scamgate asks, last {days} days")
    for col in ("host", "asks", "you approved", "you refused", "pending", "blocked", "top rules", "tools"):
        table.add_column(col)
    for r in rows:
        table.add_row(r.host, str(r.asks), str(r.ran), str(r.not_run), str(r.pending), str(r.blocks),
                      ", ".join(list(r.rules)[:2]), ", ".join(list(r.tools)[:2]))
    console.print(table)
    for r in rows[:5]:
        if r.sample_reasons:
            console.print(f"[dim]{r.host}: agent said (untrusted): "
                          + " | ".join(f"\"{s}\"" for s in r.sample_reasons) + "[/dim]")
    console.print("\nTurn a repeat ask into a rule: [bold]scamgate promote --host HOST --decision deny[/bold], or "
                  "[bold]--decision allow --rule RULE_ID[/bold] (allow waives one rule on one exact host).")


@app.command()
def promote(host: str = typer.Option(..., help="Exact host, e.g. shop.example (no wildcards)"),
            decision: str = typer.Option(..., help="allow or deny"),
            rule: Optional[str] = typer.Option(None, help="For allow: the one rule to waive on this host"),
            note: str = typer.Option("", help="Why (for your own records)")) -> None:
    """Add a human-approved override. Asks for confirmation; agents are blocked from running this."""
    from scamgate import overrides

    if decision == "allow" and not rule:
        console.print("An allow rule must name the one rule it waives: add --rule RULE_ID "
                      "(see `scamgate review` for the rules that fired).")
        raise typer.Exit(2)
    if rule and rule in overrides.NEVER_WAIVED:
        console.print(f"{rule} can't be waived: known-bad feeds, your blocklist and seed-phrase checks always apply.")
        raise typer.Exit(2)
    scope = (f"waive '{rule}' for {host} only (not its subdomains)" if decision == "allow"
             else f"deny {host} and all its subdomains")
    console.print(f"This will {scope}.")
    if not typer.confirm("Add this rule?", default=False):
        raise typer.Exit(1)
    try:
        rec = overrides.add(host, decision, rule=rule, note=note)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2)
    console.print(f"Added: {rec['decision']} {rec['host']}" + (f" (rule {rec['rule']})" if rec["rule"] else ""))


@app.command("record-payment")
def record_payment(payee: str = typer.Option(..., help="Payee name"),
                   account: str = typer.Option(..., help="IBAN, wallet or merchant id")) -> None:
    """Record a payee you've actually paid, so future checks know them (stored as hashes only)."""
    from scamgate import payees

    payees.record(payee, account)
    console.print(f"Recorded '{payee}'. Future payments to this exact account count as a known payee.")


@app.command()
def bench(
    directory: Path = typer.Option(Path("scenarios"), "--dir", help="Folder of scenario YAML files"),
    strict: bool = typer.Option(False, help="Exit non-zero if any decision differs from expected"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show reasons for each scenario"),
) -> None:
    """Run the scenario set and report caught / missed / false positives."""
    if not directory.is_dir():
        console.print(f"[red]No scenario folder at {directory}[/red]")
        raise typer.Exit(2)
    results = bench_mod.run_all(directory)

    table = Table(title=f"scamgate bench ({directory})")
    for col in ("id", "label", "expected", "got", "score", "outcome"):
        table.add_column(col)
    colours = {"caught": "green", "ok": "green", "missed": "red", "false_positive": "yellow"}
    for r in results:
        got = r.verdict.decision.value
        got_s = got if r.exact else f"[bold]{got}[/bold] (!)"
        table.add_row(r.scenario_id, r.label, r.expected.value, got_s, str(r.verdict.risk_score),
                      f"[{colours[r.outcome]}]{r.outcome}[/{colours[r.outcome]}]")
    console.print(table)

    if verbose:
        for r in results:
            console.print(f"\n[bold]{r.scenario_id}[/bold] {r.name}: {r.verdict.summary}")
            for reason in r.verdict.reasons:
                console.print(f"  +{reason.weight:<3} {reason.rule_id}: {reason.explanation}")

    s = bench_mod.summarize(results)
    console.print(
        f"\nScams: {s['scams']}  caught: {s['caught']}  missed: {s['missed']}\n"
        f"Legit: {s['legit']}  false positives: {s['false_positives']}\n"
        f"Exact decision match: {s['exact_decision_match']}/{s['total']}"
    )
    console.print("[dim]Example scenarios only; these numbers are a regression check, not a real-world detection rate.[/dim]")
    if strict and s["exact_decision_match"] != s["total"]:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
