"""Feed updates from a plain Hermes plugin install: no `scamgate` command on PATH, no typer.

- `/scamgate update` and the `scamgate_update_feeds` tool refresh the default feeds. The tool takes
  no arguments, so an agent can ask for a refresh but can't choose what lands in the cache.
- `hermes scamgate update-feeds | feeds-status` works on the plugin alone.
- A background refresh keeps the lists fresh every 6 hours, unless it's turned off.
"""

import argparse
import json
import os
import time
from pathlib import Path

import pytest

from scamgate import feeds, plugin, refresh

FIXTURES = Path(__file__).parent / "fixtures" / "feeds"


def fixture_fetch(url):
    if "openphish" in url:
        return (FIXTURES / "openphish.txt").read_text()
    if "phishing-domains" in url:
        return (FIXTURES / "phishing-domains.txt").read_text()
    raise AssertionError(f"unexpected download: {url}")


class Ctx:
    def __init__(self, cli=True):
        self.hooks, self.tools, self.commands, self.cli, self.settings, self.unload = {}, {}, {}, {}, {}, []
        if not cli:
            self.register_cli_command = None

    def register_hook(self, name, fn):
        self.hooks[name] = fn

    def register_tool(self, **kw):
        self.tools[kw["name"]] = kw

    def register_command(self, name, handler, **kw):
        self.commands[name] = handler

    def register_cli_command(self, name, help, setup_fn, handler_fn=None, description=""):
        self.cli[name] = (setup_fn, handler_fn)

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def on_unload(self, fn):
        self.unload.append(fn)


@pytest.fixture
def cache(tmp_path, monkeypatch):
    d = tmp_path / "cache"
    monkeypatch.setenv(feeds.ENV_CACHE_DIR, str(d))
    monkeypatch.delenv(feeds.ENV_URLHAUS_KEY, raising=False)
    monkeypatch.setattr(feeds, "_download", fixture_fetch)
    return d


@pytest.fixture
def spy(monkeypatch):
    calls = []
    real = feeds.update_feeds

    def update(*args, **kwargs):
        calls.append((args, kwargs))
        return real(*args, **kwargs)

    monkeypatch.setattr(feeds, "update_feeds", update)
    return calls


def _age(d: Path, hours: float) -> None:
    meta = json.loads((d / "meta.json").read_text())
    ts = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() - hours * 3600))
    for v in meta.values():
        v["fetched_at"] = ts
    (d / "meta.json").write_text(json.dumps(meta))


# ---------------------------------------------------------------- registration

def test_register_adds_the_update_tool_command_and_cli():
    ctx = Ctx()
    plugin.register(ctx)
    assert "scamgate_update_feeds" in ctx.tools
    schema = ctx.tools["scamgate_update_feeds"]["schema"]["parameters"]
    assert schema["properties"] == {} and schema.get("additionalProperties") is False
    assert "scamgate" in ctx.commands
    assert "scamgate" in ctx.cli


def test_register_still_works_on_a_hermes_without_cli_commands():
    ctx = Ctx(cli=False)
    plugin.register(ctx)
    assert "scamgate_update_feeds" in ctx.tools


# ---------------------------------------------------------------- the agent tool

def test_tool_downloads_the_default_feeds_into_the_cache(cache, spy):
    body = json.loads(plugin.update_feeds_tool({}))
    assert body["updated"] == ["openphish", "phishing_database_domains"]
    assert (cache / "phishing_database_domains.hosts.txt").read_text().startswith("bad-shop.test")
    assert json.loads(plugin.check_url({"url": "https://bad-shop.test/x"}))["decision"] == "deny"


def test_tool_ignores_any_arguments_the_agent_sends(cache, spy, tmp_path):
    other = tmp_path / "elsewhere"
    plugin.update_feeds_tool({"feeds": ["phishing_database_links"], "url": "https://evil.example/list.txt",
                              "directory": str(other), "cache_dir": str(other), "fetch": "x"})
    assert spy == [((), {})]  # default feeds, default folder, real downloader
    assert not other.exists()


def test_tool_does_not_download_again_within_the_hour(cache, spy):
    plugin.update_feeds_tool({})
    spy.clear()
    body = json.loads(plugin.update_feeds_tool({}))
    assert spy == []
    assert body["skipped"] == "fresh"


def test_tool_refreshes_again_once_the_lists_are_an_hour_old(cache, spy):
    plugin.update_feeds_tool({})
    _age(cache, 2)
    spy.clear()
    plugin.update_feeds_tool({})
    assert len(spy) == 1


def test_a_second_refresh_waits_for_the_first(cache, spy):
    cache.mkdir(parents=True)
    (cache / refresh.LOCK_NAME).write_text(str(os.getpid()))
    body = json.loads(plugin.update_feeds_tool({}))
    assert spy == [] and body["skipped"] == "busy"


def test_a_lock_left_by_a_crashed_refresh_expires(cache, spy):
    cache.mkdir(parents=True)
    lock = cache / refresh.LOCK_NAME
    lock.write_text("1")
    old = time.time() - refresh.LOCK_STALE_SECONDS - 5
    os.utime(lock, (old, old))
    plugin.update_feeds_tool({})
    assert len(spy) == 1 and not lock.exists()


def test_tool_reports_failures_without_raising(cache, monkeypatch):
    def offline(url):
        raise OSError("network is unreachable")

    monkeypatch.setattr(feeds, "_download", offline)
    body = json.loads(plugin.update_feeds_tool({}))
    assert body["updated"] == []
    assert "network is unreachable" in json.dumps(body["failed"])


# ---------------------------------------------------------------- slash command

def test_slash_update_refreshes_instead_of_pointing_at_a_missing_command(cache, spy):
    text = plugin.slash("update")
    assert len(spy) == 1
    assert "openphish" in text and "phishing_database_domains" in text
    assert "yourself" not in text


def test_slash_status_tells_plugin_users_how_to_refresh(cache):
    text = plugin.slash("status")
    assert "/scamgate update" in text


def test_slash_status_lists_each_feed_after_an_update(cache):
    plugin.slash("update")
    text = plugin.slash("status")
    assert "openphish" in text and "loaded" in text


# ---------------------------------------------------------------- hermes scamgate ...

def _cli(argv):
    ctx = Ctx()
    plugin.register(ctx)
    setup, handler = ctx.cli["scamgate"]
    parser = argparse.ArgumentParser(prog="hermes scamgate")
    setup(parser)
    args = parser.parse_args(argv)
    return (handler or args.func)(args)


def test_hermes_cli_update_feeds_and_status(cache, capsys):
    assert _cli(["update-feeds"]) == 0
    assert "phishing_database_domains" in capsys.readouterr().out
    assert _cli(["feeds-status"]) == 0
    out = capsys.readouterr().out
    assert "openphish" in out and "fetched" in out


def test_hermes_cli_status_fails_on_an_empty_cache(cache, capsys):
    assert _cli(["feeds-status"]) == 1
    assert "update-feeds" in capsys.readouterr().out


def test_hermes_cli_update_fails_when_nothing_downloads(cache, monkeypatch, capsys):
    monkeypatch.setattr(feeds, "_download", lambda url: (_ for _ in ()).throw(OSError("offline")))
    assert _cli(["update-feeds"]) == 1


# ---------------------------------------------------------------- background refresh

def test_background_refresh_is_on_by_default(monkeypatch):
    monkeypatch.delenv("SCAMGATE_AUTO_UPDATE", raising=False)
    assert plugin.auto_update_enabled(Ctx())


@pytest.mark.parametrize("value", ["0", "off", "false", "no"])
def test_background_refresh_can_be_turned_off_by_env(monkeypatch, value):
    monkeypatch.setenv("SCAMGATE_AUTO_UPDATE", value)
    assert not plugin.auto_update_enabled(Ctx())


def test_background_refresh_can_be_turned_off_in_config(monkeypatch):
    monkeypatch.delenv("SCAMGATE_AUTO_UPDATE", raising=False)
    ctx = Ctx()
    ctx.settings["auto_update_feeds"] = False
    assert not plugin.auto_update_enabled(ctx)


def test_background_pass_refreshes_only_lists_older_than_six_hours(cache, spy):
    refresh.refresh()
    _age(cache, 5)
    spy.clear()
    refresh.auto_pass()
    assert spy == []
    _age(cache, 7)
    refresh.auto_pass()
    assert len(spy) == 1


def test_background_pass_fills_an_empty_cache(cache, spy):
    refresh.auto_pass()
    assert len(spy) == 1


def test_background_thread_starts_once_and_stops_on_unload(monkeypatch, cache):
    monkeypatch.delenv("SCAMGATE_AUTO_UPDATE", raising=False)
    passes = []
    monkeypatch.setattr(refresh, "auto_pass", lambda: passes.append(1))
    monkeypatch.setattr(plugin, "AUTO_FIRST_DELAY", 0.01)
    monkeypatch.setattr(plugin, "AUTO_EVERY", 0.01)
    ctx = Ctx()
    t1 = plugin.start_auto_update(ctx)
    t2 = plugin.start_auto_update(ctx)
    assert t1 is not None and t2 is t1
    deadline = time.time() + 5
    while not passes and time.time() < deadline:
        time.sleep(0.01)
    assert passes
    for fn in ctx.unload:
        fn()
    t1.join(2)
    assert not t1.is_alive()
    plugin.start_auto_update(ctx)  # a new thread after an unload
    for fn in ctx.unload:
        fn()


def test_background_thread_not_started_when_off(monkeypatch):
    monkeypatch.setenv("SCAMGATE_AUTO_UPDATE", "0")
    assert plugin.start_auto_update(Ctx()) is None


# ---------------------------------------------------------------- the update tool is never gated

def test_the_hook_lets_the_update_tool_through(fresh_feeds):
    assert plugin.on_pre_tool_call(tool_name="scamgate_update_feeds", args={}, session_id="s") is None
