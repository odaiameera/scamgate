"""`scamgate update-feeds` and `feeds-status` end to end through the CLI, on sample feed data."""

from pathlib import Path

from typer.testing import CliRunner

from scamgate import feeds
from scamgate.cli import app

FIXTURES = Path(__file__).parent / "fixtures" / "feeds"


def fixture_fetch(url):
    if "openphish" in url:
        return (FIXTURES / "openphish.txt").read_text()
    if "phishing-domains" in url:
        return (FIXTURES / "phishing-domains.txt").read_text()
    raise AssertionError(f"unexpected download: {url}")


def test_update_feeds_then_status_on_sample_data(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    monkeypatch.setenv(feeds.ENV_CACHE_DIR, str(cache))
    monkeypatch.delenv(feeds.ENV_URLHAUS_KEY, raising=False)
    monkeypatch.setattr(feeds, "_download", fixture_fetch)
    monkeypatch.setenv("COLUMNS", "200")  # rich would cut feed names to fit 80 columns
    runner = CliRunner()

    up = runner.invoke(app, ["update-feeds"])
    assert up.exit_code == 0, up.output
    assert "openphish" in up.output and "phishing_database_domains" in up.output
    assert "bad-shop.test" in (cache / "phishing_database_domains.hosts.txt").read_text()

    st = runner.invoke(app, ["feeds-status"])
    assert st.exit_code == 0, st.output
    assert "phishing_database_domains" in st.output and "(stale)" not in st.output

    check = runner.invoke(app, ["check-url", "https://bad-shop.test/login"])
    assert '"deny"' in check.output


def test_update_feeds_exits_non_zero_when_every_feed_fails(tmp_path, monkeypatch):
    monkeypatch.setenv(feeds.ENV_CACHE_DIR, str(tmp_path / "cache"))
    monkeypatch.setattr(feeds, "_download", lambda url: (_ for _ in ()).throw(OSError("offline")))
    assert CliRunner().invoke(app, ["update-feeds"]).exit_code == 1
