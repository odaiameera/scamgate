from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def scenarios_dir() -> Path:
    return ROOT / "scenarios"


@pytest.fixture(autouse=True)
def _isolated_feed_cache(tmp_path_factory, monkeypatch):
    """Tests never read the real feed cache or the network."""
    from scamgate import feeds

    monkeypatch.setenv(feeds.ENV_CACHE_DIR, str(tmp_path_factory.mktemp("empty-cache")))
    feeds.load_index.cache_clear(); feeds._index_at.cache_clear()
    yield
    feeds.load_index.cache_clear(); feeds._index_at.cache_clear()


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path_factory, monkeypatch):
    """Tests never write to the real ask log, overrides or payee history."""
    from scamgate import state

    monkeypatch.setenv(state.ENV_STATE_DIR, str(tmp_path_factory.mktemp("state")))
    monkeypatch.delenv("SCAMGATE_PROTECT", raising=False)
    monkeypatch.delenv("HERMES_HOME", raising=False)
    from scamgate import guard, hook, overrides, payees

    monkeypatch.setattr(hook, "_FEEDS", None)
    # Tests act as the human at a terminal unless they say otherwise (the suite itself may run
    # inside an agent, or in CI without a TTY).
    for m in guard.AGENT_ENV_MARKERS:
        monkeypatch.delenv(m, raising=False)
    monkeypatch.setattr(overrides, "_interactive", lambda: True)
    monkeypatch.setattr(payees, "_interactive", lambda: True)


@pytest.fixture
def fresh_feeds(tmp_path, monkeypatch):
    """A small, current feed cache (evilshop.com domain, one OpenPhish URL)."""
    import json
    import time

    from scamgate import feeds, hook

    d = tmp_path / "fresh-cache"
    d.mkdir()
    now = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    (d / "meta.json").write_text(json.dumps({"phishing_database_domains": {"fetched_at": now},
                                             "openphish": {"fetched_at": now}}))
    (d / "phishing_database_domains.hosts.txt").write_text("evilshop.com\n")
    (d / "phishing_database_domains.urls.txt").write_text("")
    (d / "openphish.urls.txt").write_text("http://phish-login.net/steal\n")
    (d / "openphish.hosts.txt").write_text("phish-login.net\n")
    monkeypatch.setenv(feeds.ENV_CACHE_DIR, str(d))
    monkeypatch.setattr(hook, "_FEEDS", None)
    return d
