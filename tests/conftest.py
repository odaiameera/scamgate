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
    from scamgate import hook

    monkeypatch.setattr(hook, "_FEEDS", None)
