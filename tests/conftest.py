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
