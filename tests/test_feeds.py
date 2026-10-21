from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scamgate import feeds
from scamgate.engine import check_url
from scamgate.models import Decision

FIX = Path(__file__).parent / "fixtures" / "feeds"
URLS = {
    "openphish.com": FIX / "openphish.txt",
    "phishing-domains-ACTIVE": FIX / "phishing-domains.txt",
    "csv_online": FIX / "urlhaus.csv",
}


def fake_fetch(url: str) -> str:
    for key, path in URLS.items():
        if key in url:
            return path.read_text()
    raise OSError("no network in tests")


def failing_fetch(url: str) -> str:
    raise OSError("network down")


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv(feeds.ENV_URLHAUS_KEY, "testkey")
    feeds.update_feeds(["openphish", "phishing_database_domains", "urlhaus"], directory=tmp_path, fetch=fake_fetch)
    return tmp_path


def idx(d):
    feeds.load_index.cache_clear()
    return feeds.load_index(str(d))


def test_normalize():
    assert feeds.normalize_url("HTTPS://Evil.Test:443/a/") == "http://evil.test/a"
    assert feeds.normalize_url("http://evil.test/a#frag") == "http://evil.test/a"
    assert feeds.normalize_host("Sub.Phishy.TEST.") == "sub.phishy.test"
    assert feeds.normalize_host("not a domain") is None


def test_update_writes_cache_and_meta(cache):
    meta = feeds.read_meta(cache)
    assert meta["openphish"]["urls"] == 3 and meta["phishing_database_domains"]["hosts"] == 2
    assert meta["urlhaus"]["urls"] == 1 and "testkey" not in meta["urlhaus"]["source_url"]
    assert "fetched_at" in meta["openphish"]


def test_urlhaus_skipped_without_key(tmp_path, monkeypatch):
    monkeypatch.delenv(feeds.ENV_URLHAUS_KEY, raising=False)
    [r] = feeds.update_feeds(["urlhaus"], directory=tmp_path, fetch=fake_fetch)
    assert not r.ok and "skipped" in r.message


def test_network_failure_keeps_old_cache(cache):
    before = (cache / "openphish.urls.txt").read_text()
    [r] = feeds.update_feeds(["openphish"], directory=cache, fetch=failing_fetch)
    assert not r.ok and "kept cache" in r.message
    assert (cache / "openphish.urls.txt").read_text() == before


def test_exact_url_is_deny_and_names_source(cache):
    v = check_url("https://evil-login.vercel.app/secure", feeds=idx(cache))
    r = next(r for r in v.reasons if r.rule_id == "url.known_bad_feed")
    assert v.decision is Decision.deny and "OpenPhish" in r.explanation and r.weight == 100


def test_host_and_parent_matches(cache):
    i = idx(cache)
    v = check_url("https://evil-login.vercel.app/other-page", feeds=i)
    assert next(r for r in v.reasons if r.rule_id == "url.known_bad_feed").weight == 75
    v = check_url("https://www.bad-shop.test/cart", feeds=i)
    r = next(r for r in v.reasons if r.rule_id == "url.known_bad_feed")
    assert r.weight == 50 and "Phishing.Database" in r.explanation
    # parent match does not apply to hosts that only came from URL feeds
    assert "url.known_bad_feed" not in {r.rule_id for r in check_url("https://x.evil-login.vercel.app", feeds=i).reasons}
    assert "url.known_bad_feed" not in {r.rule_id for r in check_url("https://vercel.app", feeds=i).reasons}


def test_shared_host_only_exact_url(cache):
    i = idx(cache)
    assert check_url("https://cdn.discordapp.com/attachments/1/2/bad.zip", feeds=i).decision is Decision.deny
    v = check_url("https://cdn.discordapp.com/attachments/9/9/fine.png", feeds=i)
    assert "url.known_bad_feed" not in {r.rule_id for r in v.reasons}


def test_urlhaus_csv_entry(cache):
    v = check_url("http://203.0.113.9/bin.sh", feeds=idx(cache))
    assert any("URLhaus" in r.explanation for r in v.reasons)


def test_stale_warning(cache):
    i = idx(cache)
    assert check_url("https://example.org", feeds=i).warnings == []
    old = (datetime.now(timezone.utc) - timedelta(hours=30)).isoformat()
    i.fetched_at["openphish"] = old
    assert any("older than" in w for w in check_url("https://example.org", feeds=i).warnings)


def test_no_cache_warning():
    assert any("update-feeds" in w for w in check_url("https://example.org", feeds=feeds.FeedIndex()).warnings)


def test_ignore_list_covers_subdomains(tmp_path):
    d = tmp_path
    (d / "x.txt").write_text("docs.google.com\nlogin.microsoftonline.com\n")
    feeds.update_feeds(["phishing_database_domains"], directory=d, fetch=lambda u: (d / "x.txt").read_text())
    i = idx(d)
    for u in ("https://docs.google.com/forms/d/abc", "https://login.microsoftonline.com/"):
        assert "url.known_bad_feed" not in {r.rule_id for r in check_url(u, feeds=i).reasons}


def test_hook_uses_lazy_lookup_not_full_index(cache, monkeypatch):
    # A short-lived hook process must not load ~400k domains into dicts on every call.
    monkeypatch.setenv(feeds.ENV_CACHE_DIR, str(cache))
    feeds.load_index.cache_clear(); feeds._index_at.cache_clear()
    lazy = feeds.LazyFeedIndex(cache)
    assert bool(lazy)
    for url in ["http://phish.test/paypal/signin.php?x=1", "http://bad-shop.test/", "http://deep.bad-shop.test/a",
                "http://sub.phishy.test/x", "http://phishy.test/login", "https://www.example.com/"]:
        full = idx(cache).lookup(url)
        got = lazy.lookup(url)
        assert (got is None) == (full is None), url
        if full:
            assert (got.kind, sorted(got.feeds), got.matched) == (full.kind, sorted(full.feeds), full.matched)
    assert lazy.stale_feeds() == idx(cache).stale_feeds()


def test_lazy_index_empty_cache_is_falsy(tmp_path):
    assert not feeds.LazyFeedIndex(tmp_path)


def _domain_feed(*domains):
    """A domain feed index listing these domains (as Phishing.Database does)."""
    hosts = {d: ["phishing_database_domains"] for d in domains}
    return feeds.FeedIndex(hosts=dict(hosts), listed_domains=dict(hosts),
                           fetched_at={"phishing_database_domains": datetime.now(timezone.utc).isoformat()})


def test_listing_a_shared_hosting_suffix_does_not_condemn_every_site_on_it():
    # Anyone can create a bucket under s3.amazonaws.com; a feed entry for the suffix isn't about this bucket.
    v = check_url("https://my-bucket.s3.amazonaws.com/report.pdf", feeds=_domain_feed("s3.amazonaws.com"))
    assert "url.known_bad_feed" not in {r.rule_id for r in v.reasons}


def test_a_listed_bucket_on_shared_hosting_is_caught():
    v = check_url("https://bad-bucket.s3.amazonaws.com/index.html", feeds=_domain_feed("bad-bucket.s3.amazonaws.com"))
    assert "url.known_bad_feed" in {r.rule_id for r in v.reasons} and v.decision is Decision.deny


def test_parent_listing_still_covers_subdomains_of_an_ordinary_domain():
    v = check_url("https://login.bad-shop.example/", feeds=_domain_feed("bad-shop.example"))
    assert "url.known_bad_feed" in {r.rule_id for r in v.reasons}


@pytest.mark.parametrize("listed,url", [
    ("cloudapp.azure.com", "https://myvm.eastus.cloudapp.azure.com/"),
    ("eastus.cloudapp.azure.com", "https://myvm.eastus.cloudapp.azure.com/"),
    ("googleusercontent.com", "https://lh3.googleusercontent.com/a/photo.jpg"),
    ("execute-api.us-east-1.amazonaws.com", "https://abc123.execute-api.us-east-1.amazonaws.com/prod"),
])
def test_parent_listing_on_shared_hosting_does_not_condemn_other_customers(listed, url):
    v = check_url(url, feeds=_domain_feed(listed))
    assert "url.known_bad_feed" not in {r.rule_id for r in v.reasons}, (listed, url)


@pytest.mark.parametrize("host", ["myvm.eastus.cloudapp.azure.com", "n-abc-0lu-script.googleusercontent.com"])
def test_exact_host_listing_on_shared_hosting_counts(host):
    v = check_url(f"https://{host}/", feeds=_domain_feed(host))
    assert "url.known_bad_feed" in {r.rule_id for r in v.reasons} and v.decision is Decision.deny


class _Resp:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n=-1):
        return self.body if n < 0 else self.body[:n]


def test_oversized_feed_download_is_refused(monkeypatch):
    import urllib.request

    monkeypatch.setattr(feeds, "MAX_FEED_BYTES", 1000)
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: _Resp(b"x.example\n" * 500))
    with pytest.raises(ValueError):
        feeds._download("https://feed.example/list.txt")


def test_feed_download_under_the_cap_is_read(monkeypatch):
    import urllib.request

    monkeypatch.setattr(feeds, "MAX_FEED_BYTES", 1000)
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: _Resp(b"x.example\n" * 10))
    assert feeds._download("https://feed.example/list.txt") == "x.example\n" * 10
