"""RDAP domain age: off by default, cache-only or live by opt-in, never a network call in tests."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from scamgate import domainage, engine
from scamgate.models import Decision

BOOT = json.dumps({"services": [[["com", "net"], ["https://rdap.example-registry.test/"]],
                                [["shop"], ["http://x.test/", "https://rdap.shop.test/v1/"]]]})


def rdap(days_old):
    when = (datetime.now(timezone.utc) - timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return json.dumps({"objectClassName": "domain", "events": [{"eventAction": "registration", "eventDate": when},
                                                                {"eventAction": "last changed", "eventDate": when}]})


class Fake:
    def __init__(self, age=5, fail=False):
        self.calls, self.age, self.fail = [], age, fail

    def __call__(self, url):
        self.calls.append(url)
        if url == domainage.BOOTSTRAP_URL:
            return BOOT
        if self.fail:
            raise OSError("down")
        return rdap(self.age)


@pytest.fixture
def live(monkeypatch):
    monkeypatch.setenv(domainage.ENV_RDAP, "live")
    f = Fake()
    monkeypatch.setattr(domainage, "_http_get", f)
    return f


def test_off_by_default_makes_no_calls(monkeypatch):
    monkeypatch.delenv(domainage.ENV_RDAP, raising=False)
    monkeypatch.setattr(domainage, "_http_get", lambda u: pytest.fail("network call"))
    v = engine.check_url("https://brand-new-shop.com/")
    assert "url.domain_age" not in {r.rule_id for r in v.reasons}


def test_live_new_domain_fires_and_caches(live):
    v = engine.check_url("https://brand-new-shop.com/cart")
    assert "url.domain_age" in {r.rule_id for r in v.reasons} and v.decision is Decision.ask
    assert live.calls == [domainage.BOOTSTRAP_URL, "https://rdap.example-registry.test/domain/brand-new-shop.com"]
    engine.check_url("https://www.brand-new-shop.com/")
    assert len(live.calls) == 2  # cached


def test_old_domain_is_quiet(live):
    live.age = 4000
    assert "url.domain_age" not in {r.rule_id for r in engine.check_url("https://old-shop.com/").reasons}


def test_cache_mode_reads_but_never_fetches(live, monkeypatch):
    engine.check_url("https://brand-new-shop.com/")
    monkeypatch.setenv(domainage.ENV_RDAP, "cache")
    monkeypatch.setattr(domainage, "_http_get", lambda u: pytest.fail("network call"))
    assert "url.domain_age" in {r.rule_id for r in engine.check_url("https://brand-new-shop.com/").reasons}
    assert "url.domain_age" not in {r.rule_id for r in engine.check_url("https://unseen-shop.com/").reasons}


def test_failures_mean_no_answer_and_are_cached_briefly(live):
    live.fail = True
    assert domainage.lookup("down-shop.com") is None
    n = len(live.calls)
    assert domainage.lookup("down-shop.com") is None and len(live.calls) == n


def test_https_registry_preferred(live):
    domainage.lookup("x.shop")
    assert live.calls[-1] == "https://rdap.shop.test/v1/domain/x.shop"


def test_unknown_tld_is_no_answer(live):
    assert domainage.lookup("x.unknowntld") is None


@pytest.mark.parametrize("url", ["https://www.paypal.com/", "https://docs.google.com/x", "http://203.0.113.9/",
                                 "http://localhost:8000/"])
def test_official_shared_and_ip_hosts_are_never_looked_up(live, url):
    engine.check_url(url)
    assert live.calls == []


def test_registration_date_parsing():
    assert domainage.registration_date(rdap(10)) is not None
    assert domainage.registration_date("not json") is None
    assert domainage.registration_date(json.dumps({"events": [{"eventAction": "expiration"}]})) is None


@pytest.mark.parametrize("domain", ["a/b.example", "a?b.example", "a b.example", "a#b.example", "a@b.example"])
def test_only_host_names_are_sent_to_the_registry(live, domain):
    assert domainage.lookup(domain, live=True) is None
    assert live.calls == []


def test_international_domains_are_looked_up_in_ascii_form(live):
    assert domainage.lookup("bücher.com", live=True) == 5
    assert any(u.endswith("domain/xn--bcher-kva.com") for u in live.calls), live.calls


def test_names_the_old_idna_rules_would_change_are_not_looked_up(live):
    # Python's codec turns 'faß' into 'fass', a different domain; no answer beats a wrong one.
    assert domainage.lookup("faß.com", live=True) is None
    assert live.calls == []
