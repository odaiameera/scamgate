import pytest

from scamgate.engine import check_url
from scamgate.models import Decision
from scamgate.rules.url import levenshtein, normalize_variants, parse


def ids(v):
    return {r.rule_id for r in v.reasons}


def test_blocklist_matches_domain_and_subdomain():
    bl = frozenset({"evil.example"})
    assert "url.blocklist" in ids(check_url("https://evil.example/x", blocklist=bl))
    v = check_url("https://login.evil.example/", blocklist=bl)
    assert "url.blocklist" in ids(v) and v.decision is Decision.deny
    assert "url.blocklist" not in ids(check_url("https://notevil.example/", blocklist=bl))


def test_default_blocklist_file_loads():
    assert check_url("https://crypto-doubler.example").decision is Decision.deny


@pytest.mark.parametrize("url", [
    "https://paypa1.com",           # digit swap
    "https://app1e-support.com",    # digit swap in token
    "https://revoluut.com",         # one edit away
    "https://secure-paypal-help.net",  # brand token on unofficial domain
    "https://paypalsecure.net",     # brand embedded in label
    "https://aib.secure-banking.xyz",  # brand as subdomain
    "https://arnazon.com",          # rn -> m
])
def test_lookalike_brand_fires(url):
    assert "url.lookalike_brand" in ids(check_url(url))


@pytest.mark.parametrize("url", [
    "https://www.paypal.com/signin",
    "https://app.revolut.com",
    "https://onlinebanking.aib.ie",
    "https://www.amazon.co.uk/dp/123",
    "https://www.bankofireland.com",
    "https://dashboard.stripe.com",
    "https://apply.workday.com",     # 'apply' is not 'apple'
    "https://www.boise.gov",         # short brand 'boi' needs an exact token
])
def test_lookalike_brand_does_not_fire_on_official_or_unrelated(url):
    assert "url.lookalike_brand" not in ids(check_url(url))


def test_ip_host():
    assert "url.ip_host" in ids(check_url("http://192.168.10.5/pay"))
    assert "url.ip_host" in ids(check_url("http://[2001:db8::1]/pay"))
    assert "url.ip_host" not in ids(check_url("https://example.com"))


def test_punycode():
    v = check_url("https://xn--pypal-4ve.com/")
    assert {"url.punycode", "url.lookalike_brand"} <= ids(v)
    assert v.decision is Decision.deny


def test_suspicious_tld():
    assert "url.suspicious_tld" in ids(check_url("https://great-deals.top"))
    assert "url.suspicious_tld" not in ids(check_url("https://great-deals.ie"))


def test_intent_mismatch_credentials():
    v = check_url("https://hotel-stay.example/login", intent="book a hotel in Cork")
    assert "url.intent_mismatch" in ids(v)
    v = check_url("https://app.revolut.com/login", intent="log in to Revolut")
    assert "url.intent_mismatch" not in ids(v)
    # No intent given -> credential pages aren't judged
    assert "url.intent_mismatch" not in ids(check_url("https://hotel-stay.example/login"))


def test_intent_mismatch_seed_phrase_always_flagged():
    v = check_url("https://wallet-sync.example/restore?seed-phrase=1")
    assert "url.intent_mismatch" in ids(v)
    assert v.decision is Decision.deny


def test_domain_age_stub_disabled_by_default(monkeypatch):
    from scamgate.rules import url as url_rules

    assert "url.domain_age" not in ids(check_url("https://brand-new.example"))
    # Enabled in config + provider set -> fires
    from scamgate.config import load_config
    cfg = load_config()
    cfg2 = {**cfg, "rules": {**cfg["rules"], "url.domain_age": {"enabled": True, "weight": 30, "min_age_days": 30}}}
    monkeypatch.setattr(url_rules, "domain_age_provider", lambda d: 3)
    assert "url.domain_age" in ids(check_url("https://brand-new.example", config=cfg2))


def test_legit_url_allowed():
    v = check_url("https://www.booking.com/hotel/ie/x.html", intent="book a hotel")
    assert v.decision is Decision.allow and v.risk_score == 0


def test_helpers():
    assert levenshtein("paypal", "paypa") == 1
    assert "paypal" in normalize_variants("paypa1")
    assert parse("https://shop.amazon.co.uk/x").registrable == "amazon.co.uk"
