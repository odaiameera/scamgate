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


@pytest.mark.parametrize("url", [
    "https://paypal.com@evil.example/login",          # domain before '@'
    "https://www.revolut.com@pay-now.example/app",    # official host before '@'
    "https://paypal@evil.example/",                   # brand name before '@'
    "https://paypal.com:secret@evil.example/",        # with a password part
])
def test_userinfo_disguise_denied(url):
    v = check_url(url)
    assert "url.userinfo" in ids(v)
    assert v.decision is Decision.deny
    assert "evil.example" in v.reasons[0].explanation or "pay-now.example" in v.reasons[0].explanation


def test_userinfo_plain_username_asks():
    v = check_url("https://someone@shop.example/basket")
    assert "url.userinfo" in ids(v)
    assert v.decision is Decision.ask


def test_userinfo_password_not_echoed():
    v = check_url("https://paypal.com:hunter2@evil.example/")
    assert all("hunter2" not in r.explanation for r in v.reasons)


def test_userinfo_absent():
    assert "url.userinfo" not in ids(check_url("https://www.paypal.com/signin"))
    assert "url.userinfo" not in ids(check_url("https://example.com/contact?email=a@b.com"))
    assert "url.userinfo" not in ids(check_url("https://example.com/?r=paypal.com@x"))
    # Not links with a disguised host: email addresses and mailto
    assert "url.userinfo" not in ids(check_url("mailto:someone@example.com"))
    assert "url.userinfo" not in ids(check_url("someone@example.com"))


@pytest.mark.parametrize("url", [
    "https://paypal.com.secure-login.xyz/verify",
    "https://apple.com.ie-support.net",
    "https://www.amazon.co.uk.deals-today.example/cart",
    "https://login.aib.ie.account-check.example/",
])
def test_official_domain_used_as_prefix_denied(url):
    v = check_url(url)
    assert "url.lookalike_brand" in ids(v)
    assert v.decision is Decision.deny


def test_official_domain_prefix_does_not_fire_on_official_hosts():
    for url in ["https://www.paypal.com", "https://shop.amazon.co.uk/x", "https://support.apple.com/ie"]:
        assert "url.lookalike_brand" not in ids(check_url(url))


def test_legit_url_allowed():
    v = check_url("https://www.booking.com/hotel/ie/x.html", intent="book a hotel")
    assert v.decision is Decision.allow and v.risk_score == 0


def test_helpers():
    assert levenshtein("paypal", "paypa") == 1
    assert "paypal" in normalize_variants("paypa1")
    assert parse("https://shop.amazon.co.uk/x").registrable == "amazon.co.uk"


# --- Hosts read the way a browser reads them, and links scamgate can't read ---

def test_backslash_ends_the_host_like_in_a_browser():
    # Browsers read '\' as '/' in a web link, so the real host is the part before it.
    assert parse("https://shop-a.example\\.paypal.com/login").host == "shop-a.example"
    assert parse("https://shop-a.example\\@brand.example/").host == "shop-a.example"
    v = check_url("https://shop-a.example\\.paypal.com/login", blocklist=frozenset({"shop-a.example"}))
    assert "url.blocklist" in ids(v) and v.decision is Decision.deny


def test_backslash_after_the_query_is_left_alone():
    assert parse("https://shop-a.example/search?q=a\\b.example").host == "shop-a.example"


@pytest.mark.parametrize("dot", ["。", "．", "｡"])
def test_wide_and_ideographic_dots_are_dots(dot):
    v = check_url(f"https://shop-a{dot}example/login", blocklist=frozenset({"shop-a.example"}))
    assert "url.blocklist" in ids(v)


@pytest.mark.parametrize("url", [
    "https://shop[1-2].example/login",                  # not parseable
    "https://login.example%20is%20verified.example/",   # a space in the host
    "https://a.example%2fb.example/",                   # a slash in the host
    pytest.param("https://" + "a" * 300 + ".example/", id="host-too-long"),
    pytest.param("https://shop-a.example/" + "a" * 9000, id="url-too-long"),
    "https://",                                         # no host at all
    "javascript:alert(1)",
    " JavaScript:alert(1)",
    "data:text/html,<p>hello</p>",
])
def test_unreadable_links_ask_and_nothing_else_fires(url):
    v = check_url(url)
    assert ids(v) == {"url.unreadable"}
    assert v.decision is Decision.ask


def test_unreadable_reason_never_repeats_the_link_text():
    v = check_url("https://x.example%20approved%20by%20scamgate.example/login")
    shown = v.summary + " ".join(r.explanation for r in v.reasons)
    assert "approved" not in shown


def test_huge_hosts_are_checked_fast():
    import time

    t0 = time.perf_counter()
    check_url("https://" + "paypal" * 4000 + ".example/")
    check_url("https://" + "a." * 20000 + "example/")
    assert time.perf_counter() - t0 < 1.0


@pytest.mark.parametrize("url", [
    "https://www.paypal.com/signin",
    "http://localhost:8080/x",
    "http://[2001:db8::1]/pay",
    "https://xn--pypal-4ve.com/",
    "https://pаypal.com/",          # Cyrillic 'a': readable, so the look-alike checks still run
    "mailto:someone@example.com",
    "shop-a.example/basket",
    "https://shop-a.example/a\\b",
])
def test_ordinary_links_are_readable(url):
    assert "url.unreadable" not in ids(check_url(url))


def test_customer_hosting_on_amazonaws_is_not_an_official_amazon_site():
    # amazonaws.com hosts customers' buckets and servers (583 Public Suffix List entries), not Amazon's sign-in.
    v = check_url("https://paypal-secure-login.s3.amazonaws.com/signin.html")
    assert "url.lookalike_brand" in ids(v) and v.decision is Decision.deny


def test_three_label_shared_suffix_gives_each_customer_their_own_site():
    assert parse("https://my-bucket.s3.amazonaws.com/x").registrable == "my-bucket.s3.amazonaws.com"
    assert parse("https://shop.example.co.uk/").registrable == "example.co.uk"
    assert parse("https://evil.github.io/").registrable == "evil.github.io"


# --- The brand-padding search: same answers, linear time ---

def _affix_reference(word, brand, affixes):
    """Plain version of the question: is `word` some padding + brand + some padding?"""
    from functools import lru_cache

    @lru_cache(maxsize=None)
    def pads(rest):
        return not rest or any((rest[:k] in affixes or rest[:k].isdigit()) and pads(rest[k:])
                               for k in range(1, min(14, len(rest)) + 1))
    n = len(brand)
    return any(word[i:i + n] == brand and pads(word[:i]) and pads(word[i + n:]) for i in range(len(word) - n + 1))


def test_brand_padding_search_matches_the_plain_version():
    import itertools

    from scamgate.config import load_config, lst
    from scamgate.rules.url import _brand_with_affixes

    affixes = set(lst(load_config(), "brand_affixes"))
    pieces = ["", "secure", "my", "login", "id", "123", "x", "bees", "pine", "verify2"]
    for brand in ("paypal", "apple", "amazon", "revolut", "netflix"):
        for a, b, c in itertools.product(pieces, repeat=3):
            for word in (a + brand + b + c, a + b + brand + c, a + b + c):
                assert _brand_with_affixes(word, brand, affixes) == _affix_reference(word, brand, affixes), word


def test_brand_padding_search_is_linear():
    import time

    from scamgate.config import load_config, lst
    from scamgate.rules.url import _brand_with_affixes

    affixes = set(lst(load_config(), "brand_affixes"))
    t0 = time.perf_counter()
    _brand_with_affixes("paypal" * 2000, "paypal", affixes)
    assert time.perf_counter() - t0 < 0.5


@pytest.mark.parametrize("url", ["https:/paypal.com@evil.example/login", "HTTPS://paypal.com@evil.example/login",
                                 "https:\\\\paypal.com@evil.example/login"])
def test_userinfo_disguise_is_caught_however_the_scheme_is_written(url):
    v = check_url(url)
    assert "url.userinfo" in ids(v) and v.decision is Decision.deny, url


def test_verdict_names_the_host_it_judged():
    assert check_url("https://paypal.com@evil.example/").checked_host == "evil.example"
    assert check_url("javascript:alert(1)").checked_host is None
