"""Brand pack and suffix list: catch impersonation of common phishing targets without flagging normal sites."""

import pytest

from scamgate import engine
from scamgate.models import Decision
from scamgate.rules.url import parse


@pytest.mark.parametrize("domain", [
    "rnicrosoft-login.com", "micros0ft.com", "outlook-verify.net", "secure-netflix-billing.com", "netf1ix.com",
    "faceb00k.com", "instagram-verify.com", "linkedin-jobs-verify.com", "docusign-review.net",
    "coinbase-support.com", "metamask-restore.io", "anpost-redelivery.info", "royalmail-fee.com", "evri-parcel.com",
    "dhl-parcel-fee.com", "hmrc-refund.com", "ptsb-secure.ie", "bankofireland-secure.com", "barclays-verify.co.uk",
    "monzo-help.app", "klarna-pay.click", "ryanair-refund.com", "aerlingus-claim.net",
])
def test_brand_pack_catches_impersonation(domain):
    assert engine.check_url(f"https://{domain}/").decision is not Decision.allow, domain


@pytest.mark.parametrize("domain", [
    "www.microsoft.com", "login.microsoftonline.com", "outlook.live.com", "www.netflix.com", "www.anpost.ie",
    "www.ptsb.ie", "www.ryanair.com", "www.aerlingus.com", "www.royalmail.com", "www.hmrc.gov.uk",
    "finance.yahoo.com", "cooking.nytimes.com", "lookingglass.com", "tokenomics.io", "venuefinder.com",
    "netflixtechblog.com", "outlookindia.com", "dhlexpresscareers.com", "corkairport.com", "rte.ie",
])
def test_brand_pack_leaves_real_and_unrelated_sites_alone(domain):
    v = engine.check_url(f"https://{domain}/")
    assert "url.lookalike_brand" not in {r.rule_id for r in v.reasons}, (domain, v.reasons)


@pytest.mark.parametrize("host,registrable", [
    ("evil.github.io", "evil.github.io"), ("shop.co.uk", "shop.co.uk"), ("a.b.vercel.app", "b.vercel.app"),
    ("www.amazon.co.uk", "amazon.co.uk"), ("x.com.jo", "x.com.jo"), ("site.netlify.app", "site.netlify.app"),
    ("www.example.com", "example.com"),
])
def test_registrable_domain_uses_suffix_list(host, registrable):
    assert parse(f"https://{host}/").registrable == registrable


# Shared hosting: each hostname under these suffixes belongs to a different customer or user.

@pytest.mark.parametrize("url", [
    "https://paypal-verify-0lu-script.googleusercontent.com/exec",
    "https://paypal-login.eastus.cloudapp.azure.com/signin",
    "https://paypal-login.s3.amazonaws.com/signin",
])
def test_brand_name_on_shared_hosting_is_not_official(url):
    v = engine.check_url(url)
    assert "url.lookalike_brand" in {r.rule_id for r in v.reasons} and v.decision is not Decision.allow, url


def test_sign_in_page_on_a_customer_vm_is_not_official():
    v = engine.check_url("https://myvm.eastus.cloudapp.azure.com/signin")
    assert "url.credential_page" in {r.rule_id for r in v.reasons}


def test_microsofts_own_azure_hosts_stay_official():
    for url in ("https://portal.azure.com/", "https://portal.azure.com/signin", "https://management.azure.com/"):
        v = engine.check_url(url)
        assert v.decision is Decision.allow and not v.reasons, (url, v.reasons)
