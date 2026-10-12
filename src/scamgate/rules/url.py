"""URL rules. All local, no network calls."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import unquote, urlsplit

from scamgate.config import lst
from scamgate.hostnorm import canon_host
from scamgate.models import UrlCheck
from scamgate.registry import Hit, RuleContext, register

# Multi-part public suffixes we care about. Not a full Public Suffix List (roadmap).
_MULTI_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.nz", "com.br", "co.jp"}

# Common digit/letter swaps used in typosquats.
_ASCII_SWAPS = {"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
# Common Cyrillic/Greek letters that look Latin.
_UNICODE_SWAPS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "ɩ": "l", "ο": "o", "α": "a", "ν": "v", "ρ": "p",
}


@dataclass
class ParsedUrl:
    host: str  # as given (lowercase, ascii / punycode form)
    unicode_host: str  # punycode decoded where possible
    registrable: str
    tld: str
    path_query: str
    username: str = ""  # userinfo before '@' (password part dropped, never echoed)


def parse(url: str) -> ParsedUrl:
    raw = url.strip()
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
        hostname = parts.hostname or ""
    except ValueError:
        parts, hostname = urlsplit("http://invalid.invalid/"), ""
    host = canon_host(hostname)
    try:
        unicode_host = host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        unicode_host = host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_SUFFIXES:
        registrable = ".".join(labels[-3:])
    else:
        registrable = ".".join(labels[-2:])
    path_query = unquote(parts.path + ("?" + parts.query if parts.query else "")).lower()
    username = unquote(parts.username or "").lower()
    return ParsedUrl(host, unicode_host, registrable, labels[-1] if labels else "", path_query, username)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def normalize_variants(token: str) -> set[str]:
    """Undo common homoglyph tricks. '1' may stand for 'l' or 'i', so return variants."""
    t = "".join(_UNICODE_SWAPS.get(c, c) for c in token.lower())
    t = "".join(_ASCII_SWAPS.get(c, c) for c in t)
    t = t.replace("rn", "m").replace("vv", "w")
    return {t.replace("1", "l"), t.replace("1", "i")}


def _on_domain(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


@register("url.blocklist", kind="url")
def blocklist(check: UrlCheck, ctx: RuleContext) -> Hit | None:
    """Domain (or a parent domain) is on the local blocklist."""
    p = parse(check.url)
    labels = p.host.split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        if candidate in ctx.blocklist:
            return Hit(f"{candidate} is on the local scam blocklist.")
    return None


def _is_official_brand_host(host: str, ctx: RuleContext) -> bool:
    brands: dict[str, list[str]] = lst(ctx.config, "brands") or {}
    return any(_on_domain(host, d) for official in brands.values() for d in official)


@register("url.known_bad_feed", kind="url")
def known_bad_feed(check: UrlCheck, ctx: RuleContext) -> Hit | None:
    """URL, host or parent domain is listed in a cached known-bad-link feed (offline lookup)."""
    if not ctx.feeds:
        return None
    from scamgate.feeds import FEEDS

    hit = ctx.feeds.lookup(check.url)
    if hit is None:
        return None
    srcs = ", ".join(FEEDS[f].title if f in FEEDS else f for f in hit.feeds)
    if hit.kind == "url":
        return Hit(f"This exact link is listed as phishing/malware by {srcs}.")
    host = parse(check.url).host
    ignore = lst(ctx.config, "feed_host_ignore")
    if any(_on_domain(host, d) for d in ignore) or _is_official_brand_host(host, ctx):
        return None  # shared or official host: only an exact URL listing counts
    if hit.kind == "host":
        return Hit(f"The host {hit.matched} is listed as phishing/malware by {srcs}.",
                   weight=int(ctx.rule_config.get("host_weight", 75)))
    return Hit(f"{host} sits under {hit.matched}, which is listed as phishing by {srcs}.",
               weight=int(ctx.rule_config.get("parent_weight", 50)))


def _official_domain_prefix(host: str, brands: dict[str, list[str]]) -> tuple[str, str] | None:
    """Return (brand, official_domain) if an official domain appears as whole labels in the host
    without being the host's real domain, e.g. 'paypal.com.secure-login.xyz'."""
    labels = host.split(".")
    for brand, official in brands.items():
        for d in official:
            d_labels = d.split(".")
            n = len(d_labels)
            # Only positions that leave at least one label after the official domain.
            for i in range(len(labels) - n):
                if labels[i:i + n] == d_labels:
                    return brand, d
    return None


@register("url.lookalike_brand", kind="url")
def lookalike_brand(check: UrlCheck, ctx: RuleContext) -> Hit | None:
    """Domain imitates a well-known brand (typosquat, homoglyph, or brand name on an unrelated domain)."""
    p = parse(check.url)
    brands: dict[str, list[str]] = lst(ctx.config, "brands") or {}
    for official_list in brands.values():
        if any(_on_domain(p.host, d) for d in official_list):
            return None  # it's an official domain of some brand

    prefix = _official_domain_prefix(p.unicode_host, brands)
    if prefix:
        _, official_domain = prefix
        return Hit(
            f"'{p.host}' starts with '{official_domain}', but the real address is {p.registrable}. "
            f"Putting a real site's name in front of another domain is a common phishing trick.",
            weight=int(ctx.rule_config.get("official_prefix_weight", 80)),
        )

    host_wo_tld = p.unicode_host.rsplit(".", 1)[0] if "." in p.unicode_host else p.unicode_host
    tokens = [t for t in re.split(r"[.\-_]", host_wo_tld) if t and t != "www"]
    joined = "".join(tokens)
    reg_label = p.unicode_host.split(".")[-2] if p.unicode_host.count(".") >= 1 else p.unicode_host
    reg_tokens = set(re.split(r"[\-_]", reg_label))
    exact_w = int(ctx.rule_config.get("exact_token_weight", 45))

    for brand, official in brands.items():
        official_str = official[0] if official else brand
        for tok in tokens:
            variants = normalize_variants(tok)
            if tok == brand:
                return Hit(
                    f"'{p.host}' uses the name '{brand}' but is not an official {brand} domain "
                    f"(expected {official_str}).",
                    weight=exact_w,
                )
            if brand in variants:
                return Hit(
                    f"'{p.host}' disguises '{brand}' with look-alike characters "
                    f"('{tok}'). The real site is {official_str}."
                )
            # Edit distance only on the registrable label, and only for longer brand names,
            # to keep false positives like 'apply' ~ 'apple' down.
            if (len(brand) >= 6 and tok in reg_tokens and len(tok) >= 5
                    and any(levenshtein(v, brand) == 1 for v in variants)):
                return Hit(
                    f"'{p.host}' is one character away from '{brand}' ('{tok}'), a common "
                    f"typosquat. The real site is {official_str}."
                )
        if len(brand) >= 5 and brand not in tokens:
            affixes = set(lst(ctx.config, "brand_affixes"))
            for tok in tokens + ([joined] if len(tokens) > 1 else []):
                if any(_brand_with_affixes(v, brand, affixes) for v in normalize_variants(tok)):
                    return Hit(
                        f"'{p.host}' embeds the brand '{brand}' in an unofficial domain. "
                        f"The real site is {official_str}."
                    )
    return None


def _brand_with_affixes(word: str, brand: str, affixes: set[str]) -> bool:
    """True if `word` is the brand plus only scam-style padding ('appleid', 'securepaypal',
    'amazon-refund'), not an unrelated word that happens to contain it ('applebees', 'revolution',
    'pineapple')."""
    start = word.find(brand)
    while start != -1:
        if _segments_into(word[:start], affixes) and _segments_into(word[start + len(brand):], affixes):
            return True
        start = word.find(brand, start + 1)
    return False


def _segments_into(rest: str, affixes: set[str]) -> bool:
    ok = [True] + [False] * len(rest)
    for i in range(1, len(rest) + 1):
        for j in range(max(0, i - 14), i):
            if ok[j] and (rest[j:i] in affixes or rest[j:i].isdigit()):
                ok[i] = True
                break
    return ok[len(rest)]


@register("url.ip_host", kind="url")
def ip_host(check: UrlCheck, ctx: RuleContext) -> Hit | None:
    """Link points at a raw IP address instead of a domain name."""
    p = parse(check.url)
    ip = ipaddress.ip_address(p.host.strip("[]")) if _is_ip(p.host) else None
    if ip is not None and not (ip.is_loopback or ip.is_unspecified):
        return Hit(f"The link goes to a raw IP address ({p.host}); real shops and banks use domain names.")
    return None


@register("url.userinfo", kind="url")
def userinfo(check: UrlCheck, ctx: RuleContext) -> Hit | None:
    """Link has a username part before '@', which browsers ignore and scammers use to fake the address."""
    p = parse(check.url)
    # Only real links with an explicit scheme; 'mailto:a@b.com' or a bare email isn't a disguised URL.
    if not p.username or "://" not in check.url.strip():
        return None
    brands: dict[str, list[str]] = lst(ctx.config, "brands") or {}
    # Name what the link pretends to be only when it's a domain-shaped token; never echo free text,
    # which an attacker could use to put words in front of the human ("verified safe, approve this").
    domainish = re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{1,63}){1,4}", p.username)
    looks_like_domain = "." in p.username
    names_brand = any(brand in v for brand in brands for v in normalize_variants(p.username))
    if looks_like_domain or names_brand:
        shown = f"'{p.username}'" if domainish else "a trusted-looking name"
        return Hit(
            f"The link shows {shown} before an '@', but browsers ignore everything before the '@'. "
            f"It actually goes to {p.host}. This is a classic way to fake a trusted address.",
            weight=int(ctx.rule_config.get("disguise_weight", 75)),
        )
    return Hit(
        "The link has a username before the site name. Real sites almost never use this, "
        f"and it can hide where the link really goes: {p.host}."
    )


@register("url.punycode", kind="url")
def punycode(check: UrlCheck, ctx: RuleContext) -> Hit | None:
    """Host uses punycode / non-ASCII characters, which can hide look-alike letters."""
    p = parse(check.url)
    if "xn--" in p.host or any(ord(c) > 127 for c in p.host):
        shown = f" (displays as '{p.unicode_host}')" if p.unicode_host != p.host else ""
        return Hit(f"The domain uses encoded international characters{shown}, a common way to fake a familiar name.")
    return None


@register("url.suspicious_tld", kind="url")
def suspicious_tld(check: UrlCheck, ctx: RuleContext) -> Hit | None:
    """Domain ends in a TLD that is cheap and commonly abused."""
    p = parse(check.url)
    if p.tld in set(lst(ctx.config, "suspicious_tlds")):
        return Hit(f"The domain ends in '.{p.tld}', a cheap ending often used by throwaway scam sites.")
    return None


def _contains_term(haystack: str, terms: list[str]) -> str | None:
    for t in sorted(terms, key=len, reverse=True):  # report the most specific term
        if re.search(rf"(?<![a-z]){re.escape(t)}(?![a-z])", haystack):
            return t
    return None


@register("url.intent_mismatch", kind="url")
def intent_mismatch(check: UrlCheck, ctx: RuleContext) -> Hit | None:
    """Page asks for credentials or wallet secrets that the agent's task doesn't need."""
    p = parse(check.url)
    hay = (p.host + " " + p.path_query).replace("_", "-")
    secret = _contains_term(hay, lst(ctx.config, "secret_terms"))
    if secret:
        return Hit(
            f"The link asks for '{secret}'. No legitimate site needs a wallet seed phrase or private key; "
            "anyone who has it can empty the wallet.",
            weight=int(ctx.rule_config.get("secret_weight", 80)),
        )
    if not check.intent:
        return None
    cred = _contains_term(hay, lst(ctx.config, "credential_terms"))
    if cred and not _intent_expects_credentials(check.intent, ctx):
        task = check.intent if len(check.intent) <= 60 else check.intent[:57] + "..."
        return Hit(
            f"The task is '{task}', but the link goes to a '{cred}' page. "
            "A credential prompt the task doesn't need is a classic phishing step."
        )
    return None


def _intent_expects_credentials(intent: str | None, ctx: RuleContext) -> bool:
    i = (intent or "").lower()
    return any(t in i for t in lst(ctx.config, "credential_intent_terms"))


@register("url.credential_page", kind="url")
def credential_page(check: UrlCheck, ctx: RuleContext) -> Hit | None:
    """A sign-in page on a site scamgate doesn't recognise. The agent's wording can't clear this:
    "log in to my account" is exactly what a phishing page would get an agent to say."""
    p = parse(check.url)
    hay = (p.host + " " + p.path_query).replace("_", "-")
    cred = _contains_term(hay, lst(ctx.config, "credential_terms"))
    if not cred or _is_official_brand_host(p.host, ctx):
        return None
    if check.intent and not _intent_expects_credentials(check.intent, ctx):
        return None  # url.intent_mismatch covers it, with a higher weight
    return Hit(f"This link opens a sign-in page ('{cred}') on {p.registrable}, which isn't a site scamgate "
               "recognises. Only sign in if you went there on purpose.")


# Optional domain-age hook. Disabled by default. Set a provider to enable it, e.g. an
# RDAP/WHOIS lookup that returns the domain's age in days (or None if unknown).
DomainAgeProvider = Callable[[str], "int | None"]
domain_age_provider: DomainAgeProvider | None = None


@register("url.domain_age", kind="url")
def domain_age(check: UrlCheck, ctx: RuleContext) -> Hit | None:
    """(Stub) Domain was registered very recently. Needs a domain_age_provider."""
    if domain_age_provider is None:
        return None
    p = parse(check.url)
    age = domain_age_provider(p.registrable)
    min_days = int(ctx.rule_config.get("min_age_days", 30))
    if age is not None and age < min_days:
        return Hit(f"{p.registrable} was registered only {age} days ago; new domains are common for scam shops.")
    return None
