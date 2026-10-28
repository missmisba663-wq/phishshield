"""Lexical URL feature engineering + human-readable red flags.

Only lexical features are used (no DNS/WHOIS/page fetch), so analysis is
instant, works offline and never visits a potentially malicious site.
"""
import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "link",
    "country", "kim", "loan", "men", "review", "stream", "download", "racing", "win",
    "bid", "date", "faith", "party", "science", "trade", "accountant", "cricket", "rest",
    "fit", "buzz", "monster", "cam", "icu", "support", "live", "online", "site", "info",
}
SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly",
    "bitly.com", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "s.id", "t.ly",
}
PHISH_WORDS = [
    "login", "logon", "signin", "sign-in", "verify", "verification", "account", "update",
    "secure", "security", "bank", "confirm", "password", "webscr", "ebayisapi", "suspend",
    "unlock", "billing", "wallet", "invoice", "payment", "recover", "support", "authenticate",
]
BRANDS = [
    "paypal", "apple", "microsoft", "office365", "outlook", "google", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "linkedin", "dropbox", "chase", "wellsfargo",
    "bankofamerica", "hsbc", "sbi", "icici", "hdfc", "paytm", "dhl", "fedex", "usps", "ebay",
    "adobe", "docusign", "coinbase", "binance", "metamask", "steam", "irs",
]
# Domains that legitimately host brand names; prevents false brand-impersonation flags.
_TWO_LEVEL_SUFFIXES = {"co.uk", "co.in", "com.au", "co.jp", "com.br", "org.uk", "gov.uk", "ac.in", "co.za", "com.cn"}


def normalize_url(url: str) -> str:
    """Strip scheme and leading 'www.' so the model learns from the URL
    structure itself rather than from how the dataset happened to store it."""
    url = (url or "").strip()
    url = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", url)
    url = re.sub(r"^www\d?\.", "", url, flags=re.IGNORECASE)
    return url.lower()


def url_tokens(url: str) -> list[str]:
    """Word-level tokens of a URL (domain labels, path words, parameters)."""
    return [t for t in re.split(r"[^a-z0-9]+", url) if t]


def split_url(url: str):
    """Return (host, path_and_query) for a URL with or without a scheme."""
    raw = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower()
        rest = parts.path + (("?" + parts.query) if parts.query else "")
        port = parts.port
    except ValueError:
        host, rest, port = "", raw, None
    return host, rest, port


def registered_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"(0x[0-9a-f]+|\d+)", host))  # hex / decimal encoded IPs


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "num_dots_host", "num_subdomains",
    "num_hyphens", "num_digits_ratio", "has_at", "has_ip", "has_port", "num_special",
    "suspicious_tld", "phish_word_count", "brand_in_subdomain_or_path", "host_entropy",
    "has_punycode", "double_slash_in_path", "num_query_params", "is_shortener",
    "num_path_segments", "has_hex_encoding", "longest_token",
]


def extract_features(url: str) -> list[float]:
    norm = normalize_url(url)
    host, rest, port = split_url(norm)
    reg = registered_domain(host)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    sub = host[: -len(reg)].rstrip(".") if host.endswith(reg) else ""
    lower = norm
    tokens = re.split(r"[/.?=&_-]", lower)
    brand_elsewhere = any(b in (sub + rest) and b not in reg for b in BRANDS)
    return [
        len(norm),
        len(host),
        len(rest),
        host.count("."),
        max(0, len(host.split(".")) - 2),
        norm.count("-"),
        sum(c.isdigit() for c in norm) / max(1, len(norm)),
        int("@" in norm),
        int(is_ip(host)),
        int(port is not None),
        sum(not c.isalnum() for c in norm),
        int(tld in SUSPICIOUS_TLDS),
        sum(w in lower for w in PHISH_WORDS),
        int(brand_elsewhere),
        shannon_entropy(host),
        int("xn--" in host),
        int("//" in rest),
        rest.count("&") + (1 if "?" in rest else 0),
        int(host in SHORTENERS or reg in SHORTENERS),
        rest.count("/"),
        int(bool(re.search(r"%[0-9a-f]{2}", lower))),
        max((len(t) for t in tokens), default=0),
    ]


class URLFeatures(BaseEstimator, TransformerMixin):
    """sklearn transformer: raw URL strings -> scaled numeric feature matrix."""

    def fit(self, X, y=None):
        feats = np.array([extract_features(u) for u in X], dtype=float)
        self.mean_ = feats.mean(axis=0)
        self.std_ = feats.std(axis=0) + 1e-9
        return self

    def transform(self, X):
        feats = np.array([extract_features(u) for u in X], dtype=float)
        return (feats - self.mean_) / self.std_

    def get_feature_names_out(self, input_features=None):
        return np.array([f"feat:{n}" for n in FEATURE_NAMES])


def url_red_flags(url: str) -> list[dict]:
    """Rule-based indicators shown to the user alongside the ML verdict."""
    flags = []
    norm = normalize_url(url)
    host, rest, port = split_url(norm)
    reg = registered_domain(host)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""

    def add(severity, title, detail):
        flags.append({"severity": severity, "title": title, "detail": detail})

    if not url.lower().startswith("https://") and "://" in url:
        add("medium", "No HTTPS", "The link is not encrypted. Legitimate login pages always use HTTPS.")
    if is_ip(host):
        add("high", "IP address instead of domain", f"The link points to a raw IP ({host}), a common trick to hide the real owner.")
    if "@" in norm:
        add("high", "'@' symbol in URL", "Browsers ignore everything before '@', so the visible domain may be fake.")
    if "xn--" in host:
        add("high", "Punycode / look-alike characters", "The domain uses encoded characters that can imitate a real brand (homograph attack).")
    for b in BRANDS:
        if b in host.replace(reg, "") + rest and b not in reg:
            add("high", f"Brand name '{b}' outside the real domain",
                f"'{b}' appears in the link, but the actual domain is '{reg}'. This is classic brand impersonation.")
            break
    if host in SHORTENERS or reg in SHORTENERS:
        add("medium", "URL shortener", "Shortened links hide the final destination. Expand them before clicking.")
    if tld in SUSPICIOUS_TLDS:
        add("medium", f"High-risk top-level domain (.{tld})", "This TLD is cheap and heavily abused in phishing campaigns.")
    if host.count(".") >= 4:
        add("medium", "Too many subdomains", f"'{host}' is deeply nested; attackers use this to push the real domain out of view.")
    if port:
        add("medium", "Non-standard port", f"The link uses port {port}, which is unusual for public websites.")
    words = [w for w in PHISH_WORDS if w in norm]
    if words:
        add("low", "Credential-related keywords", "Contains: " + ", ".join(words[:5]))
    if len(norm) > 100:
        add("low", "Very long URL", f"{len(norm)} characters long. Long URLs are often used to hide the real domain.")
    if norm.count("-") >= 4:
        add("low", "Many hyphens", "Domains like secure-login-verify-account.com are typical of phishing kits.")
    return flags
