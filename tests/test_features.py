"""Unit tests for feature extraction and rules. These don't need trained models."""
import qrcode
import io

from phishshield.qr import classify_payload, decode_qr, payload_red_flags
from phishshield.red_flags import header_red_flags, parse_email, text_red_flags
from phishshield.text_utils import extract_urls, normalize_email, normalize_sms
from phishshield.url_features import FEATURE_NAMES, extract_features, normalize_url, registered_domain, url_red_flags


def titles(flags):
    return {f["title"] for f in flags}


def test_normalize_url_strips_scheme_and_www():
    assert normalize_url("HTTPS://www.Example.com/Login") == "example.com/login"
    assert normalize_url("example.com") == "example.com"


def test_registered_domain_handles_two_level_suffix():
    assert registered_domain("login.bank.co.uk") == "bank.co.uk"
    assert registered_domain("paypal.com.evil.xyz") == "evil.xyz"


def test_feature_vector_length():
    assert len(extract_features("http://a.b.c/d?e=f")) == len(FEATURE_NAMES)


def test_url_flags_detect_ip_brand_and_at():
    flags = titles(url_red_flags("http://192.168.1.10/paypal/login"))
    assert "IP address instead of domain" in flags
    assert any("paypal" in t for t in flags)
    assert "'@' symbol in URL" in titles(url_red_flags("http://google.com@evil.com/"))


def test_url_flags_clean_for_legit_site():
    assert not [f for f in url_red_flags("https://docs.python.org/3/") if f["severity"] == "high"]


def test_extract_urls():
    assert extract_urls("go to http://x.com/a, or www.y.org.") == ["http://x.com/a", "www.y.org"]


def test_normalizers():
    assert "urltoken" in normalize_sms("Click http://x.com now")
    assert normalize_email("The Account, IS suspended!") == "account suspended"


def test_text_red_flags():
    flags = titles(text_red_flags("URGENT: your account will be suspended. Share the OTP to verify your account."))
    assert {"Urgency / pressure", "Threat of loss / account suspension", "Request for credentials / OTP"} <= flags
    assert text_red_flags("See you at lunch tomorrow") == []


def test_email_header_spoofing():
    raw = ("From: \"PayPal\" <alerts@gmail.com>\nReply-To: x@evil.ru\n"
           "Authentication-Results: mx; spf=fail; dkim=fail\nSubject: hi\n\nbody")
    flags = titles(header_red_flags(parse_email(raw)))
    assert "Reply-To differs from sender" in flags
    assert "Sender claims to be 'paypal'" in flags
    assert "DKIM check failed" in flags


def test_qr_roundtrip_and_upi_classification():
    buf = io.BytesIO()
    payload = "upi://pay?pa=a@okaxis&pn=X&am=100&tn=refund"
    qrcode.make(payload).save(buf, format="PNG")
    assert decode_qr(buf.getvalue()) == [payload]
    info = classify_payload(payload)
    assert info["type"] == "upi" and info["data"]["amount"] == "100"
    assert any("SENDS money" in f["title"] for f in payload_red_flags(info))


def test_qr_payload_types():
    assert classify_payload("WIFI:S:Cafe;T:nopass;;")["type"] == "wifi"
    assert classify_payload("https://x.com")["type"] == "url"
    assert classify_payload("hello world")["type"] == "text"
