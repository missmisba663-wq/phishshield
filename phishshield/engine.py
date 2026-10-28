"""PhishShield detection engine: one entry point per channel.

Every analysis returns the same structure, so the web UI, REST API and CLI
can render any channel identically:

    {channel, verdict, risk_score, ml_probability, red_flags[], explanation[], details{}}
"""
import sys
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib  # noqa: E402
import numpy as np  # noqa: E402

from config import MODEL_DIR, THRESHOLD_PHISHING, THRESHOLD_SUSPICIOUS  # noqa: E402

from .qr import classify_payload, decode_qr, payload_red_flags  # noqa: E402
from .red_flags import header_red_flags, parse_email, text_red_flags  # noqa: E402
from .text_utils import extract_urls  # noqa: E402
from .url_features import registered_domain, split_url, normalize_url, url_red_flags  # noqa: E402

SEVERITY_POINTS = {"high": 10, "medium": 5, "low": 2}
MAX_FLAG_POINTS = 25

# Very small reputation list. Real deployments would use Tranco/Umbrella top-1M plus threat feeds.
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com", "wikipedia.org",
    "amazon.com", "amazon.in", "apple.com", "microsoft.com", "live.com", "office.com", "linkedin.com",
    "github.com", "netflix.com", "paypal.com", "twitter.com", "x.com", "yahoo.com", "bing.com",
    "reddit.com", "stackoverflow.com", "kaggle.com", "python.org", "flipkart.com", "sbi.co.in",
    "onlinesbi.sbi", "icicibank.com", "hdfcbank.com", "irctc.co.in", "gov.in", "nic.in", "zoom.us",
    "dropbox.com", "adobe.com", "openai.com", "anthropic.com", "claude.ai", "spotify.com", "paytm.com",
}


@lru_cache(maxsize=None)
def load_model(channel: str):
    path = MODEL_DIR / f"{channel}_model.joblib"
    if not path.exists():
        raise FileNotFoundError(
            f"Model '{path.name}' not found. Run: python scripts/download_data.py && python -m training.train_all")
    return joblib.load(path)


def _weights(clf):
    if hasattr(clf, "coef_"):
        return np.asarray(clf.coef_).ravel()
    if hasattr(clf, "calibrated_classifiers_"):
        return np.mean([np.asarray(c.estimator.coef_).ravel() for c in clf.calibrated_classifiers_], axis=0)
    if hasattr(clf, "feature_log_prob_"):
        return clf.feature_log_prob_[1] - clf.feature_log_prob_[0]
    return None


@lru_cache(maxsize=None)
def _feature_names(channel):
    return load_model(channel).named_steps["features"].get_feature_names_out()


def _pretty(name: str) -> str:
    kind, _, token = name.partition("__")
    if kind == "chars":
        return f"pattern “{token.strip()}”"
    if kind == "lexical":
        return token.replace("feat:", "").replace("_", " ")
    return f"“{token}”"


def explain(channel: str, text: str, k: int = 8) -> list[dict]:
    """Per-prediction explanation for linear models: contribution = tf-idf value x weight."""
    model = load_model(channel)
    w = _weights(model.named_steps["clf"])
    if w is None:
        return []
    x = model.named_steps["features"].transform([text])
    x = x.tocsr() if hasattr(x, "tocsr") else x
    row = x.getrow(0) if hasattr(x, "getrow") else x
    idx, vals = row.indices, row.data
    contrib = vals * w[idx]
    names = _feature_names(channel)
    order = np.argsort(-np.abs(contrib))
    out, seen = [], set()
    for i in order:
        label = _pretty(str(names[idx[i]]))
        if label in seen or abs(contrib[i]) < 1e-3:
            continue
        seen.add(label)
        out.append({"feature": label, "contribution": round(float(contrib[i]), 3),
                    "direction": "phishing" if contrib[i] > 0 else "legitimate"})
        if len(out) >= k:
            break
    return out


def _probability(channel: str, text: str) -> float:
    model = load_model(channel)
    if hasattr(model, "predict_proba"):
        return float(model.predict_proba([text])[0, 1])
    return float(1 / (1 + np.exp(-model.decision_function([text])[0])))


def _verdict(score: float) -> str:
    if score >= THRESHOLD_PHISHING:
        return "phishing"
    if score >= THRESHOLD_SUSPICIOUS:
        return "suspicious"
    return "safe"


def _combine(ml_prob: float, flags: list[dict], floor: float = 0.0) -> float:
    """Risk score (0-100) = 80% ML probability + up to 25 points of red-flag evidence.
    `floor` lets a strongly malicious sub-component (e.g. a phishing link inside
    an email) lift the overall score."""
    points = min(MAX_FLAG_POINTS, sum(SEVERITY_POINTS[f["severity"]] for f in flags))
    return round(min(100.0, max(ml_prob * 80 + points, floor)), 1)


def _result(channel, ml_prob, flags, explanation, details, floor=0.0):
    score = _combine(ml_prob, flags, floor)
    order = {"high": 0, "medium": 1, "low": 2}
    return {
        "channel": channel,
        "verdict": _verdict(score),
        "risk_score": score,
        "ml_probability": round(ml_prob, 4),
        "red_flags": sorted(flags, key=lambda f: order[f["severity"]]),
        "explanation": explanation,
        "details": details,
        "advice": advice(channel, _verdict(score)),
    }


def analyze_url(url: str) -> dict:
    url = url.strip()
    norm = normalize_url(url)
    host, _, _ = split_url(norm)
    reg = registered_domain(host)
    prob = _probability("url", norm)
    flags = url_red_flags(url)
    trusted = reg in TRUSTED_DOMAINS or any(host.endswith("." + d) or host == d for d in TRUSTED_DOMAINS)
    if trusted:
        prob = min(prob, 0.1)
        flags = [f for f in flags if f["severity"] == "low"]
        flags.insert(0, {"severity": "low", "title": "Known reputable domain",
                         "detail": f"'{reg}' is on the trusted-domain list. Still check the full address carefully."})
    details = {"url": url, "host": host, "registered_domain": reg, "trusted_domain": trusted}
    res = _result("url", prob, flags, explain("url", norm), details)
    if trusted:
        res["risk_score"] = min(res["risk_score"], 15.0)
        res["verdict"] = "safe"
        res["advice"] = advice("url", "safe")
    return res


def _linked_urls(text: str, limit: int = 10) -> list[dict]:
    return [{"url": u, "verdict": (r := analyze_url(u))["verdict"], "risk_score": r["risk_score"]}
            for u in extract_urls(text)[:limit]]


def analyze_sms(text: str) -> dict:
    prob = _probability("sms", text)
    flags = text_red_flags(text)
    links = _linked_urls(text)
    worst = max((l["risk_score"] for l in links), default=0.0)
    if any(l["verdict"] == "phishing" for l in links):
        flags.append({"severity": "high", "title": "Contains a malicious-looking link",
                      "detail": "At least one link in this message was rated as phishing by the URL model."})
    return _result("sms", prob, flags, explain("sms", text), {"links": links}, floor=worst * 0.9)


def analyze_email(raw: str | bytes) -> dict:
    parsed = parse_email(raw)
    content = f"{parsed['subject']}\n{parsed['body']}".strip()
    prob = _probability("email", content)
    flags = text_red_flags(content) + header_red_flags(parsed)
    links = _linked_urls(parsed["body"])
    worst = max((l["risk_score"] for l in links), default=0.0)
    if any(l["verdict"] == "phishing" for l in links):
        flags.append({"severity": "high", "title": "Contains a malicious-looking link",
                      "detail": "At least one link in this email was rated as phishing by the URL model."})
    details = {
        "subject": parsed["subject"], "from": parsed["from"], "reply_to": parsed["reply_to"],
        "attachments": parsed.get("attachments", []), "headers_present": parsed["has_headers"], "links": links,
    }
    return _result("email", prob, flags, explain("email", content), details, floor=worst * 0.9)


def analyze_qr_payload(payload: str) -> dict:
    info = classify_payload(payload)
    if info["type"] == "url":
        res = analyze_url(info["data"]["url"])
        res["channel"] = "qr"
        res["details"].update({"qr_payload": payload, "qr_type": info["label"]})
        res["advice"] = advice("qr", res["verdict"])
        return res
    flags = payload_red_flags(info)
    if info["type"] == "text":
        prob = _probability("sms", payload)
        flags += text_red_flags(payload)
        expl = explain("sms", payload)
    else:
        prob, expl = 0.0, []
    if info["type"] == "upi":
        # Sending money is inherently risky; a payment dressed up as a refund/prize is a known scam.
        prob = 0.8 if any(f["title"] == "Misleading payment note" for f in flags) else 0.5
    details = {"qr_payload": payload, "qr_type": info["label"], **info["data"]}
    return _result("qr", prob, flags, expl, details)


def analyze_qr_image(image_bytes: bytes) -> dict:
    payloads = decode_qr(image_bytes)
    if not payloads:
        return {"channel": "qr", "verdict": "unknown", "risk_score": None, "ml_probability": None,
                "red_flags": [], "explanation": [], "details": {"error": "No QR code found in the image."},
                "advice": ["Try a sharper, well-lit photo with the whole QR code visible."]}
    results = [analyze_qr_payload(p) for p in payloads]
    best = max(results, key=lambda r: r["risk_score"])
    if len(results) > 1:
        best["details"]["all_codes"] = [{"payload": r["details"]["qr_payload"], "verdict": r["verdict"]}
                                        for r in results]
    return best


ADVICE = {
    "phishing": [
        "Do NOT click links, scan, reply, call back or download attachments.",
        "Never share passwords, OTPs, PINs or card details. No real company asks for them.",
        "Contact the organisation through its official app or website you type yourself.",
        "Report it: forward phishing emails to your IT/security team; in India report at cybercrime.gov.in or call 1930.",
        "Delete the message after reporting.",
    ],
    "suspicious": [
        "Pause before acting. Verify the request through a separate, trusted channel.",
        "Hover over (or long-press) links to see the real destination before opening.",
        "If it asks for money, credentials or urgency, treat it as phishing until proven otherwise.",
    ],
    "safe": [
        "No strong phishing signals were found, but stay alert: no detector is 100% accurate.",
        "Still never share OTPs or passwords, even with messages that look legitimate.",
    ],
}


def advice(channel: str, verdict: str) -> list[str]:
    tips = list(ADVICE.get(verdict, []))
    if channel == "qr" and verdict != "safe":
        tips.insert(0, "Check for a sticker placed over the original QR code (common on parking meters and posters).")
    return tips
