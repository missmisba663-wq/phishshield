"""Text normalisation shared by training and inference.

The same function must be used in both places, otherwise the model sees
different tokens at prediction time than it saw during training.
"""
import re

from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\.[a-z]{2,}(?:/[^\s<>\"']*)?",
                    re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
PHONE_RE = re.compile(r"\+?\d[\d\s-]{7,}\d")
MONEY_RE = re.compile(r"[$£€₹]\s?\d[\d,.]*|\d[\d,.]*\s?(?:usd|dollars|pounds|rs|inr)\b", re.IGNORECASE)
NON_ALNUM_RE = re.compile(r"[^a-z0-9\s]")
SPACE_RE = re.compile(r"\s+")


def extract_urls(text: str) -> list[str]:
    """Return the unique URLs found in free text, in order of appearance."""
    seen, out = set(), []
    for m in URL_RE.findall(text or ""):
        url = m.rstrip(".,);:!?]'\"")
        if url.lower() not in seen:
            seen.add(url.lower())
            out.append(url)
    return out


def normalize_sms(text: str) -> str:
    """Light normalisation for SMS: keep the wording, mask volatile entities."""
    text = (text or "").lower()
    text = URL_RE.sub(" urltoken ", text)
    text = EMAIL_RE.sub(" emailtoken ", text)
    text = MONEY_RE.sub(" moneytoken ", text)
    text = PHONE_RE.sub(" phonetoken ", text)
    return SPACE_RE.sub(" ", text).strip()


def normalize_email(text: str) -> str:
    """Normalisation matching the Kaggle 'text_combined' column:
    lower-case, punctuation removed, English stop words dropped."""
    text = (text or "").lower()
    text = NON_ALNUM_RE.sub(" ", text)
    tokens = [t for t in text.split() if t not in ENGLISH_STOP_WORDS]
    return " ".join(tokens)
