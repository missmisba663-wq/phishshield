"""QR code decoding and payload classification (quishing detection)."""
from urllib.parse import parse_qs, urlsplit

import cv2
import numpy as np

_detector = cv2.QRCodeDetector()


def _try_decode(img) -> list[str]:
    try:
        ok, texts, _, _ = _detector.detectAndDecodeMulti(img)
        if ok:
            found = [t for t in texts if t]
            if found:
                return found
    except cv2.error:
        pass
    text, _, _ = _detector.detectAndDecode(img)
    return [text] if text else []


def decode_qr(image_bytes: bytes) -> list[str]:
    """Decode every QR code in an image. Tries a few preprocessing variants
    because photos of posters/screens are often blurry, small or low-contrast."""
    arr = np.frombuffer(image_bytes, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Could not read the image. Upload a PNG or JPG.")
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    variants = [img, gray]
    h, w = gray.shape
    if max(h, w) < 600:
        variants.append(cv2.resize(gray, None, fx=3, fy=3, interpolation=cv2.INTER_NEAREST))
    if max(h, w) > 2000:
        scale = 1600 / max(h, w)
        variants.append(cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA))
    variants.append(cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1])
    variants.append(cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 5))
    padded = cv2.copyMakeBorder(gray, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    variants.append(padded)
    for v in variants:
        found = _try_decode(v)
        if found:
            return list(dict.fromkeys(found))
    # Tilted photos: straighten with a few candidate rotations.
    ph, pw = padded.shape
    for angle in (-15, 15, -30, 30, -8, 8, -22, 22):
        m = cv2.getRotationMatrix2D((pw / 2, ph / 2), angle, 1.0)
        found = _try_decode(cv2.warpAffine(padded, m, (pw, ph), borderValue=255))
        if found:
            return list(dict.fromkeys(found))
    return []


def classify_payload(payload: str) -> dict:
    """Identify what a QR code will do when scanned."""
    p = payload.strip()
    low = p.lower()
    if low.startswith("upi://"):
        q = {k: v[0] for k, v in parse_qs(urlsplit(p).query).items()}
        return {"type": "upi", "label": "UPI payment request", "data": {
            "payee_vpa": q.get("pa", ""), "payee_name": q.get("pn", ""), "amount": q.get("am", ""),
            "note": q.get("tn", ""), "currency": q.get("cu", "INR")}}
    if low.startswith(("http://", "https://", "www.")) or (
            "." in low.split("/")[0] and " " not in low and not low.startswith(("wifi:", "mailto:", "tel:"))):
        return {"type": "url", "label": "Website link", "data": {"url": p}}
    if low.startswith("wifi:"):
        fields = dict(f.split(":", 1) for f in p[5:].split(";") if ":" in f)
        return {"type": "wifi", "label": "Wi-Fi network", "data": {
            "ssid": fields.get("S", ""), "security": fields.get("T", "nopass") or "nopass"}}
    if low.startswith(("mailto:", "matmsg:")):
        return {"type": "email", "label": "Compose email", "data": {"target": p}}
    if low.startswith(("smsto:", "sms:")):
        return {"type": "sms", "label": "Send SMS", "data": {"target": p}}
    if low.startswith("tel:"):
        return {"type": "tel", "label": "Phone call", "data": {"number": p[4:]}}
    if low.startswith("begin:vcard"):
        return {"type": "vcard", "label": "Contact card", "data": {}}
    if low.startswith(("bitcoin:", "ethereum:")):
        return {"type": "crypto", "label": "Crypto payment", "data": {"target": p}}
    return {"type": "text", "label": "Plain text", "data": {"text": p}}


def payload_red_flags(info: dict) -> list[dict]:
    flags = []
    t, d = info["type"], info["data"]
    if t == "upi":
        flags.append({"severity": "high", "title": "This QR SENDS money from your account",
                      "detail": "Scanning a UPI QR and entering your PIN pays the other person. "
                                "You never need to scan a QR or enter a PIN to RECEIVE money. "
                                "This is the most common QR scam on marketplaces like OLX."})
        if d.get("amount"):
            flags.append({"severity": "high", "title": f"Pre-filled amount: {d['currency']} {d['amount']}",
                          "detail": "The amount is already filled in, so one tap on 'Pay' sends it."})
        if d.get("note") and any(w in d["note"].lower() for w in ("refund", "prize", "cashback", "receive", "reward", "kyc")):
            flags.append({"severity": "high", "title": "Misleading payment note",
                          "detail": f"The note says “{d['note']}” to make a payment look like you're receiving money."})
    elif t == "crypto":
        flags.append({"severity": "high", "title": "Crypto payment request",
                      "detail": "Crypto transfers can't be reversed. Scammers favour them for this reason."})
    elif t == "wifi":
        if d.get("security", "").lower() in ("nopass", ""):
            flags.append({"severity": "medium", "title": "Open Wi-Fi network",
                          "detail": f"'{d.get('ssid')}' has no password. Traffic can be intercepted (evil-twin risk)."})
    elif t in ("sms", "tel"):
        flags.append({"severity": "low", "title": f"QR triggers a {t.upper()} action",
                      "detail": "Check the number first: premium-rate numbers can charge you."})
    return flags
