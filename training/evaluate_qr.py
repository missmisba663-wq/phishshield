"""End-to-end quishing evaluation.

Takes URLs from the held-out URL test set, encodes them as QR images
(clean + blurred/rotated/noisy, the way a phone camera would see them), then
runs the full pipeline: decode -> classify. Reports decode rate and detection accuracy.
"""
import io
import json

import cv2
import numpy as np
import qrcode
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from config import RANDOM_STATE, REPORT_DIR, ROOT
from phishshield import engine
from phishshield.qr import decode_qr

N_PER_CLASS = 150


def make_qr(text: str) -> np.ndarray:
    img = qrcode.make(text, box_size=6, border=4).convert("L")
    return np.array(img)


def distort(img: np.ndarray, kind: str, rng) -> np.ndarray:
    if kind == "blur":
        return cv2.GaussianBlur(img, (5, 5), 1.2)
    if kind == "rotate":
        # Pad first so the rotated code isn't clipped (a camera sees the whole code).
        img = cv2.copyMakeBorder(img, 60, 60, 60, 60, cv2.BORDER_CONSTANT, value=255)
        h, w = img.shape
        m = cv2.getRotationMatrix2D((w / 2, h / 2), rng.uniform(-25, 25), 1.0)
        return cv2.warpAffine(img, m, (w, h), borderValue=255)
    if kind == "noise":
        noisy = img.astype(np.int16) + rng.normal(0, 25, img.shape).astype(np.int16)
        return np.clip(noisy, 0, 255).astype(np.uint8)
    return img


def to_png(img: np.ndarray) -> bytes:
    return cv2.imencode(".png", img)[1].tobytes()


def main(X_test=None, y_test=None):
    if X_test is None:
        from training.train_url import load
        X, y = load()
        _, X_test, _, y_test = train_test_split(np.asarray(X, dtype=object), np.asarray(y), test_size=0.2,
                                                stratify=y, random_state=RANDOM_STATE)
    rng = np.random.RandomState(RANDOM_STATE)
    X_test, y_test = np.asarray(X_test, dtype=object), np.asarray(y_test)
    idx = np.concatenate([rng.choice(np.where(y_test == c)[0], N_PER_CLASS, replace=False) for c in (0, 1)])
    model = engine.load_model("url")

    print(f"\n=== QR END-TO-END | {len(idx)} URLs x 4 conditions ===")
    results = {}
    for kind in ["clean", "blur", "rotate", "noise"]:
        decoded_ok, y_true, y_pred = 0, [], []
        for i in idx:
            url = str(X_test[i])
            payloads = decode_qr(to_png(distort(make_qr(url), kind, rng)))
            if payloads and payloads[0] == url:
                decoded_ok += 1
                y_true.append(int(y_test[i]))
                y_pred.append(int(model.predict([payloads[0]])[0]))
        results[kind] = {
            "decode_rate": round(decoded_ok / len(idx), 4),
            "accuracy": round(accuracy_score(y_true, y_pred), 4),
            "precision": round(precision_score(y_true, y_pred), 4),
            "recall": round(recall_score(y_true, y_pred), 4),
            "f1": round(f1_score(y_true, y_pred), 4),
        }
        print(f"  {kind:<7} {results[kind]}")

    REPORT_DIR.mkdir(exist_ok=True)
    (REPORT_DIR / "qr_metrics.json").write_text(json.dumps(
        {"task": "qr", "n_urls": int(len(idx)), "conditions": results}, indent=2))
    make_samples()
    return results


def make_samples():
    """Demo QR images for the web app / viva presentation."""
    out = ROOT / "samples" / "qr"
    out.mkdir(parents=True, exist_ok=True)
    samples = {
        "safe_github.png": "https://github.com/login",
        "phish_paypal.png": "http://paypal.com.account-verify-secure.xyz/webscr/login.php?cmd=_update",
        "phish_ip_bank.png": "http://192.168.45.12/sbi/netbanking/kyc-update/index.html",
        "upi_refund_scam.png": "upi://pay?pa=refund.desk42@okaxis&pn=Customer%20Care&am=4999&tn=Refund%20cashback%20receive&cu=INR",
        "wifi_open.png": "WIFI:S:Free_Airport_WiFi;T:nopass;;",
        "phish_shortener.png": "http://bit.ly/3xVerify-Acct",
    }
    for name, payload in samples.items():
        qrcode.make(payload).save(out / name)
    print(f"  demo QR images written to {out}")


if __name__ == "__main__":
    main()
