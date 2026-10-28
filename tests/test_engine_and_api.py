"""Integration tests: trained models + Flask API. Skipped if models aren't trained yet."""
import pytest

from config import MODEL_DIR, ROOT

pytestmark = pytest.mark.skipif(
    not all((MODEL_DIR / f"{c}_model.joblib").exists() for c in ("sms", "email", "url")),
    reason="models not trained - run python -m training.train_all")


@pytest.fixture()
def client(tmp_path):
    from app import create_app
    app = create_app(db_path=tmp_path / "test.db")
    return app.test_client()


def test_url_engine():
    from phishshield import engine
    assert engine.analyze_url("http://paypal.com.secure-login-verify.xyz/webscr?cmd=_login")["verdict"] == "phishing"
    assert engine.analyze_url("https://en.wikipedia.org/wiki/Phishing")["verdict"] == "safe"


def test_sms_engine():
    from phishshield import engine
    bad = engine.analyze_sms("URGENT! You have won a 1000 cash prize. Claim now, call 09061701461 before it expires")
    good = engine.analyze_sms("Hey are we still on for dinner tonight? I'll pick you up at 8")
    assert bad["verdict"] == "phishing"
    assert good["verdict"] == "safe"
    assert bad["explanation"], "explanations should be produced"


def test_email_engine():
    from phishshield import engine
    r = engine.analyze_email("Subject: Verify your account\n\nDear customer, your account has been suspended. "
                             "Click here to verify your password within 24 hours: http://secure-bank-login.xyz/verify")
    assert r["verdict"] == "phishing"


def test_api_endpoints(client):
    r = client.post("/api/v1/scan/url", json={"url": "http://192.168.0.5/paypal/login.php"})
    assert r.status_code == 200 and r.get_json()["verdict"] in ("phishing", "suspicious")
    assert client.post("/api/v1/scan/sms", json={"text": ""}).status_code == 400
    with open(ROOT / "samples" / "qr" / "upi_refund_scam.png", "rb") as f:
        r = client.post("/api/v1/scan/qr", data={"file": (f, "qr.png")}, content_type="multipart/form-data")
    assert r.get_json()["details"]["qr_type"] == "UPI payment request"
    stats = client.get("/api/v1/stats").get_json()
    assert stats["total_scans"] == 2


@pytest.mark.parametrize("path", ["/", "/scan", "/training", "/learn", "/dashboard", "/about"])
def test_pages_render(client, path):
    assert client.get(path).status_code == 200
