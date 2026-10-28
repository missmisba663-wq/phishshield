# 🛡️ PhishShield: AI-Powered Multi-Channel Phishing Detection & Awareness Platform

PhishShield detects phishing across the four channels attackers actually use (**SMS/chat messages, emails, URLs and QR codes**) using machine-learning models trained on **590,000+ real-world samples from Kaggle**. It explains *why* each item is dangerous and trains users to spot phishing themselves.

> Final Year Project · Python · scikit-learn · OpenCV · Flask · SQLite

---

## ✨ Key features

| Feature | What it does |
|---|---|
| 💬 **SMS / smishing detection** | TF-IDF (word + char n-grams) model + social-engineering rule engine; links inside the message are checked too |
| 📧 **Email phishing detection** | Body classifier + **header forensics**: SPF/DKIM/DMARC failures, Reply-To mismatch, display-name spoofing, dangerous attachments. Accepts raw `.eml` files |
| 🔗 **Malicious URL detection** | Character n-grams + **22 hand-engineered lexical features** (IP host, brand-in-subdomain, punycode, risky TLDs, entropy…). Never visits the URL |
| 📷 **QR code (quishing) detection** | OpenCV decoding with image pre-processing, in-browser **live camera scanning**, payload classification (URL / **UPI payment** / Wi-Fi / SMS / crypto). Detects the "scan to receive money" UPI scam |
| 🧠 **Explainable AI** | Per-prediction feature contributions (tf-idf × model weight) show which words/patterns drove the verdict |
| 🎯 **Hybrid risk score** | `0.8 × ML probability + red-flag points` → 0–100 score → Safe / Suspicious / Phishing |
| 🎓 **Awareness training** | 14 interactive "Spot the Phish" scenarios with instant feedback, AI second opinion and a leaderboard |
| 📊 **Threat dashboard** | Scan history, verdicts per channel, top red flags, model metrics, confusion matrices, ROC curves |
| 🔌 **REST API + CLI** | `/api/v1/scan/{sms,email,url,qr}` for integration; `scan.py` for the terminal |
| ✅ **Tested** | pytest unit + integration tests (features, rules, QR round-trip, API, pages) |

---

## 🏗️ Architecture

```
  SMS / chat        Email / .eml            URL             QR image / camera
      │          header parser (SPF,        │              OpenCV decode → payload type
      │          DKIM, spoofing, attach.)   │              (URL / UPI / Wi-Fi / text)
      ▼                  ▼                  ▼                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ Feature extraction: TF-IDF words + char n-grams, 22 lexical URL features │
 │ ML model per channel (best of LogReg / LinearSVC / SGD / NB)           │
 │ + Rule engine (urgency, threats, credential requests, brand abuse…)    │
 │ + Embedded links in SMS/email re-scanned by the URL model              │
 │ → Risk score 0-100  → verdict  → explanation  → advice                 │
 └───────────────────────────────┬────────────────────────────────────────┘
                                 ▼
      Flask Web UI · REST API · CLI · SQLite history · Awareness quiz
```

---

## 📚 Datasets (Kaggle)

| Channel | Kaggle dataset | Size |
|---|---|---|
| SMS | [uciml/sms-spam-collection-dataset](https://www.kaggle.com/datasets/uciml/sms-spam-collection-dataset) | 5,574 messages |
| Email | [naserabdullahalam/phishing-email-dataset](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset) | ~82,500 emails (Enron, Ling, CEAS-08, Nazario, Nigerian Fraud, SpamAssassin) |
| URL | [taruntiwarihp/phishing-site-urls](https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls) | ~549,000 URLs |
| QR | Generated from the held-out URL **test set**, with clean / blurred / rotated / noisy variants | 300 URLs × 4 conditions |

**Data preparation:** duplicates removed; URLs normalised (scheme and `www.` stripped so the model can't cheat on formatting artefacts); conflicting URL labels resolved by majority vote; volatile entities in SMS (phone numbers, money, links) masked as tokens.

**Methodology:** stratified 80/20 train/test split → model selection on a validation split carved from training data only → best model refit on the full training set → final metrics reported once on the untouched test set.

---

## 📈 Results (held-out test set)

| Channel | Test samples | Selected model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---:|---|---:|---:|---:|---:|---:|
| **SMS** | 1,034 | LinearSVC (calibrated) | 98.84% | 97.60% | 93.13% | 95.31% | 99.83% |
| **EMAIL** | 16,416 | SGD (modified huber) | 99.40% | 99.35% | 99.50% | 99.42% | 99.96% |
| **URL** | 101,263 | LogisticRegression | 98.31% | 97.98% | 94.38% | 96.15% | 99.71% |

**QR end-to-end pipeline** (decode → classify, 300 held-out URLs):

| Image condition | Decode rate | Accuracy | F1 |
|---|---:|---:|---:|
| Clean | 100.0% | 97.00% | 96.93% |
| Blur | 99.7% | 96.99% | 96.91% |
| Rotate | 99.7% | 96.99% | 96.91% |
| Noise | 100.0% | 97.00% | 96.93% |

Confusion matrices, ROC curves and model comparisons are in [`reports/`](reports/) and on the in-app Dashboard.

---

## 🚀 Getting started

```bash
# 1. Install dependencies (Python 3.10+)
pip install -r requirements.txt

# 2. Download datasets from Kaggle (public datasets download anonymously)
python scripts/download_data.py

# 3. Train all models + run the QR end-to-end evaluation (~5-10 min)
python -m training.train_all

# 4. Launch the web app → http://127.0.0.1:5000
python app.py
```

Run tests: `python -m pytest -q`

### ☁️ Deploy (free, permanent link)

The repo ships with a `Dockerfile`, and the trained models are committed, so no retraining is needed on the server.

**Render**
1. Push this project to GitHub.
2. On [render.com](https://render.com): **New + → Blueprint** → pick the repo (uses `render.yaml`) → **Apply**.
3. Your app goes live at `https://phishshield-xxxx.onrender.com`. The free tier sleeps after 15 min idle and the first visit takes ~1 min to wake.

**Hugging Face Spaces** (16 GB RAM free, popular for ML portfolios)
1. On [huggingface.co/new-space](https://huggingface.co/new-space) choose **SDK: Docker** (blank template).
2. Push this project to the Space's git repo.
3. Live at `https://huggingface.co/spaces/<username>/phishshield`.

> Scan history uses SQLite, which resets whenever a free host restarts. That's fine for a demo.

### CLI

```bash
python scan.py url "http://paypal.com.secure-login-verify.xyz/webscr?cmd=_login"
python scan.py sms "URGENT! Your SBI account is blocked. Update KYC: http://sbi-kyc.xyz"
python scan.py email suspicious.eml
python scan.py qr samples/qr/upi_refund_scam.png
python scan.py url "https://github.com" --json
```

### REST API

```bash
curl -X POST http://127.0.0.1:5000/api/v1/scan/url  -H "Content-Type: application/json" -d '{"url":"http://192.168.1.5/paypal/login"}'
curl -X POST http://127.0.0.1:5000/api/v1/scan/sms  -H "Content-Type: application/json" -d '{"text":"You won a prize! Claim now"}'
curl -X POST http://127.0.0.1:5000/api/v1/scan/email -F "file=@message.eml"
curl -X POST http://127.0.0.1:5000/api/v1/scan/qr    -F "file=@samples/qr/phish_paypal.png"
```

Every endpoint returns:

```json
{
  "channel": "url", "verdict": "phishing", "risk_score": 95.2, "ml_probability": 0.99,
  "red_flags":   [{"severity": "high", "title": "Brand name 'paypal' outside the real domain", "detail": "..."}],
  "explanation": [{"feature": "pattern “.xyz”", "contribution": 1.84, "direction": "phishing"}],
  "details": {...}, "advice": ["Do NOT click links..."]
}
```

---

## 📁 Project structure

```
Phishing shield/
├── app.py                    # Flask web app + REST API
├── scan.py                   # Command-line scanner
├── config.py                 # Paths, Kaggle dataset IDs, thresholds
├── phishshield/
│   ├── engine.py             # Detection engine: risk scoring, explainability, per-channel analysis
│   ├── url_features.py       # 22 lexical URL features + URL red-flag rules
│   ├── red_flags.py          # Social-engineering rules + email header forensics (.eml parser)
│   ├── qr.py                 # QR decoding (OpenCV) + payload classification (UPI, Wi-Fi…)
│   ├── text_utils.py         # Text normalisation shared by training and inference
│   └── storage.py            # SQLite scan history + quiz leaderboard
├── training/
│   ├── common.py             # Model selection, evaluation, plots, reports
│   ├── train_sms.py / train_email.py / train_url.py
│   ├── evaluate_qr.py        # End-to-end QR pipeline evaluation under image distortions
│   └── train_all.py
├── scripts/download_data.py  # Kaggle download via kagglehub
├── awareness/quiz.json       # Training scenarios
├── web/templates, web/static # UI
├── models/                   # Trained pipelines (.joblib)
├── reports/                  # Metrics JSON + confusion matrix / ROC plots
├── samples/qr/               # Demo QR codes
└── tests/                    # pytest suite
```

---

## 🔒 Design decisions

- **Static analysis only.** PhishShield never opens a URL or attachment, so scanning a live phishing kit is safe.
- **Linear models on purpose.** They match transformer-level accuracy on these datasets, train in seconds, predict in milliseconds, and are fully explainable.
- **Privacy.** Only a 120-character preview of each scan is stored, for the dashboard.
- **Defence in depth.** ML catches unseen patterns, the rules catch known tactics, and the user learns to catch the rest.

## ⚠️ Limitations & future work

- Lexical URL analysis can't see page content; a sandboxed headless-browser screenshot + visual brand-similarity model would help with brand impersonation.
- The SMS dataset is English spam from 2012; regional/Hinglish smishing data would improve coverage.
- The trusted-domain list is small; production would use Tranco top-1M + threat-intel feeds (PhishTank, OpenPhish, Google Safe Browsing).
- Next steps: browser extension, Outlook/Gmail add-in, DistilBERT comparison, active learning from user reports.

---

## 📝 Resume bullet points

- Built **PhishShield**, a multi-channel phishing detection platform (SMS, email, URL, QR) in Python, trained on **590K+ Kaggle samples** with test F1 scores up to **0.99**.
- Engineered a hybrid detection engine combining TF-IDF/linear ML models, **22 lexical URL features** and a social-engineering rule engine into an explainable 0–100 risk score.
- Implemented **email header forensics** (SPF/DKIM/DMARC, Reply-To and display-name spoofing) and **QR "quishing" detection** with OpenCV, including UPI payment-scam detection; validated QR decoding under blur/rotation/noise.
- Shipped a Flask web app with a **REST API**, live camera QR scanning, explainable-AI visualisations, a threat dashboard and a gamified **phishing-awareness training** module; covered by pytest unit/integration tests.
