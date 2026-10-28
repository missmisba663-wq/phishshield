"""Central configuration for PhishShield."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
MODEL_DIR = ROOT / "models"
REPORT_DIR = ROOT / "reports"
DB_PATH = ROOT / "instance" / "phishshield.db"

# Kaggle datasets used for training (downloaded with kagglehub)
KAGGLE_DATASETS = {
    "sms": {
        "slug": "uciml/sms-spam-collection-dataset",
        "file": "spam.csv",
        "description": "UCI SMS Spam Collection - 5,574 labelled SMS messages",
    },
    "email": {
        "slug": "naserabdullahalam/phishing-email-dataset",
        "file": "phishing_email.csv",
        "description": "Phishing Email Dataset - ~82k emails (Enron, Ling, CEAS, Nazario, Nigerian Fraud, SpamAssassin)",
    },
    "url": {
        "slug": "taruntiwarihp/phishing-site-urls",
        "file": "phishing_site_urls.csv",
        "description": "Phishing Site URLs - ~549k URLs labelled good/bad",
    },
}

# Risk score thresholds (0-100)
THRESHOLD_SUSPICIOUS = 40
THRESHOLD_PHISHING = 70

RANDOM_STATE = 42
