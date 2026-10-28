"""Train every PhishShield model and run the end-to-end QR evaluation.

Usage:  python -m training.train_all
"""
from training import evaluate_qr, train_email, train_sms, train_url


def main():
    train_sms.main()
    train_email.main()
    _, _, (X_test, y_test) = train_url.main()
    evaluate_qr.main(X_test, y_test)


if __name__ == "__main__":
    main()
