"""Train the email phishing detector on the Kaggle Phishing Email Dataset."""
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import FeatureUnion
from sklearn.svm import LinearSVC

from training.common import select_and_train
from config import KAGGLE_DATASETS, RAW_DIR
from phishshield.text_utils import normalize_email


def load():
    df = pd.read_csv(RAW_DIR / "email_phishing_email.csv")
    df = df.dropna(subset=["text_combined"]).drop_duplicates("text_combined")
    # Truncate very long emails: phishing intent shows up early, and this keeps training fast.
    text = df["text_combined"].str.slice(0, 5000)
    return text.tolist(), df["label"].astype(int).tolist()


def main():
    X, y = load()
    features = FeatureUnion([
        ("words", TfidfVectorizer(preprocessor=normalize_email, ngram_range=(1, 2), min_df=3, max_df=0.9,
                                  sublinear_tf=True, max_features=300000)),
    ])
    candidates = {
        "LogisticRegression": LogisticRegression(C=10, max_iter=2000, solver="liblinear"),
        "LinearSVC (calibrated)": CalibratedClassifierCV(LinearSVC(C=0.5), cv=3),
        "SGD (modified huber)": SGDClassifier(loss="modified_huber", alpha=1e-5, random_state=42),
        "ComplementNB": ComplementNB(alpha=0.05),
    }
    return select_and_train("email", X, y, features, candidates, dataset_info=KAGGLE_DATASETS["email"])


if __name__ == "__main__":
    main()
