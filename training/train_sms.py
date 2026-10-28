"""Train the SMS / smishing detector on the UCI SMS Spam Collection."""
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import FeatureUnion
from sklearn.svm import LinearSVC

from training.common import select_and_train
from config import KAGGLE_DATASETS, RAW_DIR
from phishshield.text_utils import normalize_sms


def load():
    df = pd.read_csv(RAW_DIR / "sms_spam.csv", encoding="latin-1", usecols=[0, 1])
    df.columns = ["label", "text"]
    df = df.drop_duplicates("text")
    return df["text"].tolist(), (df["label"] == "spam").astype(int).tolist()


def main():
    X, y = load()
    features = FeatureUnion([
        ("words", TfidfVectorizer(preprocessor=normalize_sms, ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
        ("chars", TfidfVectorizer(preprocessor=normalize_sms, analyzer="char_wb", ngram_range=(3, 5),
                                  min_df=3, sublinear_tf=True, max_features=60000)),
    ])
    candidates = {
        "LogisticRegression": LogisticRegression(C=20, max_iter=3000, class_weight="balanced"),
        "LinearSVC (calibrated)": CalibratedClassifierCV(LinearSVC(C=0.5, class_weight="balanced"), cv=3),
        "ComplementNB": ComplementNB(alpha=0.1),
    }
    return select_and_train("sms", X, y, features, candidates, dataset_info=KAGGLE_DATASETS["sms"])


if __name__ == "__main__":
    main()
