"""Train the URL phishing detector on the Kaggle Phishing Site URLs dataset."""
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.pipeline import FeatureUnion

from training.common import select_and_train
from config import KAGGLE_DATASETS, RAW_DIR
from phishshield.url_features import URLFeatures, normalize_url, url_tokens


def load():
    df = pd.read_csv(RAW_DIR / "url_phishing_site_urls.csv")
    df["norm"] = df["URL"].astype(str).map(normalize_url)
    df = df[df["norm"].str.len() > 3]
    # The same normalised URL can carry conflicting labels; keep the majority label.
    df["y"] = (df["Label"] == "bad").astype(int)
    df = df.groupby("norm", as_index=False)["y"].mean()
    df["y"] = (df["y"] >= 0.5).astype(int)
    return df["norm"].tolist(), df["y"].tolist()


def main():
    X, y = load()
    features = FeatureUnion([
        ("chars", TfidfVectorizer(preprocessor=normalize_url, analyzer="char", ngram_range=(3, 5),
                                  min_df=5, sublinear_tf=True, max_features=250000, dtype="float32")),
        ("tokens", TfidfVectorizer(preprocessor=normalize_url, tokenizer=url_tokens, token_pattern=None,
                                   min_df=3, sublinear_tf=True, max_features=100000, dtype="float32")),
        ("lexical", URLFeatures()),
    ])
    candidates = {
        "LogisticRegression": LogisticRegression(C=5, max_iter=1000, solver="liblinear"),
        "SGD (log loss)": SGDClassifier(loss="log_loss", alpha=2e-6, random_state=42),
        "SGD (modified huber)": SGDClassifier(loss="modified_huber", alpha=5e-6, random_state=42),
    }
    return select_and_train("url", X, y, features, candidates, selection_sample=120000,
                            dataset_info=KAGGLE_DATASETS["url"])


if __name__ == "__main__":
    main()
