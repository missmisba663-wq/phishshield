"""Shared training utilities: model selection, evaluation, reporting."""
import json
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib  # noqa: E402
import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from sklearn.base import clone  # noqa: E402
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,  # noqa: E402
                             precision_score, recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import train_test_split  # noqa: E402
from sklearn.pipeline import Pipeline  # noqa: E402

from config import MODEL_DIR, RANDOM_STATE, REPORT_DIR  # noqa: E402


def scores(y_true, y_pred, y_prob):
    return {
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred), 4),
        "recall": round(recall_score(y_true, y_pred), 4),
        "f1": round(f1_score(y_true, y_pred), 4),
        "roc_auc": round(roc_auc_score(y_true, y_prob), 4),
    }


def predict_scores(model, X):
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    return model.decision_function(X)


def select_and_train(name, X, y, features, candidates, selection_sample=None, dataset_info=None):
    """Hold out 20% as the test set, choose the best candidate by F1 on a validation
    split of the training data, refit it on all training data, and report test metrics.

    selection_sample: optional cap on rows used for model comparison (speeds up big datasets).
    """
    X = np.asarray(X, dtype=object)
    y = np.asarray(y, dtype=int)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE)
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train, y_train, test_size=0.15, stratify=y_train, random_state=RANDOM_STATE)
    if selection_sample and len(X_fit) > selection_sample:
        idx = np.random.RandomState(RANDOM_STATE).choice(len(X_fit), selection_sample, replace=False)
        X_fit, y_fit = X_fit[idx], y_fit[idx]

    print(f"\n=== {name.upper()} | train={len(X_train):,} test={len(X_test):,} "
          f"phishing-rate={y.mean():.1%} ===")
    comparison = {}
    for cname, clf in candidates.items():
        t = time.time()
        pipe = Pipeline([("features", clone(features)), ("clf", clone(clf))])
        pipe.fit(X_fit, y_fit)
        s = scores(y_val, pipe.predict(X_val), predict_scores(pipe, X_val))
        s["train_seconds"] = round(time.time() - t, 1)
        comparison[cname] = s
        print(f"  {cname:<22} F1={s['f1']:.4f}  AUC={s['roc_auc']:.4f}  ({s['train_seconds']}s)")

    best = max(comparison, key=lambda k: comparison[k]["f1"])
    print(f"  -> best: {best}; refitting on full training set")
    model = Pipeline([("features", clone(features)), ("clf", clone(candidates[best]))])
    t = time.time()
    model.fit(X_train, y_train)
    fit_seconds = time.time() - t

    y_pred = model.predict(X_test)
    y_prob = predict_scores(model, X_test)
    test = scores(y_test, y_pred, y_prob)
    cm = confusion_matrix(y_test, y_pred)
    print(f"  TEST: {test}")

    MODEL_DIR.mkdir(exist_ok=True)
    REPORT_DIR.mkdir(exist_ok=True)
    joblib.dump(model, MODEL_DIR / f"{name}_model.joblib", compress=3)

    report = {
        "task": name,
        "trained_at": datetime.now().isoformat(timespec="seconds"),
        "dataset": dataset_info or {},
        "n_samples": int(len(X)),
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "phishing_rate": round(float(y.mean()), 4),
        "model_comparison_validation": comparison,
        "selected_model": best,
        "fit_seconds": round(fit_seconds, 1),
        "test_metrics": test,
        "confusion_matrix": cm.tolist(),
        "top_phishing_features": top_features(model, 20),
    }
    (REPORT_DIR / f"{name}_metrics.json").write_text(json.dumps(report, indent=2))
    plot_report(name, y_test, y_prob, cm, comparison)
    return model, report, (X_test, y_test)


def linear_weights(clf):
    """Per-feature weights pointing towards the phishing class, for any supported classifier."""
    if hasattr(clf, "coef_"):
        return np.asarray(clf.coef_).ravel()
    if hasattr(clf, "calibrated_classifiers_"):
        return np.mean([np.asarray(c.estimator.coef_).ravel() for c in clf.calibrated_classifiers_], axis=0)
    if hasattr(clf, "feature_log_prob_"):
        return clf.feature_log_prob_[1] - clf.feature_log_prob_[0]
    return None


def top_features(model, k=20):
    w = linear_weights(model.named_steps["clf"])
    if w is None:
        return []
    names = model.named_steps["features"].get_feature_names_out()
    order = np.argsort(w)[::-1][:k]
    return [{"feature": str(names[i]).split("__", 1)[-1], "weight": round(float(w[i]), 3)} for i in order]


def plot_report(name, y_test, y_prob, cm, comparison):
    fig, axes = plt.subplots(1, 3, figsize=(16, 4.5))
    fig.suptitle(f"PhishShield - {name.upper()} model", fontsize=14, fontweight="bold")

    ax = axes[0]
    ax.imshow(cm, cmap="Blues")
    for (i, j), v in np.ndenumerate(cm):
        ax.text(j, i, f"{v:,}", ha="center", va="center",
                color="white" if v > cm.max() / 2 else "black", fontsize=12)
    ax.set_xticks([0, 1], ["Legit", "Phishing"])
    ax.set_yticks([0, 1], ["Legit", "Phishing"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("Confusion matrix (test set)")

    ax = axes[1]
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    ax.plot(fpr, tpr, lw=2, label=f"AUC = {roc_auc_score(y_test, y_prob):.4f}")
    ax.plot([0, 1], [0, 1], "--", color="grey")
    ax.set_xlabel("False positive rate")
    ax.set_ylabel("True positive rate")
    ax.set_title("ROC curve")
    ax.legend(loc="lower right")

    ax = axes[2]
    names = list(comparison)
    ax.barh(names, [comparison[n]["f1"] for n in names], color="#4C78A8")
    lo = min(comparison[n]["f1"] for n in names)
    ax.set_xlim(max(0, lo - 0.05), 1.0)
    for i, n in enumerate(names):
        ax.text(comparison[n]["f1"], i, f" {comparison[n]['f1']:.4f}", va="center")
    ax.set_title("Model comparison (validation F1)")

    fig.tight_layout()
    fig.savefig(REPORT_DIR / f"{name}_report.png", dpi=110)
    plt.close(fig)
