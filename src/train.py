"""
Train the false-positive triage model.

    python -m src.train

Compares Logistic Regression, Random Forest and Gradient Boosting with
stratified cross-validation (average precision, the right metric for an
imbalanced problem), fits the best on a training split, reports held-out
metrics, and saves the model. The held-out split is written to
data/holdout.csv so evaluation reports on exactly the same test data.
"""
from __future__ import annotations

import json

import joblib
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline

from . import config
from .features import FEATURE_COLUMNS

RANDOM_STATE = 42


def build_models() -> dict:
    return {
        "Logistic Regression": make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=1000, class_weight="balanced"),
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=300, class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1
        ),
        "Gradient Boosting": GradientBoostingClassifier(random_state=RANDOM_STATE),
    }


def main() -> int:
    df = pd.read_csv(config.DATASET)
    X = df[FEATURE_COLUMNS]
    y = df["label"].astype(int)
    print(f"Dataset: {len(df)} alerts  ({int(y.sum())} true positives, {int((y == 0).sum())} false positives)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    print("\nModel comparison (5-fold CV, average precision on the true-positive class):")
    scores = {}
    for name, model in build_models().items():
        s = cross_val_score(model, X_train, y_train, cv=cv, scoring="average_precision")
        scores[name] = s.mean()
        print(f"  {name:22s}: {s.mean():.3f}  (+/- {s.std():.3f})")

    best_name = max(scores, key=scores.get)
    print(f"\nBest: {best_name}")
    best = build_models()[best_name]
    best.fit(X_train, y_train)

    config.MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump({"model": best, "name": best_name, "features": FEATURE_COLUMNS}, config.MODEL_PATH)

    # Persist the exact held-out split for evaluation.
    holdout = X_test.copy()
    holdout["label"] = y_test.values
    holdout.to_csv(config.DATA_DIR / "holdout.csv", index=False)

    with open(config.MODELS_DIR / "cv_scores.json", "w") as f:
        json.dump(scores, f, indent=2)

    print(f"Saved model -> {config.MODEL_PATH}")
    print("Next:  python -m src.evaluate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
