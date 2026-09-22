"""
Evaluate the trained model and produce report-ready figures.

    python -m src.evaluate

Reports on the held-out split (never seen in training):
  - confusion matrix and precision / recall / F1 for the true-positive class;
  - the headline comparison against triaging every ZAP alert by hand;
  - recall per vulnerability category;
  - which features drive the decision (SHAP for tree models, else permutation
    importance).

Figures are written to docs/ ; numbers to models/metrics.json .
"""
from __future__ import annotations

import json

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score, confusion_matrix, f1_score, precision_score, recall_score,
)

from . import config
from .benchmark_labeller import CWE_TO_CATEGORY
from .features import FEATURE_COLUMNS

INK = "#1f2933"
ACCENT = "#2563eb"     # model
NEUTRAL = "#9aa5b1"    # baseline
GOOD = "#059669"


def _style(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.tick_params(colors=INK)
    ax.yaxis.label.set_color(INK)
    ax.xaxis.label.set_color(INK)
    ax.title.set_color(INK)


def main() -> int:
    bundle = joblib.load(config.MODEL_PATH)
    model, name = bundle["model"], bundle["name"]
    df = pd.read_csv(config.DATA_DIR / "holdout.csv")
    X, y = df[FEATURE_COLUMNS], df["label"].astype(int)

    proba = model.predict_proba(X)[:, 1]
    pred = model.predict(X)

    prec = precision_score(y, pred, zero_division=0)
    rec = recall_score(y, pred, zero_division=0)
    f1 = f1_score(y, pred, zero_division=0)
    ap = average_precision_score(y, proba)
    cm = confusion_matrix(y, pred)
    config.DATA_DIR.mkdir(exist_ok=True)

    print(f"Model: {name}   (held-out set: {len(df)} alerts, {int(y.sum())} real)")
    print(f"  precision {prec:.1%}   recall {rec:.1%}   F1 {f1:.1%}   PR-AUC {ap:.3f}")
    print(f"  confusion matrix [tn fp / fn tp]:\n{cm}")

    # --- headline: model vs reviewing every ZAP alert by hand ---------------
    total = len(df)
    real = int(y.sum())
    base_precision = real / total if total else 0
    flagged_by_model = int(pred.sum())
    metrics = {
        "model": name,
        "precision": prec, "recall": rec, "f1": f1, "pr_auc": ap,
        "held_out_alerts": total, "real_findings": real,
        "baseline_precision_review_all": base_precision,
        "alerts_flagged_by_model": flagged_by_model,
        "manual_review_reduction": 1 - (flagged_by_model / total) if total else 0,
    }
    with open(config.MODELS_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"\n  Reviewing all ZAP alerts by hand: {total} to read, {base_precision:.1%} are real.")
    print(f"  With the model: {flagged_by_model} to read, {prec:.1%} are real "
          f"({metrics['manual_review_reduction']:.0%} less to review), catching {rec:.0%} of real findings.")

    _fig_confusion(cm)
    _fig_model_vs_baseline(base_precision, prec, rec)
    _fig_per_category(df, pred, y)
    _fig_importance(model, X)
    print("\nFigures written to docs/. Numbers in models/metrics.json.")
    return 0


def _fig_confusion(cm):
    fig, ax = plt.subplots(figsize=(4.2, 3.8))
    ax.imshow(cm, cmap="Blues")
    labels = ["False positive", "Real finding"]
    ax.set_xticks([0, 1], labels)
    ax.set_yticks([0, 1], labels)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("Confusion matrix (held-out)")
    thresh = cm.max() / 2
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                    color="white" if cm[i, j] > thresh else INK, fontweight="bold")
    fig.tight_layout()
    fig.savefig(config.ROOT_DIR / "docs" / "confusion_matrix.png", dpi=150)
    plt.close(fig)


def _fig_model_vs_baseline(base_prec, model_prec, model_rec):
    fig, ax = plt.subplots(figsize=(5.4, 3.8))
    bars = ["Review every\nZAP alert", "Model-triaged\nalerts"]
    vals = [base_prec * 100, model_prec * 100]
    colors = [NEUTRAL, ACCENT]
    b = ax.bar(bars, vals, color=colors, width=0.6)
    ax.set_ylabel("Share that are real findings (precision, %)")
    ax.set_ylim(0, 100)
    ax.set_title(f"The model keeps {model_rec:.0%} of real findings\nwhile cutting the noise")
    for rect, v in zip(b, vals):
        ax.text(rect.get_x() + rect.get_width() / 2, v + 2, f"{v:.1f}%",
                ha="center", fontweight="bold", color=INK)
    _style(ax)
    fig.tight_layout()
    fig.savefig(config.ROOT_DIR / "docs" / "model_vs_zap.png", dpi=150)
    plt.close(fig)


def _fig_per_category(df, pred, y):
    df = df.copy()
    df["pred"] = pred
    df["actual"] = y.values
    df["category"] = df["cweid"].map(CWE_TO_CATEGORY).fillna("other")
    rows = []
    for cat, g in df.groupby("category"):
        real = g[g.actual == 1]
        if len(real) == 0:
            continue
        rows.append((cat, recall_score(real.actual, real.pred, zero_division=0), len(real)))
    if not rows:
        return
    rows.sort(key=lambda r: r[2], reverse=True)
    cats = [f"{c} (n={n})" for c, _, n in rows]
    recalls = [r * 100 for _, r, n in rows]
    fig, ax = plt.subplots(figsize=(6, 0.5 * len(rows) + 1.5))
    ax.barh(cats, recalls, color=GOOD)
    ax.set_xlim(0, 100)
    ax.set_xlabel("Recall on real findings (%)")
    ax.set_title("Detection rate by vulnerability category")
    ax.invert_yaxis()
    for i, v in enumerate(recalls):
        ax.text(v + 1, i, f"{v:.0f}%", va="center", color=INK)
    _style(ax)
    fig.tight_layout()
    fig.savefig(config.ROOT_DIR / "docs" / "per_category.png", dpi=150)
    plt.close(fig)


def _fig_importance(model, X):
    """SHAP summary for tree models; permutation importance otherwise."""
    out = config.ROOT_DIR / "docs" / "shap_summary.png"
    sample = X.sample(min(2000, len(X)), random_state=42)
    try:
        import shap
        est = getattr(model, "named_steps", {}).get("randomforestclassifier", model)
        explainer = shap.TreeExplainer(est)
        sv = explainer.shap_values(sample)
        vals = sv[1] if isinstance(sv, list) else sv
        shap.summary_plot(vals, sample, show=False, plot_size=(6, 4))
        plt.tight_layout()
        plt.savefig(out, dpi=150)
        plt.close()
        return
    except Exception as exc:
        print(f"  (SHAP unavailable: {exc}; using permutation importance)")

    from sklearn.inspection import permutation_importance
    r = permutation_importance(model, X, model.predict(X), n_repeats=5, random_state=42)
    order = np.argsort(r.importances_mean)
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.barh(np.array(FEATURE_COLUMNS)[order], r.importances_mean[order], color=ACCENT)
    ax.set_title("Feature importance (permutation)")
    _style(ax)
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    raise SystemExit(main())
