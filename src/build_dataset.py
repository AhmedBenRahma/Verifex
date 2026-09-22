"""
Build the labelled training dataset from a ZAP scan report.

    python -m src.build_dataset data/benchmark_report.json

Reads the ZAP JSON report, joins every alert to the OWASP Benchmark answer key
for a ground-truth label, extracts features, and writes data/dataset.csv.
"""
from __future__ import annotations

import argparse
import json

import pandas as pd

from . import config
from .benchmark_labeller import iter_alerts, label_alert, load_answer_key
from .features import extract_features


def build(report_path: str, out_path=None) -> pd.DataFrame:
    out_path = out_path or config.DATASET
    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)

    answer_key = load_answer_key()
    rows, skipped = [], 0
    for alert in iter_alerts(report):
        label = label_alert(alert, answer_key)
        if label is None:
            skipped += 1
            continue
        row = extract_features(alert)
        row["label"] = label
        row["alert_name"] = alert.get("name", "")
        rows.append(row)

    df = pd.DataFrame(rows)
    df.to_csv(out_path, index=False)

    n_tp = int((df["label"] == 1).sum()) if len(df) else 0
    n_fp = int((df["label"] == 0).sum()) if len(df) else 0
    print(f"Labelled {len(df)} alerts  ->  {n_tp} true positives, {n_fp} false positives")
    print(f"Skipped {skipped} alerts not tied to a Benchmark test case")
    print(f"Saved: {out_path}")
    return df


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("report", help="Path to the ZAP JSON report")
    args = ap.parse_args()
    build(args.report)
