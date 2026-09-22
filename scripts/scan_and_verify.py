"""
Closed loop: scan a target -> triage with the model -> actively verify the
confirmed findings -> write an HTML report. This is the full brief in one run.

    python -m scripts.scan_and_verify --target http://localhost:3000

Defaults to the lab target in .env. AUTHORISED TARGETS ONLY: verification sends
probe payloads, so it refuses non-local/non-private hosts unless you pass
--allow-external (use only with written authorisation).

Requires the ZAP lab up (docker compose up -d) and a trained model
(python -m src.train).
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import joblib
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import config
from src.benchmark_labeller import CWE_TO_CATEGORY
from src.features import FEATURE_COLUMNS, extract_features
from src.report import save_report
from src.verify import verify_finding
from src.zap_client import ZapClient

VERIFIABLE = {"xss", "sqli", "cmdi"}


def triage(alerts, model):
    X = pd.DataFrame([extract_features(a) for a in alerts], columns=FEATURE_COLUMNS)
    pred = model.predict(X)
    proba = model.predict_proba(X)[:, 1]
    rows = []
    for a, p, pr in zip(alerts, pred, proba):
        inst = (a.get("instances") or [{}])[0]
        rows.append({
            "Vulnerability": a.get("name", "Unknown"),
            "URL": a.get("url") or inst.get("uri", ""),
            "Risk": a.get("risk") or {3: "High", 2: "Medium", 1: "Low", 0: "Info"}.get(int(a.get("riskcode", 0) or 0), ""),
            "Verdict": "REAL" if p == 1 else "NOISE",
            "Confidence": float(pr),
            "cweid": int(a.get("cweid", 0) or 0),
            "param": inst.get("param", ""),
        })
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=config.TARGET_URL)
    ap.add_argument("--allow-external", action="store_true")
    ap.add_argument("--out", default=str(config.DATA_DIR / "report.html"))
    args = ap.parse_args()

    bundle = joblib.load(config.MODEL_PATH)
    model = bundle["model"]

    zap = ZapClient()
    if not zap.wait_until_ready(30):
        print(f"Cannot reach ZAP at {zap.base_url}. Is the lab up? (docker compose up -d)")
        return 1

    print(f"[1/4] Scanning {args.target}")
    zap.set_scan_threads(2)
    zap.spider(args.target)
    scan_id = zap.start_active_scan(args.target)
    while True:
        s = zap.active_scan_status(scan_id)
        print(f"  active scan: {s}%   ", end="\r", flush=True)
        if s >= 100:
            break
        time.sleep(5)
    alerts = zap.alerts(args.target)
    print(f"\n[2/4] {len(alerts)} alerts; triaging with {bundle['name']}")

    rows = triage(alerts, model)
    real = [r for r in rows if r["Verdict"] == "REAL"]
    print(f"       {len(real)} real findings, {len(rows) - len(real)} noise")

    print("[3/4] Verifying confirmed findings (sending probe payloads)")
    verdicts = []
    for r in real:
        cat = CWE_TO_CATEGORY.get(r["cweid"])
        if cat in VERIFIABLE:
            v = verify_finding(cat, r["URL"], r.get("param", ""), allow_external=args.allow_external)
            verdicts.append(vars(v))
            print(f"  {v.result:11s} {v.finding} @ {v.url[:60]}")

    print(f"[4/4] Writing report -> {args.out}")
    save_report(args.out, args.target, rows, verdicts, {"model": bundle["name"]})
    n_conf = sum(1 for v in verdicts if v["result"] == "CONFIRMED")
    print(f"\nDone. {len(real)} findings, {n_conf} confirmed exploitable. Open {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
