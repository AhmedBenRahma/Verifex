"""
Targeted, memory-safe scan of the injection categories.

    python -m scripts.run_scan

Scans one category at a time - SQL injection first, then command injection,
path traversal, XSS - restarting ZAP between each so its memory is released
and it cannot accumulate to a crash. Within a category it scans each
`/benchmark/<cat>-NN/` folder directly (plain recurse scan, no context), so it
only attacks that category's endpoints. Alerts are merged and snapshotted to
data/benchmark_report.json every 30s, so nothing is ever lost.

Requires the lab up (docker compose up -d) and ZAP_API_KEY in .env. The script
restarts the ZAP container itself via `docker compose restart zap`.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import config
from src.zap_client import ZapClient

CATEGORIES = ["sqli", "cmdi", "pathtraver", "xss"]
SNAPSHOT_EVERY = 60
SCAN_THREADS = 2
REPORT = config.DATA_DIR / "benchmark_report.json"


def restart_zap() -> None:
    print("  restarting ZAP to free memory...")
    subprocess.run(["docker", "compose", "restart", "zap"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def save(merged: dict) -> None:
    with open(REPORT, "w", encoding="utf-8") as f:
        json.dump({"site": [{"@name": config.TARGET_URL, "alerts": list(merged.values())}]}, f, indent=2)


def key(alert: dict) -> tuple:
    inst = (alert.get("instances") or [{}])[0]
    return (alert.get("name"), alert.get("url") or inst.get("uri"),
            alert.get("param") or inst.get("param"))


def merge(zap: ZapClient, target: str, merged: dict) -> bool:
    """Pull alerts and merge them. Returns False on a transient failure
    (never raises, so a snapshot hiccup can't kill the scan)."""
    try:
        for a in zap.alerts(target):
            merged[key(a)] = a
        return True
    except Exception as exc:
        print(f"\n  (snapshot skipped: {exc})")
        return False


def scan_category(cat: str, merged: dict) -> None:
    target = config.TARGET_URL
    zap = ZapClient()
    if not zap.wait_until_ready():
        print(f"  ZAP did not come back after restart; skipping {cat}")
        return

    zap.set_scan_threads(SCAN_THREADS)
    zap.spider(target)

    # Find this category's folders, e.g. .../benchmark/sqli-00/
    folders = sorted({
        m.group(0) for u in zap.urls(target)
        if (m := re.search(rf".*/benchmark/{cat}-\d+/", u))
    })
    if not folders:
        print(f"  no {cat} URLs discovered; skipping")
        return
    print(f"  {cat}: {len(folders)} folder(s) to scan")

    last = 0.0
    for i, folder in enumerate(folders, 1):
        try:
            scan_id = zap.start_active_scan(folder)
        except Exception as exc:
            print(f"    {cat} folder {i}: could not start ({exc}); skipping")
            continue
        while True:
            try:
                status = zap.active_scan_status(scan_id)
            except Exception as exc:
                print(f"\n  {cat}: ZAP interrupted ({exc}); keeping what was found.")
                merge(zap, target, merged); save(merged)
                return
            print(f"    {cat}: folder {i}/{len(folders)}  {status}%   ", end="\r", flush=True)
            if time.time() - last > SNAPSHOT_EVERY:
                if merge(zap, target, merged):
                    save(merged)
                last = time.time()
            if status >= 100:
                break
            time.sleep(5)

    if merge(zap, target, merged):
        save(merged)
    print(f"  {cat}: done. unique alerts so far: {len(merged)}   ")


def main() -> int:
    merged: dict = {}
    for cat in CATEGORIES:
        restart_zap()
        scan_category(cat, merged)
    print(f"\nAll categories done. {len(merged)} unique alerts in {REPORT}")
    print("Next:  python -m src.build_dataset data/benchmark_report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
