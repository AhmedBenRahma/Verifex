"""
Feature extraction from a ZAP alert.

Handles both ZAP alert shapes:
  - the REST API shape (risk/confidence as words: "High", "Medium", ...,
    fields url/param/evidence at the top level);
  - the desktop report shape (riskcode/confidence as 0..3, fields under
    instances[]).

Features describe what ZAP saw and how sure it was - never the ground truth,
so there is no label leakage.
"""
from __future__ import annotations

from urllib.parse import urlparse

import pandas as pd

SENSITIVE_MARKERS = ("login", "search", "user", "admin", "basket", "api", "token", "password")

# Word -> number, for the API shape. Numbers pass straight through.
RISK_LEVELS = {"informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3}
CONFIDENCE_LEVELS = {
    "false positive": 0, "low": 1, "medium": 2, "high": 3, "confirmed": 4,
}

FEATURE_COLUMNS = [
    "riskcode",
    "confidence",
    "cweid",
    "has_param",
    "url_depth",
    "sensitive_endpoint",
    "evidence_len",
    "has_solution",
    "alert_name_code",
]


def _to_level(value, table: dict[str, int]) -> int:
    """Accept a number, a numeric string, or a ZAP word like 'Medium'."""
    if value is None:
        return 0
    s = str(value).strip()
    if s.isdigit():
        return int(s)
    return table.get(s.lower(), 0)


def _field(alert: dict, name: str) -> str:
    """Read a field from the top level or the first instance, whichever has it."""
    if alert.get(name):
        return alert[name]
    instances = alert.get("instances") or []
    if instances and instances[0].get(name):
        return instances[0][name]
    # the desktop shape calls the URL 'uri' under instances
    if name == "url" and instances:
        return instances[0].get("uri", "")
    return ""


def extract_features(alert: dict) -> dict:
    url = _field(alert, "url")
    param = _field(alert, "param")
    evidence = _field(alert, "evidence")
    path = urlparse(url).path

    riskcode = _to_level(alert.get("riskcode", alert.get("risk")), RISK_LEVELS)
    confidence = _to_level(alert.get("confidence"), CONFIDENCE_LEVELS)
    cwe = alert.get("cweid", 0)
    cwe = int(cwe) if str(cwe).lstrip("-").isdigit() else 0

    return {
        "riskcode": riskcode,
        "confidence": confidence,
        "cweid": cwe,
        "has_param": 1 if param else 0,
        "url_depth": len([p for p in path.split("/") if p]),
        "sensitive_endpoint": 1 if any(m in url.lower() for m in SENSITIVE_MARKERS) else 0,
        "evidence_len": len(evidence),
        "has_solution": 1 if alert.get("solution") else 0,
        "alert_name_code": hash(alert.get("name", "")) % 10_000,
    }


def features_frame(alerts: list[dict]) -> pd.DataFrame:
    rows = [extract_features(a) for a in alerts]
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)
