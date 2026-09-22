"""
MCP server for the Smart Security Testing Module.

Exposes the trained triage model to an MCP client (e.g. Claude Desktop) so an
assistant can, in natural language:

  - triage a ZAP report (how many real findings vs noise);
  - list the confirmed findings;
  - explain why a given alert was judged real or noise;
  - suggest payloads to re-verify a finding.

Run (stdio):  python -m src.mcp_server
Register it in Claude Desktop's config as a command server (see docs/MCP.md).
"""
from __future__ import annotations

import json

import joblib
import pandas as pd

# mcp 1.x exposes FastMCP; mcp 2.x renamed it to MCPServer. Support both.
try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    from mcp.server.mcpserver import MCPServer as FastMCP

from . import config
from .benchmark_labeller import iter_alerts
from .features import FEATURE_COLUMNS, extract_features
from .payloads import suggest

mcp = FastMCP("smart-security-testing-module")


def _load():
    bundle = joblib.load(config.MODEL_PATH)
    return bundle["model"], bundle["name"]


def _read_report(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return list(iter_alerts(json.load(f)))


@mcp.tool()
def triage_report(report_path: str) -> dict:
    """Triage a ZAP JSON report: how many alerts are real findings vs noise."""
    model, name = _load()
    alerts = _read_report(report_path)
    X = pd.DataFrame([extract_features(a) for a in alerts], columns=FEATURE_COLUMNS)
    pred = model.predict(X)
    real = int(pred.sum())
    return {
        "model": name,
        "total_alerts": len(alerts),
        "real_findings": real,
        "noise_filtered": len(alerts) - real,
        "review_reduction": f"{(1 - real / len(alerts)) * 100:.0f}%" if alerts else "n/a",
    }


@mcp.tool()
def list_findings(report_path: str, limit: int = 20) -> list[dict]:
    """List the confirmed real findings from a ZAP report, most confident first."""
    model, _ = _load()
    alerts = _read_report(report_path)
    X = pd.DataFrame([extract_features(a) for a in alerts], columns=FEATURE_COLUMNS)
    proba = model.predict_proba(X)[:, 1]
    pred = model.predict(X)
    findings = []
    for a, p, pr in zip(alerts, pred, proba):
        if p == 1:
            inst = (a.get("instances") or [{}])[0]
            findings.append({
                "vulnerability": a.get("name"),
                "url": a.get("url") or inst.get("uri"),
                "confidence": round(float(pr), 3),
            })
    findings.sort(key=lambda f: f["confidence"], reverse=True)
    return findings[:limit]


@mcp.tool()
def explain_finding(report_path: str, index: int) -> dict:
    """Explain why alert #index was judged real or noise (probability + features)."""
    model, _ = _load()
    alerts = _read_report(report_path)
    if not 0 <= index < len(alerts):
        return {"error": f"index out of range (0..{len(alerts) - 1})"}
    a = alerts[index]
    feats = extract_features(a)
    X = pd.DataFrame([feats], columns=FEATURE_COLUMNS)
    proba = float(model.predict_proba(X)[0, 1])
    return {
        "vulnerability": a.get("name"),
        "verdict": "real finding" if proba >= 0.5 else "noise / false positive",
        "confidence": round(proba, 3),
        "features": feats,
    }


@mcp.tool()
def suggest_payloads(vulnerability: str) -> dict:
    """Suggest re-verification payloads for a confirmed vulnerability class."""
    return suggest(vulnerability) or {"note": "No payload template for this class yet."}


if __name__ == "__main__":
    mcp.run()
