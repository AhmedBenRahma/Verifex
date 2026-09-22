"""
Local demo of the MCP tools — proves the server's tools work, no Claude Desktop.

    python -m scripts.mcp_demo

Calls the exact tool functions the MCP server exposes, against the bundled
sample report, and prints what an AI assistant would receive. (This runs the
tools in-process, which is reliable on every Python version. Claude Desktop
talks to the same tools over the MCP protocol — see docs/MCP.md.)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import mcp_server as srv

REPORT = "data/sample_report.json"


def show(title, value):
    print(f"\n--- {title} ---")
    print(json.dumps(value, indent=2, ensure_ascii=False))


def main() -> None:
    print("MCP tools exposed by the server:")
    print("  triage_report · list_findings · explain_finding · suggest_payloads")

    show("triage_report", srv.triage_report(REPORT))
    show("list_findings (top 5)", srv.list_findings(REPORT, limit=5))
    show("explain_finding #0", srv.explain_finding(REPORT, 0))
    show("suggest_payloads (XSS)", srv.suggest_payloads("Cross Site Scripting (Reflected)"))


if __name__ == "__main__":
    main()