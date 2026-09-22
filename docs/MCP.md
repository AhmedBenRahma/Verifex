# Using the MCP server with Claude Desktop

The module ships an MCP server so an AI assistant can triage ZAP reports in
natural language ("how many real findings are in this scan?", "explain alert 3",
"what payloads verify this XSS?").


## Quickest test — no Claude Desktop needed

A bundled local client speaks the MCP protocol to the server and calls every
tool on the sample report:

```bash
python -m scripts.mcp_demo
```

Expected output: the four tools listed, then triage (465 alerts -> 165 real),
the top findings, one explanation, and XSS payloads. This proves the full
client <-> server <-> model round-trip on your own machine.

## Register it (optional — Claude Desktop front-end)

Add this to your Claude Desktop config
(`%APPDATA%\Claude\claude_desktop_config.json` on Windows,
`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "smart-security-testing-module": {
      "command": "python",
      "args": ["-m", "src.mcp_server"],
      "cwd": "C:/path/to/smart-security-testing-module"
    }
  }
}
```

Restart Claude Desktop. The server's tools appear in the tools menu.

## Tools

| Tool | What it does |
|------|--------------|
| `triage_report(report_path)` | Counts real findings vs noise in a ZAP JSON report |
| `list_findings(report_path, limit)` | Lists the confirmed findings, most confident first |
| `explain_finding(report_path, index)` | Probability + features behind one alert's verdict |
| `suggest_payloads(vulnerability)` | Re-verification payloads for a vulnerability class |

## Example conversation

> **You:** Triage data/benchmark_report.json
> **Claude:** 415 alerts — 165 real findings, 250 noise (60% less to review).
> **You:** List the top findings.
> **Claude:** Cross Site Scripting (Reflected) at …/BenchmarkTest00003 (100%), …
> **You:** What payloads verify that XSS?
> **Claude:** Basic: `<script>alert(1)</script>` …
