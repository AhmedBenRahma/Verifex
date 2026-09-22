"""
Ground-truth labelling against the OWASP Benchmark answer key.

OWASP Benchmark ships 2,740 test cases, each tagged in expectedresults-1.2.csv
with its true category, whether it is a real vulnerability, and its CWE. Every
Benchmark URL contains a test id like ``BenchmarkTest01234``.

This module joins each ZAP alert to its test case and assigns a ground-truth
label, so a scan produces thousands of labelled rows with no manual work:

    label = 1  (true positive)  -> ZAP flagged the right vulnerability class
                                    on a test case that really is vulnerable
    label = 0  (false positive) -> ZAP flagged it, but the test case is safe
                                    (or ZAP flagged the wrong class)

Note on scope: ZAP is a DAST tool, so it exercises the injection-family
categories (SQLi, XSS, command injection, path traversal, ...). SAST-only
categories such as weak randomness or weak hashing produce no ZAP alerts and
simply do not appear as rows. That is expected and is stated in the report.
"""
from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path

from . import config

# Canonical CWE for each Benchmark category ZAP can plausibly detect.
CATEGORY_CWE = {
    "cmdi": 78,
    "xss": 79,
    "sqli": 89,
    "pathtraver": 22,
    "ldapi": 90,
    "xpathi": 643,
    "securecookie": 614,
    "trustbound": 501,
    "crypto": 327,
    "hash": 328,
    "weakrand": 330,
}

# Map a ZAP alert CWE to a Benchmark category (inverse of the table above,
# plus a few CWEs ZAP uses that are equivalent for scoring purposes).
CWE_TO_CATEGORY = {cwe: cat for cat, cwe in CATEGORY_CWE.items()}
CWE_TO_CATEGORY.update(
    {
        943: "sqli",   # ZAP sometimes reports SQLi-family under CWE-943
        80: "xss",     # basic XSS
        77: "cmdi",    # command injection (generic)
        98: "pathtraver",  # RFI/LFI-adjacent
    }
)

TEST_ID_RE = re.compile(r"BenchmarkTest(\d{5})", re.IGNORECASE)


@dataclass
class TestCase:
    category: str
    real: bool
    cwe: int


def load_answer_key(path: Path | None = None) -> dict[str, TestCase]:
    """Load expectedresults-1.2.csv into {test_id: TestCase}."""
    path = path or config.ANSWER_KEY
    key: dict[str, TestCase] = {}
    with open(path, encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)  # header / version comment line
        for row in reader:
            if len(row) < 4 or not row[0].strip():
                continue
            test_id = row[0].strip()
            key[test_id.lower()] = TestCase(
                category=row[1].strip(),
                real=row[2].strip().lower() == "true",
                cwe=int(row[3].strip()) if row[3].strip().isdigit() else -1,
            )
    return key


def extract_test_id(url: str) -> str | None:
    m = TEST_ID_RE.search(url or "")
    return f"BenchmarkTest{m.group(1)}".lower() if m else None


def label_alert(alert: dict, answer_key: dict[str, TestCase]) -> int | None:
    """Return 1 (true positive), 0 (false positive), or None if the alert
    cannot be tied to a Benchmark test case."""
    instances = alert.get("instances") or []
    url = instances[0].get("uri", "") if instances else alert.get("url", "")
    test_id = extract_test_id(url)
    if test_id is None or test_id not in answer_key:
        return None

    case = answer_key[test_id]
    zap_cwe = int(alert.get("cweid", 0) or 0)
    zap_category = CWE_TO_CATEGORY.get(zap_cwe)

    # True positive: ZAP flagged the correct vulnerability class on a test
    # case that really is vulnerable. Everything else ZAP reports here is a
    # false positive against ground truth.
    if zap_category == case.category and case.real:
        return 1
    return 0


def iter_alerts(zap_report: dict):
    """Yield alerts from a ZAP JSON report (both API and desktop shapes)."""
    if "site" in zap_report:
        for site in zap_report.get("site", []):
            yield from site.get("alerts", [])
    elif "alerts" in zap_report:
        yield from zap_report["alerts"]
