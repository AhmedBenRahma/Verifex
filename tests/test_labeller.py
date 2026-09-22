"""
Unit tests for the ground-truth labeller.

The fixture below is a small, hand-built ZAP-style report using real Benchmark
test-case IDs. It verifies the join logic against the actual answer key - it is
a test fixture, not experimental results.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.benchmark_labeller import label_alert, load_answer_key, extract_test_id


def _alert(test_id: str, cweid: int, category_path: str = "sqli"):
    uri = f"https://localhost:8443/benchmark/{category_path}-00/{test_id}"
    return {"name": "SQL Injection", "cweid": cweid, "instances": [{"uri": uri, "param": "q"}]}


def test_test_id_extraction():
    assert extract_test_id("https://x/benchmark/sqli-00/BenchmarkTest00008") == "benchmarktest00008"
    assert extract_test_id("https://x/no-id-here") is None


def test_true_positive_sqli():
    key = load_answer_key()
    # BenchmarkTest00008 is a real SQLi (CWE-89); ZAP flags SQLi (CWE-89) -> TP
    assert label_alert(_alert("BenchmarkTest00008", 89), key) == 1


def test_false_positive_safe_case():
    key = load_answer_key()
    # BenchmarkTest00052 is a *safe* SQLi test case; a ZAP SQLi alert here -> FP
    assert label_alert(_alert("BenchmarkTest00052", 89), key) == 0


def test_wrong_class_is_false_positive():
    key = load_answer_key()
    # Real SQLi case, but ZAP reports XSS (CWE-79) -> wrong class -> FP
    assert label_alert(_alert("BenchmarkTest00008", 79), key) == 0


def test_unmapped_url_returns_none():
    key = load_answer_key()
    alert = {"name": "X", "cweid": 89, "instances": [{"uri": "https://localhost/other"}]}
    assert label_alert(alert, key) is None
