"""Unit tests for feature extraction (both ZAP alert shapes)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.features import FEATURE_COLUMNS, extract_features


def test_api_shape_words():
    a = {"name": "SQL Injection", "risk": "High", "confidence": "Medium", "cweid": "89",
         "url": "http://x/benchmark/sqli-00/BenchmarkTest00008", "param": "q",
         "evidence": "error", "solution": "use params"}
    f = extract_features(a)
    assert f["riskcode"] == 3          # High
    assert f["confidence"] == 2        # Medium
    assert f["cweid"] == 89
    assert f["has_param"] == 1
    assert f["has_solution"] == 1
    assert set(f) == set(FEATURE_COLUMNS)


def test_desktop_shape_numbers():
    b = {"name": "XSS", "riskcode": "2", "confidence": "2", "cweid": "79",
         "instances": [{"uri": "http://x/benchmark/xss-00/BenchmarkTest00013", "param": "p"}]}
    f = extract_features(b)
    assert f["riskcode"] == 2
    assert f["cweid"] == 79
    assert f["has_param"] == 1


def test_missing_fields_default_safely():
    f = extract_features({"name": "Bare"})
    assert f["riskcode"] == 0
    assert f["has_param"] == 0
    assert f["cweid"] == 0
