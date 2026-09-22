"""Unit tests for the active verifier (offline — HTTP is mocked)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import src.verify as v


class _Resp:
    def __init__(self, text):
        self.text = text


def test_refuses_external_target():
    verdict = v.verify_finding("xss", "http://example.com/x", "q")
    assert verdict.result == "SKIPPED"


def test_allows_localhost():
    assert v._is_authorised("http://localhost:3000/x")
    assert v._is_authorised("http://127.0.0.1/x")


def test_xss_confirmed_when_reflected(monkeypatch):
    monkeypatch.setattr(v, "_get", lambda url, params=None, timeout=15:
                        _Resp(f"<div><script>{v.XSS_MARKER}</script></div>"))
    assert v.verify_xss("http://localhost/x", "q").result == "CONFIRMED"


def test_xss_unconfirmed_when_encoded(monkeypatch):
    monkeypatch.setattr(v, "_get", lambda url, params=None, timeout=15:
                        _Resp(f"&lt;script&gt;{v.XSS_MARKER}&lt;/script&gt;"))
    assert v.verify_xss("http://localhost/x", "q").result == "UNCONFIRMED"


def test_sqli_confirmed_on_db_error(monkeypatch):
    monkeypatch.setattr(v, "_get", lambda url, params=None, timeout=15:
                        _Resp("You have an error in your SQL syntax near '''"))
    assert v.verify_sqli("http://localhost/x", "q").result == "CONFIRMED"
