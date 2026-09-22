"""
Active verification of confirmed findings (the closed loop).

For a finding the model flagged as real, this actually sends a payload to the
endpoint and inspects the response for proof of exploitation, returning a
verdict: CONFIRMED, UNCONFIRMED, or ERROR.

Techniques (safe, evidence-based):
  - XSS              : is the payload reflected UNENCODED in the response body?
  - SQL Injection    : does a probe trigger a database error, or a measurable
                       time delay (SLEEP) vs a baseline request?
  - Command Injection: does a time-based probe delay the response vs baseline?

SAFETY: only authorised targets. By default this refuses any host that is not
localhost / 127.0.0.1 / a private address unless allow_external=True is passed
explicitly. Payloads are benign probes (alert markers, SLEEP timings) — never
destructive.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

SQL_ERROR_SIGNS = (
    "sql syntax", "mysql", "sqlite", "psql", "postgresql", "odbc", "ora-",
    "you have an error in your sql", "unclosed quotation mark", "quoted string not properly terminated",
)
XSS_MARKER = "ssvm7x9z"          # unique, harmless marker
TIME_DELAY = 5                    # seconds for time-based probes
DELAY_TOLERANCE = 3              # min extra seconds over baseline to count


@dataclass
class Verdict:
    finding: str
    url: str
    technique: str
    result: str                  # CONFIRMED | UNCONFIRMED | ERROR | SKIPPED
    evidence: str = ""
    payload: str = ""
    extra: dict = field(default_factory=dict)


def _is_authorised(url: str) -> bool:
    host = urlparse(url).hostname or ""
    if host in ("localhost",):
        return True
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return ip.is_loopback or ip.is_private
    except Exception:
        return False


def _get(url: str, params=None, timeout=15):
    return requests.get(url, params=params, timeout=timeout)


def verify_xss(url: str, param: str) -> Verdict:
    payload = f"<script>{XSS_MARKER}</script>"
    try:
        r = _get(url, params={param: payload} if param else None)
        reflected = payload in r.text
        return Verdict("XSS", url, "reflection", "CONFIRMED" if reflected else "UNCONFIRMED",
                       evidence="payload reflected unencoded" if reflected else "payload not reflected unencoded",
                       payload=payload)
    except Exception as e:
        return Verdict("XSS", url, "reflection", "ERROR", evidence=str(e), payload=payload)


def verify_sqli(url: str, param: str) -> Verdict:
    # 1) error-based
    err_payload = "'"
    try:
        r = _get(url, params={param: err_payload} if param else None)
        low = r.text.lower()
        for sign in SQL_ERROR_SIGNS:
            if sign in low:
                return Verdict("SQL Injection", url, "error-based", "CONFIRMED",
                               evidence=f"database error signature: '{sign}'", payload=err_payload)
    except Exception as e:
        return Verdict("SQL Injection", url, "error-based", "ERROR", evidence=str(e), payload=err_payload)

    # 2) time-based
    base = time.time()
    try:
        _get(url, params={param: "1"} if param else None)
        baseline = time.time() - base
        t_payload = f"1' AND SLEEP({TIME_DELAY})-- -"
        start = time.time()
        _get(url, params={param: t_payload} if param else None, timeout=TIME_DELAY + 15)
        elapsed = time.time() - start
        if elapsed - baseline >= DELAY_TOLERANCE:
            return Verdict("SQL Injection", url, "time-based", "CONFIRMED",
                           evidence=f"response delayed {elapsed:.1f}s vs {baseline:.1f}s baseline", payload=t_payload)
        return Verdict("SQL Injection", url, "time-based", "UNCONFIRMED",
                       evidence=f"no delay ({elapsed:.1f}s vs {baseline:.1f}s)", payload=t_payload)
    except Exception as e:
        return Verdict("SQL Injection", url, "time-based", "ERROR", evidence=str(e))


def verify_cmdi(url: str, param: str) -> Verdict:
    base = time.time()
    try:
        _get(url, params={param: "x"} if param else None)
        baseline = time.time() - base
        payload = f"; sleep {TIME_DELAY}"
        start = time.time()
        _get(url, params={param: payload} if param else None, timeout=TIME_DELAY + 15)
        elapsed = time.time() - start
        if elapsed - baseline >= DELAY_TOLERANCE:
            return Verdict("Command Injection", url, "time-based", "CONFIRMED",
                           evidence=f"response delayed {elapsed:.1f}s vs {baseline:.1f}s baseline", payload=payload)
        return Verdict("Command Injection", url, "time-based", "UNCONFIRMED",
                       evidence=f"no delay ({elapsed:.1f}s vs {baseline:.1f}s)", payload=payload)
    except Exception as e:
        return Verdict("Command Injection", url, "time-based", "ERROR", evidence=str(e))


VERIFIERS = {
    "xss": verify_xss,
    "sqli": verify_sqli,
    "cmdi": verify_cmdi,
}


def verify_finding(category: str, url: str, param: str, allow_external: bool = False) -> Verdict:
    """Verify one finding. `category` is a benchmark category (xss/sqli/cmdi)."""
    if not allow_external and not _is_authorised(url):
        return Verdict(category, url, "-", "SKIPPED",
                       evidence="target is not localhost/private; refused (authorised targets only)")
    fn = VERIFIERS.get(category)
    if fn is None:
        return Verdict(category, url, "-", "SKIPPED", evidence="no verifier for this category")
    return fn(url, param)
