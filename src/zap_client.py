"""
Thin client over the OWASP ZAP REST API.

Drives a scan from code: spider, active scan, and pulling alerts. The API key
is read from the environment (see config.py) so nothing secret is in source.

Robustness on a memory-limited machine:
  - long request timeout + retries, so a slow reply does not crash the run;
  - the active scan is exposed as start + poll so the caller can snapshot
    alerts to disk while it runs (see scripts/run_scan.py);
  - thread count is tunable, to keep ZAP's peak memory low.
"""
from __future__ import annotations

import time
from typing import Any

import requests

from . import config

REQUEST_TIMEOUT = 180
MAX_RETRIES = 5
RETRY_WAIT = 10


class ZapClient:
    def __init__(self, base_url: str | None = None, api_key: str | None = None):
        self.base_url = (base_url or config.ZAP_BASE_URL).rstrip("/")
        self.api_key = api_key if api_key is not None else config.ZAP_API_KEY

    def _call(self, endpoint: str, params: dict[str, Any] | None = None) -> dict:
        params = dict(params or {})
        if self.api_key:
            params["apikey"] = self.api_key
        url = f"{self.base_url}{endpoint}"

        last_err: Exception | None = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
                resp.raise_for_status()
                return resp.json()
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as err:
                last_err = err
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_WAIT)
        raise last_err  # type: ignore[misc]

    # --- basics ------------------------------------------------------------
    def version(self) -> str:
        return self._call("/JSON/core/view/version/")["version"]

    def alerts(self, baseurl: str | None = None, page: int = 1000) -> list[dict]:
        """Pull alerts in pages, so a huge result never breaks mid-download."""
        out: list[dict] = []
        start = 0
        while True:
            params: dict[str, Any] = {"start": start, "count": page}
            if baseurl:
                params["baseurl"] = baseurl
            batch = self._call("/JSON/core/view/alerts/", params).get("alerts", [])
            out.extend(batch)
            if len(batch) < page:
                break
            start += page
        return out

    # --- spider ------------------------------------------------------------
    def spider(self, target: str, poll: float = 3.0) -> None:
        scan_id = self._call("/JSON/spider/action/scan/", {"url": target})["scan"]
        while True:
            status = int(self._call("/JSON/spider/view/status/", {"scanId": scan_id})["status"])
            print(f"  spider: {status}%   ", end="\r", flush=True)
            if status >= 100:
                break
            time.sleep(poll)
        print("  spider: done   ")

    # --- active scan (granular, so the caller can snapshot while it runs) ---
    def set_scan_threads(self, threads: int) -> None:
        """Lower this to reduce ZAP's peak memory on a small machine."""
        self._call("/JSON/ascan/action/setOptionThreadPerHost/", {"Integer": threads})

    def start_active_scan(self, target: str) -> str:
        return self._call("/JSON/ascan/action/scan/", {"url": target, "recurse": "true"})["scan"]

    def active_scan_status(self, scan_id: str) -> int:
        return int(self._call("/JSON/ascan/view/status/", {"scanId": scan_id})["status"])

    # --- readiness + contexts (for targeted, memory-safe scanning) ----------
    def wait_until_ready(self, timeout: float = 120) -> bool:
        """Poll until ZAP answers, after a container (re)start."""
        import time as _t
        deadline = _t.time() + timeout
        while _t.time() < deadline:
            try:
                self.version()
                return True
            except Exception:
                _t.sleep(3)
        return False

    def new_context(self, name: str) -> str:
        try:
            self._call("/JSON/context/action/newContext/", {"contextName": name})
        except Exception:
            pass  # already exists
        return self._call("/JSON/context/view/context/", {"contextName": name})["context"]["id"]

    def include_in_context(self, name: str, regex: str) -> None:
        self._call("/JSON/context/action/includeInContext/", {"contextName": name, "regex": regex})

    def start_active_scan_context(self, context_id: str, target: str) -> str:
        return self._call(
            "/JSON/ascan/action/scan/",
            {"url": target, "recurse": "true", "inScopeOnly": "false", "contextId": context_id},
        )["scan"]

    def urls(self, baseurl: str | None = None) -> list[str]:
        """All URLs ZAP has discovered (optionally under a base URL)."""
        params = {"baseurl": baseurl} if baseurl else {}
        return self._call("/JSON/core/view/urls/", params).get("urls", [])
