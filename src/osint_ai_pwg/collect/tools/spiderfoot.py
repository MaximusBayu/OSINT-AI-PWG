"""Real SpiderFoot collector (HTTP client for a hosted SpiderFoot 4.x instance).

Lifecycle: start a passive scan on the seed identifier, poll until finished, pull the
JSON results, map SpiderFoot event types to our Observation fields.

The HTTP client is injectable so the mapping/polling logic is testable without a live
instance. Against a real instance, verify the exact /startscan and results shapes — they
vary a little across SpiderFoot builds; the parse helpers are isolated for that reason.

BLOCKS for the duration of the scan (minutes) — run it inside a background job, not a
request handler.
"""

from __future__ import annotations

import ast
import json
import re
import time
import urllib.parse
import urllib.request

from osint_ai_pwg.collect.base import Collector
from osint_ai_pwg.schemas import Directness, FieldGroup, Observation

name = "spiderfoot"

# SpiderFoot event type -> (our field, group). Only PII we can use downstream.
SF_MAP: dict[str, tuple[str, FieldGroup]] = {
    "EMAILADDR": ("email", FieldGroup.IDENTITY),   # revised taxonomy: email is Identity
    "HUMAN_NAME": ("name", FieldGroup.IDENTITY),
    "USERNAME": ("username", FieldGroup.IDENTITY),
    "ACCOUNT_EXTERNAL_OWNED": ("username", FieldGroup.IDENTITY),
    "PHONE_NUMBER": ("phone", FieldGroup.CONTACT),
    "GEOINFO": ("city", FieldGroup.LOCATION),
    "PHYSICAL_ADDRESS": ("city", FieldGroup.LOCATION),
}

_TERMINAL = {"FINISHED", "ABORTED", "ERROR-FAILED", "FAILED"}


class HttpClient:
    """Minimal stdlib HTTP client (no requests dependency).

    Sends `Accept: application/json` — without it SpiderFoot returns its HTML UI instead
    of the JSON API responses the collector parses.
    """

    def get(self, url: str) -> str:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 (user-configured host)
            return r.read().decode("utf-8", "replace")

    def post(self, url: str, data: dict) -> str:
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(url, data=body, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310
            return r.read().decode("utf-8", "replace")


class SpiderFootCollector(Collector):
    name = "spiderfoot"

    def __init__(self, base_url: str, http: HttpClient | None = None,
                 poll_interval: float = 5.0, timeout_s: float = 90.0) -> None:
        self.base = base_url.rstrip("/")
        self._http = http or HttpClient()
        self._poll = poll_interval
        self._timeout = timeout_s

    # --- lifecycle ---------------------------------------------------------
    def _start(self, target: str, scan_name: str) -> str:
        resp = self._http.post(self.base + "/startscan", {
            "scanname": scan_name,
            "scantarget": target,
            "usecase": "Passive",   # passive modules only — no active probing
            "modulelist": "",
            "typelist": "",
        })
        return self._parse_scan_id(resp)

    def _status(self, scan_id: str) -> str:
        resp = self._http.get(self.base + f"/scanstatus?id={urllib.parse.quote(scan_id)}")
        data = json.loads(resp)
        # SpiderFoot v4 returns [name, target, created, started, ended, STATUS, counts]
        return str(data[5]).upper() if isinstance(data, list) and len(data) > 5 else "UNKNOWN"

    def _results(self, scan_id: str) -> list[dict]:
        resp = self._http.get(self.base + f"/scanexportjsonmulti?ids={urllib.parse.quote(scan_id)}")
        data = json.loads(resp)
        return data if isinstance(data, list) else []

    # --- parsing (isolated so a real instance's quirks are easy to adjust) --
    @staticmethod
    def _parse_scan_id(resp: str) -> str:
        try:
            data = json.loads(resp)
        except json.JSONDecodeError:
            return resp.strip().strip('"')
        if isinstance(data, list) and len(data) >= 2 and str(data[0]).upper() == "SUCCESS":
            return str(data[1])
        if isinstance(data, str):
            return data
        raise RuntimeError(f"unexpected /startscan response: {resp[:120]}")

    @staticmethod
    def _source_url(row: dict) -> str:
        """Best-effort proof URL from a SpiderFoot export row.

        SpiderFoot stores the source URL inside `source_data` (a Python dict repr
        string, e.g. "{'profileUrl': 'https://gravatar.com/...', ...}"). Fall back to
        the first http(s) URL in the raw string.
        """
        sd = row.get("source_data")
        if isinstance(sd, str) and sd.strip():
            try:
                d = ast.literal_eval(sd)
                if isinstance(d, dict):
                    url = d.get("profileUrl") or d.get("url") or d.get("link")
                    if url:
                        return str(url)
            except (ValueError, SyntaxError):
                pass
            m = re.search(r"https?://[^\s'\"<>]+", sd)
            if m:
                return m.group(0).rstrip("'\"")
        return ""

    def _map(self, target_id: str, rows: list[dict]) -> list[Observation]:
        obs: list[Observation] = []
        for row in rows:
            # SpiderFoot v4 export uses lowercase keys; event type is 'event_type'.
            etype = row.get("event_type") or row.get("Type") or row.get("type")
            value = row.get("data") or row.get("Data")
            module = row.get("module") or row.get("Module") or "spiderfoot"
            mapped = SF_MAP.get(etype or "")
            if not mapped or not value:
                continue
            field, group = mapped
            obs.append(Observation(
                target_id, field, group, str(value),
                f"spiderfoot:{module}", Directness.STATED, url=self._source_url(row),
            ))
        return obs

    # --- Collector interface ----------------------------------------------
    def collect(self, target_id: str, seed: dict[str, str]) -> list[Observation]:
        target = seed.get("email") or seed.get("username") or seed.get("name")
        if not target:
            return []
        try:
            scan_id = self._start(target, scan_name=f"pwg-{target_id}")
            deadline = time.time() + self._timeout
            while time.time() < deadline:
                if self._status(scan_id) in _TERMINAL:
                    break
                time.sleep(self._poll)
            return self._map(target_id, self._results(scan_id))
        except Exception:  # never sink the pipeline on a tool failure (Collector contract)
            return []
