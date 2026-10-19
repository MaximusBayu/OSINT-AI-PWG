"""theHarvester collector: HTTP client for a hosted restfulHarvest instance.

theHarvester enumerates DNS/email for a DOMAIN; the seed's email supplies that domain.
Queries the restfulHarvest `/query` endpoint and maps returned emails to Identity
observations. Hosts/subdomains are infrastructure, not personal PII — they carry no
9-field slot, so they are dropped.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

from osint_ai_pwg.collect.base import Collector
from osint_ai_pwg.schemas import Directness, FieldGroup, Observation

name = "theharvester"

# Free DNS/email sources (no API key). goog/bing were removed in theHarvester 4.11.0.
_DEFAULT_SOURCES = ["crtsh", "hackertarget", "dnsdumpster", "duckduckgo", "brave"]


class HttpClient:
    """Minimal stdlib HTTP GET client (no requests dependency)."""

    def get(self, url: str, timeout: float = 30.0) -> str:
        with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 (user-configured host)
            return r.read().decode("utf-8", "replace")


class TheHarvesterCollector(Collector):
    name = "theharvester"

    def __init__(
        self,
        base_url: str,
        http: HttpClient | None = None,
        sources: list[str] | None = None,
        limit: int = 500,
    ) -> None:
        self.base = base_url.rstrip("/")
        self._http = http or HttpClient()
        self._sources = list(sources or _DEFAULT_SOURCES)
        self._limit = limit

    @staticmethod
    def _domain_from(seed: dict[str, str]) -> str:
        email = seed.get("email", "")
        if "@" in email:
            return email.rsplit("@", 1)[1].strip()
        return seed.get("domain", "").strip()

    def _query(self, domain: str) -> str:
        q = urllib.parse.urlencode(
            {"domain": domain, "source": ",".join(self._sources), "limit": self._limit}
        )
        return self._http.get(f"{self.base}/query?{q}")

    def collect(self, target_id: str, seed: dict[str, str]) -> list[Observation]:
        domain = self._domain_from(seed)
        if not domain:
            return []
        try:
            data = json.loads(self._query(domain))
        except Exception:  # network / JSON / rate-limit: never sink the pipeline
            return []
        if not isinstance(data, dict):
            return []
        obs: list[Observation] = []
        for email in data.get("emails", []) or []:
            if isinstance(email, str) and email.strip():
                obs.append(
                    Observation(
                        target_id=target_id,
                        field="email",
                        group=FieldGroup.IDENTITY,
                        value=email.strip(),
                        source="theharvester:restful",
                        directness=Directness.STATED,
                    )
                )
        return obs
