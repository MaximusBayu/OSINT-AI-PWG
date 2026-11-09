"""GitHub public REST API: username -> name, location, public email (no key needed).

This is the profile-extractor the pipeline was missing: it reads the profile rather than
merely confirming the handle exists. Unauthenticated rate limit is 60 requests/hour per
IP, and this makes exactly one request per run.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from collections.abc import Callable

from osint_ai_pwg.collect.base import Collector
from osint_ai_pwg.schemas import Directness, FieldGroup, Observation


class GitHubAPICollector(Collector):
    name = "github-api"

    def __init__(
        self,
        api_base: str = "https://api.github.com",
        fetch: Callable[[str], dict] | None = None,
    ) -> None:
        self.base = api_base.rstrip("/")
        self._fetch = fetch or self._http_get

    @staticmethod
    def _http_get(url: str) -> dict:
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "osint-ai-pwg",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310 (fixed API host)
            return json.load(r)

    def collect(self, target_id: str, seed: dict[str, str]) -> list[Observation]:
        user = seed.get("username")
        if not user:
            return []
        try:
            data = self._fetch(f"{self.base}/users/{urllib.parse.quote(user)}")
        except Exception:  # never raise (Collector contract)
            return []
        if not isinstance(data, dict) or data.get("message") == "Not Found":
            return []

        profile = str(data.get("html_url") or "")
        obs: list[Observation] = []
        if data.get("name"):
            obs.append(Observation(target_id, "name", FieldGroup.IDENTITY,
                                   str(data["name"]), "github-api:profile",
                                   Directness.STATED, url=profile))
        if data.get("location"):
            obs.append(Observation(target_id, "city", FieldGroup.LOCATION,
                                   str(data["location"]), "github-api:profile",
                                   Directness.STATED, url=profile))
        if data.get("email"):
            obs.append(Observation(target_id, "email", FieldGroup.IDENTITY,
                                   str(data["email"]), "github-api:profile",
                                   Directness.STATED, url=profile))
        return obs
