"""Maigret wrapper: username -> sites + extracted PII (name, location).

Maigret searches ~8000 sites for a username and, where a profile is claimed, extracts
extra data (fullname, location, avatar, etc.) via socid-extractor. That yields more PII
fields than Sherlock, which only confirms presence. Runs `maigret <user> --json simple`
in a temp dir and reads the generated report file.
"""

from __future__ import annotations

import glob
import json
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from osint_ai_pwg.collect.base import Collector
from osint_ai_pwg.schemas import Directness, FieldGroup, Observation

name = "maigret"

ReportRunner = Callable[[list[str]], dict]


def _default_report(cmd: list[str]) -> dict:
    """Run maigret in a temp dir and return its `--json simple` report as a dict."""
    with tempfile.TemporaryDirectory() as td:
        subprocess.run(cmd, capture_output=True, text=True, timeout=75, cwd=td)
        hits = glob.glob(str(Path(td) / "reports" / "report_*_simple.json"))
        if not hits:
            return {}
        return json.loads(Path(hits[0]).read_text(encoding="utf-8"))


class MaigretCollector(Collector):
    name = "maigret"

    def __init__(self, report_runner: ReportRunner | None = None) -> None:
        self._report = report_runner or _default_report

    def collect(self, target_id: str, seed: dict[str, str]) -> list[Observation]:
        username = seed.get("username")
        if not username:
            return []
        try:
            data = self._report(
                ["maigret", username, "--json", "simple", "--no-recursion", "--timeout", "20"]
            )
        except Exception:  # never raise (Collector contract: partial-failure tolerance)
            return []
        return _map(data, target_id, username)


def _map(data: dict, target_id: str, username: str) -> list[Observation]:
    """Map a Maigret `--json simple` report to observations.

    For each site with status "Claimed", record the username confirmation plus any
    extracted fullname (Identity/name) and location (Location/city). Location is a
    best-effort mapping: Maigret reports a free-text string that is usually a city but
    may be a region or country. The profile URL (`url_user`) is attached as proof.
    """
    obs: list[Observation] = []
    for site_name, entry in (data or {}).items():
        if not isinstance(entry, dict):
            continue
        status = entry.get("status") or {}
        if status.get("status") != "Claimed":
            continue
        tag = site_name.split(" [")[0].strip().lower() or "unknown"
        url = (entry.get("url_user") or "").strip()
        obs.append(
            Observation(
                target_id=target_id,
                field="username",
                group=FieldGroup.IDENTITY,
                value=username,
                source=f"maigret:{tag}",
                directness=Directness.STATED,
                url=url,
            )
        )
        ids = status.get("ids") or {}
        fullname = (ids.get("fullname") or "").strip()
        if fullname:
            obs.append(
                Observation(
                    target_id=target_id,
                    field="name",
                    group=FieldGroup.IDENTITY,
                    value=fullname,
                    source=f"maigret:{tag}",
                    directness=Directness.STATED,
                    url=url,
                )
            )
        location = (ids.get("location") or "").strip()
        if location:
            obs.append(
                Observation(
                    target_id=target_id,
                    field="city",
                    group=FieldGroup.LOCATION,
                    value=location,
                    source=f"maigret:{tag}",
                    directness=Directness.STATED,
                    url=url,
                )
            )
    return obs
