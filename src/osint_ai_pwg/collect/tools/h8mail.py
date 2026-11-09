"""h8mail wrapper: email -> breach exposure + recovered PII (username, name, email).

h8mail queries breach services (Scylla, HunterIO by default; Snusbase, Leak-Lookup,
HaveIBeenPwned, EmailRep, Dehashed with an optional API-key config) for a target email
and returns any leaked fields. This is a different signal from the footprint tools: it
recovers identity fields straight from breach dumps. Runs `h8mail -t <email> -j <file>`
in a temp dir and reads the JSON it writes.

API keys: pass `H8MAIL_CONFIG=/path/to/h8mail.ini` (the `--gen-config` template) to hit
the keyed sources; without it h8mail still checks the free defaults (Scylla + HunterIO).
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from osint_ai_pwg.collect.base import Collector
from osint_ai_pwg.schemas import Directness, FieldGroup, Observation

ReportRunner = Callable[[list[str]], dict]

# h8mail prefixes its fields with the source service. Map those to a clean name.
_SERVICES = {
    "SCYLLA": "scylla",
    "SNUS": "snusbase",
    "LKLP": "leaklookup",
    "HIBP3": "haveibeenpwned",
    "EMAILREP": "emailrep",
    "HUNTER": "hunter.io",
}


def _default_report(cmd: list[str]) -> dict:
    """Run h8mail in a temp dir and return its `-j` JSON output as a dict."""
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "h8mail.json"
        subprocess.run([*cmd, "-j", str(out)], capture_output=True, text=True, timeout=45)
        if not out.exists():
            return {}
        return json.loads(out.read_text(encoding="utf-8"))


def _flatten(data: list) -> list[tuple[str, str]]:
    """h8mail's JSON `data` is a list of groups, each a list of "FIELD:value" strings."""
    pairs: list[tuple[str, str]] = []
    for group in data or []:
        for item in group or []:
            if isinstance(item, str) and ":" in item:
                field, _, value = item.partition(":")
                pairs.append((field.strip(), value.strip()))
    return pairs


def _service_of(field: str) -> str:
    for prefix, name in _SERVICES.items():
        if field.startswith(prefix):
            return name
    return "breach"


def _map(data: dict, target_id: str) -> list[Observation]:
    """Map h8mail's flat `data` to identity observations (username/name/email).

    Breach passwords/hashes/IPs are deliberately NOT mapped — the collect layer recovers
    PII to guess *from*, and the leaked password is the guess target, not an input.
    """
    obs: list[Observation] = []
    targets = (data or {}).get("targets") or []
    for target in targets:
        for field, value in _flatten(target.get("data")):
            if not value:
                continue
            src = f"h8mail:{_service_of(field)}"
            if field.endswith("_USERNAME"):
                obs.append(Observation(target_id, "username", FieldGroup.IDENTITY, value, src, Directness.STATED))
            elif field.endswith("_NAME"):
                obs.append(Observation(target_id, "name", FieldGroup.IDENTITY, value, src, Directness.STATED))
            elif field.endswith("_EMAIL"):
                obs.append(Observation(target_id, "email", FieldGroup.IDENTITY, value, src, Directness.STATED))
    return obs


class H8mailCollector(Collector):
    name = "h8mail"

    def __init__(self, report_runner: ReportRunner | None = None) -> None:
        self._report = report_runner or _default_report

    def collect(self, target_id: str, seed: dict[str, str]) -> list[Observation]:
        email = seed.get("email")
        if not email:
            return []
        cmd = ["h8mail", "-t", email]
        cfg = os.environ.get("H8MAIL_CONFIG")
        if cfg:
            cmd += ["-c", cfg]
        try:
            data = self._report(cmd)
        except Exception:  # never raise (Collector contract: partial-failure tolerance)
            return []
        return _map(data, target_id)
