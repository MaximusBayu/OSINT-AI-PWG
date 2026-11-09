"""GHunt wrapper: Google account OSINT from an email (name, public identity).

Requires an authenticated GHunt session (``ghunt login``) in the container's home. Without
it the CLI exits non-zero and this collector yields nothing — it is wired but dormant.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterator

from osint_ai_pwg.collect.base import Collector
from osint_ai_pwg.schemas import Directness, FieldGroup, Observation


def _walk(obj: Any, key: str) -> Iterator[str]:
    """Yield every string stored under ``key``, at any depth (GHunt's JSON drifts)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key and isinstance(v, str) and v.strip():
                yield v.strip()
            else:
                yield from _walk(v, key)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v, key)


class GhuntCollector(Collector):
    name = "ghunt"

    def collect(self, target_id: str, seed: dict[str, str]) -> list[Observation]:
        email = seed.get("email")
        if not email:
            return []
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "ghunt.json"
            try:
                subprocess.run(
                    ["ghunt", "email", email, "--json", str(out)],
                    capture_output=True, text=True, timeout=45, env=dict(os.environ),
                )
            except Exception:
                return []
            if not out.exists():
                return []
            try:
                data = json.loads(out.read_text(encoding="utf-8"))
            except Exception:
                return []

        obs: list[Observation] = []
        found_name = next(_walk(data, "name"), "")
        if found_name:
            obs.append(Observation(target_id, "name", FieldGroup.IDENTITY, found_name,
                                   "ghunt:google", Directness.STATED))
        found_email = next(_walk(data, "email"), "")
        if found_email and "@" in found_email:
            obs.append(Observation(target_id, "email", FieldGroup.IDENTITY, found_email,
                                   "ghunt:google", Directness.STATED))
        return obs
