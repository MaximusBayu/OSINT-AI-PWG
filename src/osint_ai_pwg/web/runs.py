"""Persist the last pipeline result per target so the UI can revisit a searched profile.

The full result (observations, normalized profile, conditions, verdict) is written to
``data/runs/<target_id>.json`` after every run. ``/api/runs/<target_id>`` reads it back,
so a target stays browsable without re-running collection or guessing.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def run_path(out_dir: Path, target_id: str) -> Path:
    return Path(out_dir) / f"{target_id}.json"


def save_run(out_dir: Path, target_id: str, result: dict) -> Path:
    """Write a run result (stamped with ``saved_at``) and return its path."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = dict(result)
    payload["saved_at"] = datetime.now(timezone.utc).isoformat()
    path = run_path(out_dir, target_id)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def load_run(out_dir: Path, target_id: str) -> dict | None:
    """Read the last saved run for a target, or None."""
    path = run_path(out_dir, target_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
