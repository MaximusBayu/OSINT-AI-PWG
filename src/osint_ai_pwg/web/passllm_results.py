"""Store/load real PassLLM guess results (computed on Colab, imported to the VPS).

PassLLM needs a GPU, so it runs in Colab and its ranked guesses are shipped back here.
The web UI then shows the *real* guesses instead of the demo pattern-engine. Per-target
format::

    {"target_id": "max", "engine": "passllm",
     "conditions": {"C2": [{"password": "...", "confidence": 0.87, "log_score": -1.1}, ...]}}
"""

from __future__ import annotations

import json
from pathlib import Path


def _path(base: Path, target_id: str) -> Path:
    return Path(base) / f"{target_id}.json"


def load_results(base: Path, target_id: str) -> dict | None:
    p = _path(base, target_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def save_results(base: Path, target_id: str, payload: dict) -> None:
    Path(base).mkdir(parents=True, exist_ok=True)
    _path(base, target_id).write_text(json.dumps(payload, indent=2), encoding="utf-8")
