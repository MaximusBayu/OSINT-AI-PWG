"""Build the PassLLM input JSONL for a set of targets under one condition.

One line per target (a PassLLM PII object; C0 lines are '{}'). Line order is returned as
`order` so the engine's per-line outputs can be mapped back to target ids.
"""

from __future__ import annotations

import json
from pathlib import Path

from osint_ai_pwg.guess.prompt import build_passllm_object
from osint_ai_pwg.schemas import Condition, NormalizedProfile


def build_input(profiles: list[NormalizedProfile], condition: Condition) -> tuple[str, list[str]]:
    """Return (jsonl_text, order). order[i] is the target_id of line i."""
    order: list[str] = []
    lines: list[str] = []
    for prof in profiles:
        obj = build_passllm_object(prof, condition)
        order.append(prof.target_id)
        lines.append(json.dumps(obj))
    return "\n".join(lines) + ("\n" if lines else ""), order


def write_input(profiles: list[NormalizedProfile], condition: Condition, path: Path) -> list[str]:
    """Write the JSONL to `path`; return the target-id order for output mapping."""
    text, order = build_input(profiles, condition)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text, encoding="utf-8")
    return order
