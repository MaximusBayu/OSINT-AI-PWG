"""Persist Observations as JSONL under data/observations/ (gitignored)."""

from __future__ import annotations

import json
from pathlib import Path

from osint_ai_pwg.schemas import Directness, FieldGroup, Observation


def obs_to_dict(o: Observation) -> dict:
    return {
        "target_id": o.target_id,
        "field": o.field,
        "group": o.group.value,
        "value": o.value,
        "source": o.source,
        "directness": o.directness.value,
        "collected_at": o.collected_at,
    }


def obs_from_dict(d: dict) -> Observation:
    return Observation(
        target_id=d["target_id"],
        field=d["field"],
        group=FieldGroup(d["group"]),
        value=d["value"],
        source=d["source"],
        directness=Directness(d.get("directness", "stated")),
        collected_at=d["collected_at"],
    )


def save_observations(target_id: str, obs: list[Observation], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{target_id}.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for o in obs:
            fh.write(json.dumps(obs_to_dict(o)) + "\n")
    return path


def load_observations(path: Path) -> list[Observation]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [obs_from_dict(json.loads(ln)) for ln in lines if ln.strip()]
