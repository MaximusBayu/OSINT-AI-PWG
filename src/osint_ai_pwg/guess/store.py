"""Persist GuessRun records as JSONL under data/runs/ (gitignored)."""

from __future__ import annotations

import json
from pathlib import Path

from osint_ai_pwg.schemas import Condition, GuessRun


def run_to_dict(r: GuessRun) -> dict:
    return {
        "target_id": r.target_id,
        "condition": r.condition.value,
        "config_hash": r.config_hash,
        "guesses": r.guesses,
    }


def run_from_dict(d: dict) -> GuessRun:
    return GuessRun(
        target_id=d["target_id"],
        condition=Condition(d["condition"]),
        config_hash=d["config_hash"],
        guesses=list(d.get("guesses", [])),
    )


def save_runs(runs: list[GuessRun], path: Path) -> Path:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("w", encoding="utf-8") as fh:
        for r in runs:
            fh.write(json.dumps(run_to_dict(r)) + "\n")
    return Path(path)


def load_runs(path: Path) -> list[GuessRun]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [run_from_dict(json.loads(ln)) for ln in lines if ln.strip()]
