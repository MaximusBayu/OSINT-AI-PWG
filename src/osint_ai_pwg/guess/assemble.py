"""Assemble engine outputs into GuessRun records, preserving input order."""

from __future__ import annotations

from osint_ai_pwg.schemas import Condition, GuessRun


def build_runs(
    order: list[str],
    guesses_by_id: dict[str, list[str]],
    condition: Condition,
    config_hash: str,
) -> list[GuessRun]:
    """One GuessRun per target (in `order`); missing outputs become empty guess lists."""
    return [
        GuessRun(
            target_id=tid,
            condition=condition,
            config_hash=config_hash,
            guesses=guesses_by_id.get(tid, []),
        )
        for tid in order
    ]
