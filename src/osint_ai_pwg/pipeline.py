"""End-to-end pilot driver: run every condition over the target roster (Phase 5).

The guessing engine is abstracted as `Engine` — a callable (profiles, condition) ->
{target_id: [ranked guesses]}. This keeps the driver independent of PassLLM's I/O:
tests inject a deterministic fake engine; the real run uses `make_passllm_engine`.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from pathlib import Path

from osint_ai_pwg.guess.assemble import build_runs
from osint_ai_pwg.guess import jsonl, runner as passllm_runner
from osint_ai_pwg.schemas import Condition, GuessRun, NormalizedProfile

# (profiles, condition) -> {target_id: [ranked guesses]}
Engine = Callable[[list[NormalizedProfile], Condition], dict[str, list[str]]]


def run_matrix(
    profiles: list[NormalizedProfile],
    conditions: list[Condition],
    engine: Engine,
    config_hash: str,
) -> dict[Condition, list[GuessRun]]:
    """Run every condition over all profiles; return runs keyed by condition (order preserved)."""
    order = [p.target_id for p in profiles]
    results: dict[Condition, list[GuessRun]] = {}
    for cond in conditions:
        guesses_by_id = engine(profiles, cond)
        results[cond] = build_runs(order, guesses_by_id, cond, config_hash)
    return results


def make_passllm_engine(weights_file: Path, runner=None, fast: bool = True) -> Engine:
    """Real engine: write the JSONL, invoke PassLLM, parse its output.

    Depends on `runner.parse_output`, which must be implemented against the real PassLLM
    stdout format (first Colab run). Untested here for that reason.
    """

    def engine(profiles: list[NormalizedProfile], condition: Condition) -> dict[str, list[str]]:
        with tempfile.TemporaryDirectory() as td:
            in_path = Path(td) / "target.jsonl"
            order = jsonl.write_input(profiles, condition, in_path)
            raw = passllm_runner.run(in_path, weights_file, runner=runner, fast=fast)
            return passllm_runner.parse_output(raw, order)

    return engine
