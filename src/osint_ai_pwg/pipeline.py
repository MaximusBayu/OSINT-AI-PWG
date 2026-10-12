"""End-to-end pilot driver: run every condition over the target roster (Phase 5).

The guessing engine is abstracted as `Engine` — a callable (profiles, condition) ->
{target_id: [ranked guesses]}. This keeps the driver independent of PassLLM's I/O:
tests inject a deterministic fake engine; the real run uses `make_passllm_engine`.
"""

from __future__ import annotations

import random
import string
import tempfile
from collections.abc import Callable
from pathlib import Path

from osint_ai_pwg.evaluate.harness import condition_crack_rate
from osint_ai_pwg.evaluate.metrics import coefficient_of_variation
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


def make_passllm_engine(
    weights_file: Path, runner=None, fast: bool = True, base_only: bool = False
) -> Engine:
    """Real engine: write the JSONL, invoke PassLLM, parse its output.

    base_only=True runs the raw base model without the LoRA adapter (condition C0b).
    Depends on `runner.parse_output`, which must be implemented against the real PassLLM
    stdout format (first Colab run). Untested here for that reason.
    """

    def engine(profiles: list[NormalizedProfile], condition: Condition) -> dict[str, list[str]]:
        with tempfile.TemporaryDirectory() as td:
            in_path = Path(td) / "target.jsonl"
            order = jsonl.write_input(profiles, condition, in_path)
            raw = passllm_runner.run(
                in_path, weights_file, runner=runner, fast=fast, base_only=base_only
            )
            return passllm_runner.parse_output(raw, order)

    return engine


def make_composite_engine(default: Engine, overrides: dict[Condition, Engine]) -> Engine:
    """Dispatch per condition: C0b -> base engine, C7 -> random engine, rest -> default.

    Lets run_matrix cover the full revised-design condition set with one callable.
    """

    def engine(profiles: list[NormalizedProfile], condition: Condition) -> dict[str, list[str]]:
        return overrides.get(condition, default)(profiles, condition)

    return engine


def _charset_of(pw: str) -> str:
    """Character pool matching a password's composition (classes + its own specials)."""
    pool: set[str] = set()
    if any(c.islower() for c in pw):
        pool |= set(string.ascii_lowercase)
    if any(c.isupper() for c in pw):
        pool |= set(string.ascii_uppercase)
    if any(c.isdigit() for c in pw):
        pool |= set(string.digits)
    pool |= {c for c in pw if not c.isalnum()}
    return "".join(sorted(pool)) or string.ascii_lowercase


def make_random_engine(passwords: dict[str, str], n: int = 1000, seed: int = 20260923) -> Engine:
    """Condition C7: random passwords matching each target's gt length + charset.

    The trivial sanity floor any method with genuine signal must beat. Deterministic.
    """

    def engine(profiles: list[NormalizedProfile], condition: Condition) -> dict[str, list[str]]:
        rng = random.Random(seed)
        out: dict[str, list[str]] = {}
        for p in profiles:
            pw = passwords.get(p.target_id, "")
            length = len(pw) or 8
            pool = _charset_of(pw)
            out[p.target_id] = ["".join(rng.choice(pool) for _ in range(length)) for _ in range(n)]
        return out

    return engine


def seed_sweep_cv(
    profiles: list[NormalizedProfile],
    passwords: dict[str, str],
    engine_for_seed: Callable[[int], Engine],
    seeds: list[int],
    budget: int,
    config_hash: str,
    condition: Condition = Condition.C2,
) -> dict:
    """Run one condition under several inference seeds; report CR per seed + CV.

    Revised design: quantifies beam-search stochasticity. CV(CR100) < 0.15 = stable;
    > 0.30 = raise run_count or keep_ratio before the main run.
    """
    order = [p.target_id for p in profiles]
    per_seed: dict[int, float] = {}
    for s in seeds:
        runs = build_runs(order, engine_for_seed(s)(profiles, condition), condition, config_hash)
        per_seed[s] = condition_crack_rate(runs, passwords, budget)
    vals = list(per_seed.values())
    mean = sum(vals) / len(vals) if vals else 0.0
    return {"per_seed": per_seed, "mean": mean, "cv": coefficient_of_variation(vals)}


def reproduction_gate(
    cal_runs: list[GuessRun],
    passwords: dict[str, str],
    budget: int = 100,
    lo: float = 0.1254,
    hi: float = 0.3163,
) -> dict:
    """Gate before measuring any noise penalty: C3 (clean GT) on calibration profiles must
    land within PassLLM's reported CR100 range (12.54-31.63%), confirming the engine is not
    underperforming. Returns the rate and whether the gate passed.
    """
    cr = condition_crack_rate(cal_runs, passwords, budget)
    return {"cr": cr, "lo": lo, "hi": hi, "passed": lo <= cr <= hi}
