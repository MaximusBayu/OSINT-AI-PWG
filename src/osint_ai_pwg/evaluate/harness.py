"""Evaluation harness (Ur et al. protocol): GNC, bootstrap CI, paired deltas, ablation.

Consumes GuessRun records + a target->password lookup (from the ground-truth roster) and
produces the quantities that answer RQ1-RQ3:
  - guess_number_curve  -> RQ1 (performance across budgets / tiers)
  - paired_delta        -> RQ2 (OSINT vs ground-truth noise penalty)
  - ablation_delta      -> RQ3 (per-group contribution)
All crack-rate math is exact-match, delegated to metrics.py.
"""

from __future__ import annotations

import math
import random
from collections.abc import Sequence

from osint_ai_pwg.evaluate.metrics import cracked_within, crack_rate
from osint_ai_pwg.schemas import GuessRun


def passwords_from_ground_truth(gts) -> dict[str, str]:
    """target_id -> password, from a list of GroundTruth records."""
    return {gt.target_id: gt.password for gt in gts}


def _pairs(runs: Sequence[GuessRun], passwords: dict[str, str]) -> list[tuple[list[str], str]]:
    return [(r.guesses, passwords[r.target_id]) for r in runs if r.target_id in passwords]


def condition_crack_rate(runs: Sequence[GuessRun], passwords: dict[str, str], budget: int) -> float:
    """Crack rate for one condition at a fixed guess budget."""
    return crack_rate(_pairs(runs, passwords), budget)


def guess_number_curve(
    runs: Sequence[GuessRun], passwords: dict[str, str], budgets: Sequence[int]
) -> list[tuple[int, float]]:
    """(budget, crack_rate) points — the Guess Number Curve. Non-decreasing in budget."""
    pairs = _pairs(runs, passwords)
    return [(b, crack_rate(pairs, b)) for b in budgets]


def _percentile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = q * (len(sorted_vals) - 1)
    lo, hi = math.floor(idx), math.ceil(idx)
    if lo == hi:
        return sorted_vals[int(idx)]
    frac = idx - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def bootstrap_ci(
    runs: Sequence[GuessRun],
    passwords: dict[str, str],
    budget: int,
    iters: int = 1000,
    ci: float = 0.95,
    seed: int = 20260923,
) -> tuple[float, float, float]:
    """(point_estimate, lo, hi) crack rate with a bootstrap CI over targets (within-subjects)."""
    pairs = _pairs(runs, passwords)
    n = len(pairs)
    point = crack_rate(pairs, budget)
    if n == 0:
        return (0.0, 0.0, 0.0)
    rng = random.Random(seed)
    rates: list[float] = []
    for _ in range(iters):
        sample = [pairs[rng.randrange(n)] for _ in range(n)]
        rates.append(crack_rate(sample, budget))
    rates.sort()
    alpha = (1 - ci) / 2
    return (point, _percentile(rates, alpha), _percentile(rates, 1 - alpha))


def paired_delta(
    runs_a: Sequence[GuessRun],
    runs_b: Sequence[GuessRun],
    passwords: dict[str, str],
    budget: int,
) -> dict:
    """Per-target and mean (cracked_A - cracked_B) at budget. RQ2: A=OSINT (C1), B=ground truth (C2).

    A negative mean = the OSINT noise penalty (fewer cracks than ground truth).
    """
    a = {r.target_id: r.guesses for r in runs_a}
    b = {r.target_id: r.guesses for r in runs_b}
    common = [t for t in a if t in b and t in passwords]
    per = {
        t: int(cracked_within(a[t], passwords[t], budget))
        - int(cracked_within(b[t], passwords[t], budget))
        for t in common
    }
    mean = sum(per.values()) / len(per) if per else 0.0
    return {"per_target": per, "mean": mean, "n": len(per)}


def ablation_delta(
    full_runs: Sequence[GuessRun],
    ablated_runs: Sequence[GuessRun],
    passwords: dict[str, str],
    budget: int,
) -> float:
    """delta_g = crack_rate(full) - crack_rate(ablated). Positive = the removed group helped (RQ3)."""
    return condition_crack_rate(full_runs, passwords, budget) - condition_crack_rate(
        ablated_runs, passwords, budget
    )
