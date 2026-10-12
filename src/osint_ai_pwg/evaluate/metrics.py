"""Crack-rate + collection-quality metrics (Ur et al. protocol + revised design 2026-10).

Exact-match crack-rate primitives, plus the revised-design collection-quality and
stability measures: per-field precision/recall/F1, Jaccard field stability, Cohen's g
effect size, and coefficient of variation for the inference seed sweep.
"""

from __future__ import annotations

import statistics
from collections.abc import Iterable, Sequence


def guess_number(guesses: Sequence[str], password: str) -> int | None:
    """1-indexed rank at which `password` is exactly matched, or None if never.

    This is the core quantity behind Guess Number Curves.
    """
    for i, g in enumerate(guesses, start=1):
        if g == password:
            return i
    return None


def cracked_within(guesses: Sequence[str], password: str, budget: int) -> bool:
    """True if the password is exactly matched within the first `budget` guesses."""
    gn = guess_number(guesses, password)
    return gn is not None and gn <= budget


def crack_rate(
    runs: Iterable[tuple[Sequence[str], str]],
    budget: int,
) -> float:
    """Fraction of (guesses, password) pairs cracked within `budget`.

    Budgets used by the study: 100, 1_000, 10_000.
    """
    runs = list(runs)
    if not runs:
        return 0.0
    hits = sum(cracked_within(g, pw, budget) for g, pw in runs)
    return hits / len(runs)


# --- Collection-quality + stability metrics (revised design 2026-10) ---


def precision_recall_f1(correct: int, collected: int, ground_truth: int) -> dict[str, float]:
    """Per-field OSINT collection quality (eq 12-14).

    precision = correct / collected (syntactic accuracy); recall = correct / ground_truth
    present (completeness); F1 is their harmonic mean. Each component is 0.0 when undefined.
    """
    precision = correct / collected if collected else 0.0
    recall = correct / ground_truth if ground_truth else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def jaccard(values_run1: Iterable[str], values_run2: Iterable[str]) -> float:
    """Per-field collection stability J_f (eq 11): |A n B| / |A u B| over distinct values.

    Two empty runs = perfectly stable (1.0): nothing collected either time, no disagreement.
    Stable >= 0.80, moderately stable 0.50-0.79, unstable < 0.50.
    """
    a, b = set(values_run1), set(values_run2)
    union = a | b
    if not union:
        return 1.0
    return len(a & b) / len(union)


def cohens_g(proportion: float) -> float:
    """Cohen's g effect size for a proportion vs 0.5: g = p - 0.5.

    For a paired binary comparison, pass the discordant-pair proportion b / (b + c).
    |g| ~ 0.05 small, 0.15 medium, 0.25 large.
    """
    return proportion - 0.5


def coefficient_of_variation(values: Sequence[float]) -> float:
    """CV = sigma / mu for the inference seed sweep (revised design). 0.0 if mean is 0.

    CV(CR100) < 0.15 = stable inference; > 0.30 = raise run_count or keep_ratio.
    """
    vals = list(values)
    if not vals:
        return 0.0
    mean = statistics.fmean(vals)
    if mean == 0:
        return 0.0
    return statistics.pstdev(vals) / mean
