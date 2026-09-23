"""Crack-rate metrics (ROADMAP Phase 4).

Exact-match evaluation per Ur et al. GNC + bootstrap CI land here in Phase 4;
guess_number and cracked_within are implemented now because they are simple and testable.
"""

from __future__ import annotations

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
