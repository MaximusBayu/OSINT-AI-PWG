"""Phase 4 tests: GNC monotonicity, crack rate, bootstrap CI, paired delta (RQ2), ablation (RQ3)."""

from __future__ import annotations

from osint_ai_pwg.evaluate.harness import (
    ablation_delta,
    bootstrap_ci,
    condition_crack_rate,
    guess_number_curve,
    paired_delta,
    passwords_from_ground_truth,
)
from osint_ai_pwg.personas.schema import GroundTruth, PasswordKind
from osint_ai_pwg.schemas import Condition, FootprintTier, GuessRun


def _run(tid: str, guesses: list[str], cond: Condition = Condition.C1) -> GuessRun:
    return GuessRun(tid, cond, "h", guesses)


PW = {"t01": "secret", "t02": "hunter2", "t03": "letmein"}


def test_condition_crack_rate() -> None:
    runs = [_run("t01", ["a", "secret"]), _run("t02", ["x", "y"]), _run("t03", ["letmein"])]
    assert condition_crack_rate(runs, PW, budget=100) == 2 / 3
    assert condition_crack_rate(runs, PW, budget=1) == 1 / 3   # only t03 cracked at rank 1


def test_gnc_non_decreasing() -> None:
    runs = [_run("t01", ["a", "b", "secret"]), _run("t02", ["hunter2"])]
    curve = guess_number_curve(runs, PW, [1, 2, 3, 10])
    rates = [r for _, r in curve]
    assert rates == sorted(rates)                 # non-decreasing in budget
    assert curve[0] == (1, 0.5)                   # only t02 at rank 1
    assert curve[-1] == (10, 1.0)


def test_bootstrap_ci_brackets_point() -> None:
    runs = [_run(t, [PW[t]]) for t in PW]          # everyone cracked at rank 1
    point, lo, hi = bootstrap_ci(runs, PW, budget=1, iters=200, seed=1)
    assert point == 1.0 and lo <= point <= hi
    assert 0.0 <= lo <= hi <= 1.0


def test_paired_delta_rq2() -> None:
    # C2 (ground truth) cracks t01+t02; C1 (OSINT) cracks only t01 -> noise penalty.
    c1 = [_run("t01", ["secret"]), _run("t02", ["nope"])]
    c2 = [_run("t01", ["secret"], Condition.C2), _run("t02", ["hunter2"], Condition.C2)]
    d = paired_delta(c1, c2, PW, budget=100)
    assert d["mean"] == -0.5 and d["n"] == 2       # OSINT worse on average
    assert d["per_target"]["t02"] == -1


def test_ablation_delta_rq3() -> None:
    full = [_run("t01", ["secret"]), _run("t02", ["hunter2"])]
    ablated = [_run("t01", ["secret"]), _run("t02", ["nope"])]   # removing group loses t02
    assert ablation_delta(full, ablated, PW, budget=100) == 0.5


def test_passwords_from_ground_truth() -> None:
    gts = [GroundTruth("t01", FootprintTier.SPARSE, {"Identity": {"name": "A"}}, "pw", PasswordKind.RANDOM)]
    assert passwords_from_ground_truth(gts) == {"t01": "pw"}
