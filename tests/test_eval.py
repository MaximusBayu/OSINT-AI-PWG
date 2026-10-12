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


# --- Revised design 2026-10: new eval math ---


def test_precision_recall_f1() -> None:
    from osint_ai_pwg.evaluate.metrics import precision_recall_f1

    m = precision_recall_f1(correct=3, collected=4, ground_truth=6)
    assert m["precision"] == 0.75 and m["recall"] == 0.5
    assert abs(m["f1"] - 0.6) < 1e-9
    zero = precision_recall_f1(0, 0, 0)
    assert zero == {"precision": 0.0, "recall": 0.0, "f1": 0.0}


def test_jaccard_stability() -> None:
    from osint_ai_pwg.evaluate.metrics import jaccard

    assert jaccard(["a", "b"], ["a", "b"]) == 1.0            # identical -> stable
    assert jaccard(["a", "b"], ["b", "c"]) == 1 / 3          # |{b}| / |{a,b,c}|
    assert jaccard([], []) == 1.0                            # nothing collected either run
    assert jaccard(["a"], []) == 0.0


def test_cohens_g_and_cv() -> None:
    from osint_ai_pwg.evaluate.metrics import coefficient_of_variation, cohens_g

    assert cohens_g(0.75) == 0.25
    assert cohens_g(0.5) == 0.0
    assert coefficient_of_variation([0.4, 0.4, 0.4]) == 0.0  # no variance
    assert coefficient_of_variation([]) == 0.0
    assert coefficient_of_variation([0.2, 0.4, 0.6]) > 0.0


def test_bca_ci_brackets_point() -> None:
    from osint_ai_pwg.evaluate.harness import bootstrap_ci_bca

    runs = [_run(t, ["x", "y", PW[t]]) for t in PW]          # all cracked at rank 3
    point, lo, hi = bootstrap_ci_bca(runs, PW, budget=100, iters=200, seed=1)
    assert point == 1.0 and 0.0 <= lo <= point <= hi <= 1.0


def test_noise_penalty_positive() -> None:
    from osint_ai_pwg.evaluate.harness import noise_penalty

    osint = [_run("t01", ["secret"]), _run("t02", ["nope"])]            # cracks t01 only
    gt = [_run("t01", ["secret"], Condition.C3), _run("t02", ["hunter2"], Condition.C3)]  # both
    d = noise_penalty(osint, gt, PW, budget=100)
    assert d["mean"] == 0.5 and d["per_target"]["t02"] == 1   # gt - osint, positive


def test_crack_rate_by_confidence_tier() -> None:
    from osint_ai_pwg.evaluate.harness import (
        confidence_tiers_from_profiles,
        crack_rate_by_confidence_tier,
    )
    from osint_ai_pwg.schemas import NormalizedProfile, ProfileField

    profiles = [
        NormalizedProfile("t01", {"name": ProfileField("A", 0.9, 3)}),   # High
        NormalizedProfile("t02", {"name": ProfileField("B", 0.2, 1)}),   # Low
    ]
    tiers = confidence_tiers_from_profiles(profiles)
    assert tiers["t01"].value == "high" and tiers["t02"].value == "low"

    runs = [_run("t01", ["secret"], Condition.C5), _run("t02", ["nope"], Condition.C5)]
    by_tier = crack_rate_by_confidence_tier(runs, PW, tiers, budget=100)
    assert by_tier == {"high": 1.0, "low": 0.0}              # high-confidence cracks, low doesn't


def test_collection_quality_field_quality() -> None:
    from osint_ai_pwg.evaluate.collection_quality import field_quality
    from osint_ai_pwg.schemas import FieldGroup, Observation

    obs = [
        Observation("t01", "name", FieldGroup.IDENTITY, "Alex P", "sherlock:twitter"),
        Observation("t01", "name", FieldGroup.IDENTITY, "Alex Wrong", "spiderfoot:x"),   # noise
        Observation("t01", "email", FieldGroup.IDENTITY, "alex@example.com", "holehe:y"),
    ]
    gt = {"name": "Alex P", "email": "alex@example.com", "phone": "+1555"}
    q = field_quality(obs, gt)
    assert q["name"]["precision"] == 0.5 and q["name"]["recall"] == 1.0   # 1 of 2 values correct
    assert q["email"]["f1"] == 1.0                                        # clean recovery
    assert q["phone"] == {"precision": 0.0, "recall": 0.0, "f1": 0.0}     # omission


def test_collection_quality_field_stability() -> None:
    from osint_ai_pwg.evaluate.collection_quality import field_stability
    from osint_ai_pwg.schemas import FieldGroup, Observation

    def o(field, value):
        return Observation("t01", field, FieldGroup.IDENTITY, value, "sherlock:x")

    run1 = [o("name", "Alex P"), o("email", "a@x.com")]
    run2 = [o("name", "Alex P")]                              # email dropped second run
    stab = field_stability(run1, run2)
    assert stab["name"] == 1.0 and stab["email"] == 0.0
