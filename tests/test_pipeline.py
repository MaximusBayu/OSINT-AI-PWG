"""Phase 5/6 tests: end-to-end matrix run with a fake engine, then report assembly."""

from __future__ import annotations

from osint_ai_pwg.evaluate.report import build_report, tiers_from_ground_truth
from osint_ai_pwg.personas.schema import GroundTruth, PasswordKind
from osint_ai_pwg.pipeline import run_matrix
from osint_ai_pwg.schemas import Condition, FootprintTier, NormalizedProfile, ProfileField


def _profiles() -> list[NormalizedProfile]:
    return [
        NormalizedProfile("t01", {"name": ProfileField("Rina", 0.9, 2)}, FootprintTier.RICH),
        NormalizedProfile("t02", {"name": ProfileField("Budi", 0.8, 1)}, FootprintTier.SPARSE),
    ]


PW = {"t01": "rina1", "t02": "budi2"}


def _fake_engine(profiles, condition):
    """C1 cracks t01; C2 cracks t01+t02; C0/C3 crack nothing. Deterministic."""
    if condition in (Condition.C1, Condition.C2):
        out = {"t01": ["x", "rina1"]}
        if condition is Condition.C2:
            out["t02"] = ["budi2"]
        return out
    return {}


def test_run_matrix_shapes() -> None:
    profs = _profiles()
    results = run_matrix(profs, [Condition.C0, Condition.C1, Condition.C2], _fake_engine, "h")
    assert set(results) == {Condition.C0, Condition.C1, Condition.C2}
    # every condition has one run per target, order preserved
    for runs in results.values():
        assert [r.target_id for r in runs] == ["t01", "t02"]
    assert results[Condition.C0][0].guesses == []          # C0 baseline: no guesses from fake


def test_build_report_rqs() -> None:
    profs = _profiles()
    conditions = [Condition.C0, Condition.C1, Condition.C2, Condition.C3]
    results = run_matrix(profs, conditions, _fake_engine, "h")
    gts = [
        GroundTruth("t01", FootprintTier.RICH, {"Identity": {"name": "Rina"}}, "rina1", PasswordKind.PII_LADEN),
        GroundTruth("t02", FootprintTier.SPARSE, {"Identity": {"name": "Budi"}}, "budi2", PasswordKind.PII_LADEN),
    ]
    tiers = tiers_from_ground_truth(gts)
    rep = build_report(results, PW, tiers, budgets=[100, 1000], primary_budget=100)

    # C1 cracks 1/2; C2 cracks 2/2
    assert rep["conditions"]["C1"]["crack_rate"]["100"] == 0.5
    assert rep["conditions"]["C2"]["crack_rate"]["100"] == 1.0
    # RQ2 noise penalty: C1 - C2 = -0.5 mean
    assert rep["rq2_noise_penalty"]["mean"] == -0.5
    # RQ1 by tier: rich (t01) cracked, sparse (t02) not, under C1
    assert rep["rq1_by_tier"] == {"rich": 1.0, "sparse": 0.0}
    # RQ3: removing Identity (C3) drops C1's cracks to 0 -> delta 0.5
    assert rep["rq3_group_delta"]["Identity"] == 0.5
