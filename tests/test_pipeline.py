"""Phase 5/6 tests: end-to-end matrix run with a fake engine, then report assembly."""

from __future__ import annotations

from osint_ai_pwg.evaluate.harness import condition_crack_rate
from osint_ai_pwg.evaluate.report import build_report, tiers_from_ground_truth
from osint_ai_pwg.guess.assemble import build_runs
from osint_ai_pwg.personas.schema import GroundTruth, PasswordKind
from osint_ai_pwg.pipeline import (
    make_composite_engine,
    make_random_engine,
    reproduction_gate,
    run_matrix,
    seed_sweep_cv,
)
from osint_ai_pwg.schemas import Condition, FootprintTier, NormalizedProfile, ProfileField


def _profiles() -> list[NormalizedProfile]:
    return [
        NormalizedProfile("t01", {"name": ProfileField("Rina", 0.9, 2)}, FootprintTier.RICH),
        NormalizedProfile("t02", {"name": ProfileField("Budi", 0.8, 1)}, FootprintTier.SPARSE),
    ]


PW = {"t01": "rina1", "t02": "budi2"}


def _fake_engine(profiles, condition):
    """Revised design: C2 (OSINT) cracks t01; C3 (GT) cracks t01+t02; C4a (minus
    Identity) and C0/C1 crack nothing. Deterministic."""
    if condition is Condition.C2:
        return {"t01": ["x", "rina1"]}
    if condition is Condition.C3:
        return {"t01": ["x", "rina1"], "t02": ["budi2"]}
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
    conditions = [Condition.C0, Condition.C2, Condition.C3, Condition.C4A]
    results = run_matrix(profs, conditions, _fake_engine, "h")
    gts = [
        GroundTruth("t01", FootprintTier.RICH, {"Identity": {"name": "Rina"}}, "rina1", PasswordKind.PII_LADEN),
        GroundTruth("t02", FootprintTier.SPARSE, {"Identity": {"name": "Budi"}}, "budi2", PasswordKind.PII_LADEN),
    ]
    tiers = tiers_from_ground_truth(gts)
    rep = build_report(results, PW, tiers, budgets=[100, 1000], primary_budget=100)

    # C2 (OSINT) cracks 1/2; C3 (GT) cracks 2/2
    assert rep["conditions"]["C2"]["crack_rate"]["100"] == 0.5
    assert rep["conditions"]["C3"]["crack_rate"]["100"] == 1.0
    # RQ2 noise penalty Gamma = CR_gt - CR_osint = C3 - C2 = +0.5 (OSINT below ground truth)
    assert rep["rq2_noise_penalty"]["mean"] == 0.5
    # RQ1 by tier (OSINT = C2): rich (t01) cracked, sparse (t02) not
    assert rep["rq1_by_tier"] == {"rich": 1.0, "sparse": 0.0}
    # RQ3: removing Identity (C4a) drops C2's cracks to 0 -> delta 0.5
    assert rep["rq3_group_delta"]["Identity"] == 0.5


# --- Revised design 2026-10: step-6 pipeline pieces ---


def test_random_engine_is_a_floor() -> None:
    profs = _profiles()
    eng = make_random_engine(PW, n=50, seed=1)
    out = eng(profs, Condition.C7)
    # right shape: n guesses per target, each matching the gt password length
    assert len(out["t01"]) == 50
    assert all(len(g) == len(PW["t01"]) for g in out["t01"])
    # random guessing does not crack a real password -> sanity floor
    runs = build_runs(["t01", "t02"], out, Condition.C7, "h")
    assert condition_crack_rate(runs, PW, budget=1000) == 0.0


def test_composite_engine_dispatch() -> None:
    profs = _profiles()
    default = lambda p, c: {"t01": ["default"]}          # noqa: E731
    c7 = lambda p, c: {"t01": ["random"]}                # noqa: E731
    eng = make_composite_engine(default, {Condition.C7: c7})
    assert eng(profs, Condition.C2)["t01"] == ["default"]
    assert eng(profs, Condition.C7)["t01"] == ["random"]


def test_seed_sweep_cv() -> None:
    profs = _profiles()
    # same crack rate under every seed -> CV 0; all seeds recorded
    engine_for_seed = lambda s: (lambda p, c: {"t01": ["rina1"]})   # noqa: E731
    out = seed_sweep_cv(profs, PW, engine_for_seed, [42, 137, 856], budget=100, config_hash="h")
    assert set(out["per_seed"]) == {42, 137, 856}
    assert out["cv"] == 0.0 and out["mean"] == 0.5       # cracks t01 only, every seed


def test_reproduction_gate() -> None:
    cal = [build_runs(["t01"], {"t01": ["rina1"]}, Condition.C3, "h")[0]]
    # cr = 1.0 is outside PassLLM's reported 12.54-31.63% range -> fails
    assert reproduction_gate(cal, PW, budget=100)["passed"] is False
    # with a permissive band it passes
    assert reproduction_gate(cal, PW, budget=100, lo=0.0, hi=1.0)["passed"] is True
