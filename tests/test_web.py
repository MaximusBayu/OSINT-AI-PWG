"""Web demo tests: roster guardrail, pipeline walkthrough, noise-penalty behavior."""

from __future__ import annotations

import pytest

from osint_ai_pwg.personas.generate import build_targets
from osint_ai_pwg.personas.schema import PasswordKind
from osint_ai_pwg.web.demo import DemoEngine
from osint_ai_pwg.web.service import (
    ConsentRequired,
    TargetNotAllowed,
    create_self_target,
    list_targets,
    run_demo,
)


def _roster():
    return {gt.target_id: gt for gt in build_targets(n=15, seed=20260923)}


def test_unknown_target_refused() -> None:
    with pytest.raises(TargetNotAllowed):
        run_demo("does-not-exist", _roster())


def test_list_targets() -> None:
    items = list_targets(_roster())
    assert len(items) == 15 and {"target_id", "tier"} <= set(items[0])


def test_run_demo_structure_and_c2_full() -> None:
    roster = _roster()
    tid = next(iter(roster))
    out = run_demo(tid, roster)
    conds = {c["condition"]: c for c in out["conditions"]}
    assert set(conds) == {"C0", "C1", "C2", "C3", "C4", "C5"}
    assert conds["C0"]["pii_sent"] == {}                 # baseline empty
    assert conds["C2"]["pii_sent"]                        # C2 gets full ground-truth PII


def test_c2_cracks_pii_laden_and_c0_does_not() -> None:
    # find a PII-laden target with a name+birthdate (so the demo engine can reconstruct it)
    roster = _roster()
    tid = next(
        t for t, gt in roster.items()
        if gt.password_kind is PasswordKind.PII_LADEN
        and "name" in gt.flatten_pii() and "birthdate" in gt.flatten_pii()
    )
    conds = {c["condition"]: c for c in run_demo(tid, roster)["conditions"]}
    assert conds["C2"]["cracked"] is True                 # full PII -> cracks its PII-laden pw
    assert conds["C0"]["cracked"] is False                # no PII -> misses


def test_create_self_target_requires_consent(tmp_path) -> None:
    with pytest.raises(ConsentRequired):
        create_self_target({"name": "Me", "password": "Me2000"}, tmp_path)


def test_create_self_target_requires_password(tmp_path) -> None:
    with pytest.raises(ValueError):
        create_self_target({"name": "Me", "consent": True}, tmp_path)


def test_create_self_target_writes_and_runs(tmp_path) -> None:
    info = create_self_target(
        {"id": "self01", "name": "Me Here", "birthdate": "2000-01-01",
         "platforms": "twitter, github", "password": "Me2000", "consent": True},
        tmp_path,
    )
    assert info["target_id"] == "self01" and info["password_kind"] == "pii_laden"
    assert (tmp_path / "self01.json").exists()


def test_more_platforms_more_sources() -> None:
    from osint_ai_pwg.personas.self_target import build_self_target

    gt = build_self_target(
        "s1", password="Rina1995", name="Rina", birthdate="1995-01-01",
        platforms=["twitter", "github", "linkedin"],
    )
    out = run_demo("s1", {"s1": gt})
    # name is a seed field, recovered from all 3 planted platforms -> 3 sources
    assert out["profile"]["name"]["sources"] == 3
    assert out["profile_summary"]["fields"] >= 1


def test_demo_engine_needs_name_and_year() -> None:
    eng = DemoEngine()
    assert eng.guesses({"name": "Rina P", "birth_year": "1995"})          # produces patterns
    # without a year it cannot rebuild a name+year password
    assert "Rina1995" not in eng.guesses({"name": "Rina P"})
