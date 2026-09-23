"""Phase 1 tests: tier classification, password kinds, stratified generation, validation."""

from __future__ import annotations

import random

from osint_ai_pwg.personas import passwords as pw
from osint_ai_pwg.personas.generate import build_targets
from osint_ai_pwg.personas.schema import GroundTruth, PasswordKind, validate
from osint_ai_pwg.personas.tiers import classify
from osint_ai_pwg.schemas import FootprintTier


def test_classify_tiers() -> None:
    rich_pii = {"Identity": {"name": "A"}, "Temporal": {"birthdate": "1990-01-01"}, "Contact": {"email": "a@x"}}
    rich_planted = {"name": ["twitter"], "birthdate": ["github"], "email": ["linkedin", "instagram"]}
    assert classify(rich_pii, rich_planted) is FootprintTier.RICH

    mod_pii = {"Identity": {"name": "A"}, "Temporal": {"birthdate": "1990-01-01"}}
    mod_planted = {"name": ["twitter"], "birthdate": ["github"]}
    assert classify(mod_pii, mod_planted) is FootprintTier.MODERATE

    sparse_pii = {"Identity": {"name": "A"}}
    sparse_planted = {"name": ["twitter"]}
    assert classify(sparse_pii, sparse_planted) is FootprintTier.SPARSE


def test_password_kinds() -> None:
    rng = random.Random(1)
    flat = {"name": "Rina Persona", "birthdate": "1995-06-01"}
    laden = pw.generate(flat, PasswordKind.PII_LADEN, rng)
    assert pw.contains_pii(laden, flat)
    rnd = pw.generate(flat, PasswordKind.RANDOM, rng)
    assert not pw.contains_pii(rnd, flat)


def test_build_targets_stratified_and_valid() -> None:
    targets = build_targets(n=15, seed=20260923)
    assert len(targets) == 15
    # every record valid
    for gt in targets:
        assert validate(gt) == []
    # all three tiers represented
    tiers = {gt.footprint_tier for gt in targets}
    assert tiers == {FootprintTier.RICH, FootprintTier.MODERATE, FootprintTier.SPARSE}
    # PII-laden share roughly ~60% (wide tolerance for n=15)
    n_pii = sum(1 for gt in targets if gt.password_kind is PasswordKind.PII_LADEN)
    assert 0.3 <= n_pii / 15 <= 0.85
    # deterministic
    assert [gt.password for gt in build_targets(15, 20260923)] == [gt.password for gt in targets]


def test_roundtrip(tmp_path) -> None:
    gt = build_targets(n=3, seed=1)[0]
    path = gt.save(tmp_path)
    loaded = GroundTruth.load(path)
    assert loaded.to_dict() == gt.to_dict()


def test_validate_catches_missing_password() -> None:
    gt = GroundTruth(
        target_id="t01", footprint_tier=FootprintTier.SPARSE,
        pii={"Identity": {"name": "A"}}, password="", password_kind=PasswordKind.RANDOM,
    )
    assert "empty password" in validate(gt)
