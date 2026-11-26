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


def test_birth_year_field_is_used_by_generator() -> None:
    rng = random.Random(1)
    flat = {"name": "Rina Persona", "birth_year": "1995"}
    laden = pw.generate(flat, PasswordKind.PII_LADEN, rng)
    assert "1995" in laden
    assert pw.contains_pii(laden, flat)


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

def test_sparse_persona_gets_no_invented_year() -> None:
    """A persona without a birth date must not get a year in its password.

    Sparse personas carry only the Identity group by design, so there is no birth year
    to embed. The old fallback drew a random year from 70 to 99, which produced a
    ground truth that no collection and no engine could ever recover.
    """
    flat = {"name": "Maya Persona", "username": "maya42"}
    assert pw._birth_year(flat) is None

    shapes = pw._patterns("Maya", None, "!", random.Random(1))
    assert len(shapes) == 3
    assert all("maya" in shape.lower() for shape in shapes)

    rng = random.Random(7)
    for _ in range(200):
        generated = pw.generate(flat, PasswordKind.PII_LADEN, rng)
        assert "maya" in generated.lower()
        assert pw.contains_pii(generated, flat)


def test_persona_with_birth_year_still_gets_year_shapes() -> None:
    shapes = pw._patterns("Maya", "1983", "!", random.Random(1))
    assert any("1983" in shape for shape in shapes)
    assert len(shapes) == 4
