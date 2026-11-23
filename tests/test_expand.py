"""Tests for deterministic PII candidate expansion."""

from __future__ import annotations

from osint_ai_pwg.guess.expand import expand_candidates
from osint_ai_pwg.guess.prompt import build_passllm_object
from osint_ai_pwg.schemas import Condition, NormalizedProfile, ProfileField


def _profile(**values: str) -> NormalizedProfile:
    return NormalizedProfile(
        target_id="t",
        fields={name: ProfileField(value=value, confidence=0.8, sources=2) for name, value in values.items()},
    )


def test_username_and_name_number_patterns() -> None:
    profile = _profile(
        name="Maximus Bayu Proudiasto",
        username="Lordmax4581",
        birth_year="1990",
        email="lordmax4581@example.com",
    )
    out = set(expand_candidates(profile, Condition.C2))
    expected = {
        "Lordmax4581",
        "lordmax4581",
        "maximusbayu123",
        "maximus1990",
        "maximusproudiasto123",
        "lordmax4581123",
    }
    missing = expected - out
    assert not missing, f"missing patterns: {sorted(missing)}"


def test_length_floor_allows_five_to_seven_characters() -> None:
    profile = _profile(name="Max Sim", username="maxsim")
    out = expand_candidates(profile, Condition.C2)
    assert any(len(candidate) == 5 for candidate in out)
    assert all(5 <= len(candidate) <= 24 for candidate in out)


def test_identity_ablation_removes_name_and_username() -> None:
    profile = _profile(
        name="Maximus Bayu",
        username="Lordmax4581",
        birth_year="1990",
        city="Jakarta",
    )
    out = set(expand_candidates(profile, Condition.C4A))
    assert not any("maximus" in candidate.lower() for candidate in out)
    assert not any("lordmax" in candidate.lower() for candidate in out)
    assert any("jakarta" in candidate.lower() for candidate in out)


def test_expansion_covers_symbol_year_and_numeric_tails() -> None:
    profile = _profile(name="Alex Smith", birth_year="1985")
    out = set(expand_candidates(profile, Condition.C3, limit=5000))
    expected = {"Alex#1985", "Alex1985#", "Alex123", "Alex85"}
    missing = expected - out
    assert not missing, f"missing generator patterns: {sorted(missing)}"


def test_projection_keeps_only_the_four_trained_keys() -> None:
    profile = _profile(
        name="Maximus Bayu",
        username="Lordmax4581",
        birth_year="1990",
        email="lordmax4581@example.com",
        city="Jakarta",
    )
    full = build_passllm_object(profile, Condition.C2)
    projected = build_passllm_object(profile, Condition.C2, project_to_trained=True)
    assert {"name", "birth_year", "username", "email", "city"} <= set(full)
    assert set(projected) == {"name", "birth_year", "username"}
