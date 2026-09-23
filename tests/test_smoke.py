"""Phase 0 smoke tests: the skeleton imports and the implemented bits behave.

Done-when (ROADMAP Phase 0): `pytest` runs green on stubs.
"""

from __future__ import annotations

from osint_ai_pwg import __version__
from osint_ai_pwg.evaluate.metrics import cracked_within, crack_rate, guess_number
from osint_ai_pwg.guess.prompt import build_prompt
from osint_ai_pwg.normalize.confidence import confidence
from osint_ai_pwg.schemas import (
    Condition,
    Directness,
    FootprintTier,
    NormalizedProfile,
    Observation,
    ProfileField,
    FieldGroup,
)


def test_version() -> None:
    assert __version__ == "0.0.1"


def test_schemas_build() -> None:
    obs = Observation(
        target_id="t01", field="birthdate", group=FieldGroup.TEMPORAL,
        value="1998-04-12", source="sherlock:twitter",
    )
    assert obs.directness is Directness.STATED
    assert obs.collected_at  # ISO-8601 timestamp set


def test_guess_number_and_crack_rate() -> None:
    guesses = ["a", "b", "secret", "d"]
    assert guess_number(guesses, "secret") == 3
    assert guess_number(guesses, "missing") is None
    assert cracked_within(guesses, "secret", budget=3) is True
    assert cracked_within(guesses, "secret", budget=2) is False
    assert crack_rate([(guesses, "secret"), (guesses, "missing")], budget=100) == 0.5
    assert crack_rate([], budget=100) == 0.0


def test_confidence_bounds_and_monotonicity() -> None:
    low = confidence("F", n_agreeing_sources=1, directness=Directness.INFERRED)
    high = confidence("A", n_agreeing_sources=5, directness=Directness.STATED)
    assert 0.0 <= low <= high <= 1.0


def test_passllm_prompt_and_ablation() -> None:
    import json

    profile = NormalizedProfile(
        target_id="t01",
        fields={
            "name": ProfileField(value="Test Persona", confidence=0.9, sources=2),
            "birthdate": ProfileField(value="1990-04-12", confidence=0.7, sources=1),
            "email": ProfileField(value="probe@example.com", confidence=0.8, sources=2),
            "city": ProfileField(value="Examplecity", confidence=0.6, sources=1),
        },
        footprint_tier=FootprintTier.MODERATE,
    )
    # C0: empty (no PII baseline).
    assert build_prompt(profile, Condition.C0) == ""

    # C1: PassLLM schema; birthdate -> birth_year; city has no slot, dropped.
    c1 = json.loads(build_prompt(profile, Condition.C1))
    assert c1["name"] == "Test Persona"
    assert c1["birth_year"] == "1990"
    assert c1["email"] == "probe@example.com"
    assert "city" not in c1 and "location" not in c1  # Location has no engine slot

    # C3 removes Identity -> name gone; C4 removes Temporal -> birth_year gone.
    assert "name" not in json.loads(build_prompt(profile, Condition.C3))
    assert "birth_year" not in json.loads(build_prompt(profile, Condition.C4))
