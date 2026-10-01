"""Phase 2b tests: merge, conflict resolution, confidence monotonicity, tier passthrough."""

from __future__ import annotations

from osint_ai_pwg.normalize.normalize import normalize
from osint_ai_pwg.normalize.reliability import grade_for
from osint_ai_pwg.schemas import Directness, FieldGroup, FootprintTier, Observation


def _obs(field: str, value: str, source: str, group: FieldGroup = FieldGroup.IDENTITY) -> Observation:
    return Observation("t01", field, group, value, source)


def test_grade_for() -> None:
    assert grade_for("sherlock:github") == "B"
    assert grade_for("unknown:x") == "D"


def test_agreement_raises_confidence() -> None:
    one = normalize([_obs("username", "rina48", "sherlock:github")])
    three = normalize([
        _obs("username", "rina48", "sherlock:github"),
        _obs("username", "rina48", "sherlock:twitter"),
        _obs("username", "rina48", "sherlock:linkedin"),
    ])
    assert three.fields["username"].sources == 3
    assert three.fields["username"].confidence > one.fields["username"].confidence


def test_conflict_resolved_by_support() -> None:
    obs = [
        _obs("email", "a@x", "holehe:twitter.com", FieldGroup.CONTACT),
        _obs("email", "a@x", "holehe:spotify.com", FieldGroup.CONTACT),
        _obs("email", "b@x", "theharvester:bing", FieldGroup.CONTACT),
    ]
    prof = normalize(obs)
    assert prof.fields["email"].value == "a@x"   # 2 sources beat 1
    assert prof.fields["email"].sources == 2


def test_empty_and_tier_passthrough() -> None:
    empty = normalize([])
    assert empty.fields == {} and empty.target_id == ""
    tagged = normalize([_obs("username", "u", "sherlock:github")], FootprintTier.RICH)
    assert tagged.footprint_tier is FootprintTier.RICH


def test_profile_summary_tiers() -> None:
    from osint_ai_pwg.normalize.summary import confidence_tier, profile_summary
    from osint_ai_pwg.schemas import NormalizedProfile, ProfileField

    assert confidence_tier(0.8) == "high"
    assert confidence_tier(0.5) == "medium"
    assert confidence_tier(0.2) == "low"

    prof = NormalizedProfile("t01", {
        "a": ProfileField("x", 0.8, 2), "b": ProfileField("y", 0.4, 1),
    })
    s = profile_summary(prof)
    assert s["fields"] == 2 and s["avg_confidence"] == 0.6 and s["tier"] == "medium"
    assert profile_summary(NormalizedProfile("t0", {}))["tier"] == "low"   # empty


def test_inferred_lower_than_stated() -> None:
    stated = normalize([_obs("city", "Jakarta", "spiderfoot:x")])
    inferred = normalize([
        Observation("t01", "city", FieldGroup.LOCATION, "Jakarta", "spiderfoot:x", Directness.INFERRED)
    ])
    assert stated.fields["city"].confidence > inferred.fields["city"].confidence
