"""Layer 2: Observations -> NormalizedProfile.

Merges raw observations per field, resolves conflicting values by support, and scores each
retained field with the 3-signal confidence model (reliability x agreement x directness).

The result is the C1 (full OSINT PII) input. Ablation variants (C3-C5) are produced
downstream by the prompt builder dropping field groups, so nothing here is condition-specific.
The footprint tier is the target's PLANTED tier (RQ1 label), passed in from the roster —
it is not inferred from what OSINT happened to recover.
"""

from __future__ import annotations

from collections import defaultdict

from osint_ai_pwg.normalize.confidence import confidence
from osint_ai_pwg.normalize.reliability import grade_for
from osint_ai_pwg.schemas import (
    Directness,
    FootprintTier,
    NormalizedProfile,
    Observation,
    ProfileField,
)


def _resolve_field(obs_list: list[Observation]) -> tuple[str, int, str, Directness]:
    """Pick the best-supported value for one field and its confidence inputs.

    Returns (value, n_distinct_sources, best_grade, directness).
    """
    sources_by_value: dict[str, set[str]] = defaultdict(set)
    grades_by_value: dict[str, list[str]] = defaultdict(list)
    stated_by_value: dict[str, bool] = defaultdict(bool)

    for o in obs_list:
        sources_by_value[o.value].add(o.source)
        grades_by_value[o.value].append(grade_for(o.source))
        if o.directness is Directness.STATED:
            stated_by_value[o.value] = True

    def score(v: str) -> tuple[int, int]:
        # most distinct sources wins; tie-break on best (lowest) Admiralty grade
        best_grade = min(grades_by_value[v])
        return (len(sources_by_value[v]), -ord(best_grade))

    best = max(sources_by_value, key=score)
    n = len(sources_by_value[best])
    grade = min(grades_by_value[best])
    directness = Directness.STATED if stated_by_value[best] else Directness.INFERRED
    return best, n, grade, directness


def normalize(
    observations: list[Observation],
    footprint_tier: FootprintTier = FootprintTier.MODERATE,
) -> NormalizedProfile:
    """Build the normalized profile from a target's observations."""
    by_field: dict[str, list[Observation]] = defaultdict(list)
    for o in observations:
        by_field[o.field].append(o)

    fields: dict[str, ProfileField] = {}
    for field, lst in by_field.items():
        value, n, grade, directness = _resolve_field(lst)
        fields[field] = ProfileField(
            value=value,
            confidence=confidence(grade, n, directness),
            sources=n,
        )

    target_id = observations[0].target_id if observations else ""
    return NormalizedProfile(target_id=target_id, fields=fields, footprint_tier=footprint_tier)
