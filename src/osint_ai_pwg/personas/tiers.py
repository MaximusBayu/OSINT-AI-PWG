"""Footprint tier criteria (RQ1 independent variable).

Tier is a function of how much PII a target exposes and how widely it is spread:
  - group breadth  = number of PII groups with >=1 field
  - platform spread = distinct platforms the fields were planted on

Thresholds are defaults; adjust here if the Phase 1 protocol changes.
"""

from __future__ import annotations

from osint_ai_pwg.schemas import FieldGroup, FootprintTier

# tier -> (min groups, min distinct platforms)
CRITERIA: dict[FootprintTier, tuple[int, int]] = {
    FootprintTier.RICH: (3, 4),
    FootprintTier.MODERATE: (2, 2),
    FootprintTier.SPARSE: (1, 1),
}


def _breadth(pii: dict[str, dict[str, str]]) -> int:
    return sum(1 for fields in pii.values() if fields)


def _spread(planted: dict[str, list[str]]) -> int:
    platforms: set[str] = set()
    for pl in planted.values():
        platforms.update(pl)
    return len(platforms)


def classify(pii: dict[str, dict[str, str]], planted: dict[str, list[str]]) -> FootprintTier:
    """Assign the highest tier whose thresholds are met (rich > moderate > sparse)."""
    g, p = _breadth(pii), _spread(planted)
    for tier in (FootprintTier.RICH, FootprintTier.MODERATE, FootprintTier.SPARSE):
        min_g, min_p = CRITERIA[tier]
        if g >= min_g and p >= min_p:
            return tier
    return FootprintTier.SPARSE


# Sanity: taxonomy groups referenced by the protocol.
ALL_GROUPS = [g.value for g in FieldGroup]
