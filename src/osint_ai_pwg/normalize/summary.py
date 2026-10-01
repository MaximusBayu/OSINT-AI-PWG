"""Profile confidence summary: average confidence + a high/medium/low tier badge.

Mirrors the collection UI's "Avg Confidence 55% MEDIUM" readout. This is a DISPLAY summary
of extraction quality; it is distinct from footprint_tier (the RQ1 exposure label).
Thresholds match the collection tool: >=0.7 high, >=0.4 medium, else low.
"""

from __future__ import annotations

from osint_ai_pwg.schemas import NormalizedProfile

HIGH, MEDIUM = 0.7, 0.4


def confidence_tier(value: float) -> str:
    if value >= HIGH:
        return "high"
    if value >= MEDIUM:
        return "medium"
    return "low"


def avg_confidence(profile: NormalizedProfile) -> float:
    if not profile.fields:
        return 0.0
    return sum(pf.confidence for pf in profile.fields.values()) / len(profile.fields)


def profile_summary(profile: NormalizedProfile) -> dict:
    """{'fields': n, 'avg_confidence': x, 'tier': 'high'|'medium'|'low'} for the UI."""
    avg = avg_confidence(profile)
    return {"fields": len(profile.fields), "avg_confidence": round(avg, 3), "tier": confidence_tier(avg)}
