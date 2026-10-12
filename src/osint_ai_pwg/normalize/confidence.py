"""3-signal confidence model (revised design 2026-10).

confidence = w_r * reliability + w_a * agreement + w_d * directness

Weights are FIXED, literature-motivated (not learned -- five calibration profiles would
overfit), with agreement (w_a) as the dominant component per the Admiralty Code rationale
and cross-source corroboration findings. Provisional; validated by a +/-0.15 sensitivity
sweep in the pilot. Directness is scored on the revised 4-level continuum.
"""

from __future__ import annotations

from osint_ai_pwg.schemas import Directness

# Admiralty-style source reliability grade -> score in [0, 1].
_RELIABILITY: dict[str, float] = {
    "A": 1.0, "B": 0.8, "C": 0.6, "D": 0.4, "E": 0.2, "F": 0.0,
}

# Directness continuum (revised design): explicit / strongly-implied / weakly-implied / inferred.
DIRECTNESS_SCORE: dict[Directness, float] = {
    Directness.STATED: 1.0,
    Directness.STRONGLY_IMPLIED: 0.7,
    Directness.WEAKLY_IMPLIED: 0.4,
    Directness.INFERRED: 0.2,
}

# Signal weights, sum to 1.0. Agreement dominant (provisional; sensitivity-swept +/-0.15).
_W_RELIABILITY = 0.3
_W_AGREEMENT = 0.5
_W_DIRECTNESS = 0.2


def confidence(
    reliability_grade: str,
    n_agreeing_sources: int,
    directness: Directness,
) -> float:
    """Combine the three signals into a confidence in [0, 1].

    Args:
        reliability_grade: Admiralty grade A-F of the most reliable source.
        n_agreeing_sources: independent sources that reported the same value.
        directness: one of the 4 revised-design levels (scored via DIRECTNESS_SCORE).
    """
    rel = _RELIABILITY.get(reliability_grade.upper(), 0.0)
    # Diminishing returns: 1 source -> 0.0, saturating toward 1.0.
    agree = 1.0 - (1.0 / (1 + max(0, n_agreeing_sources - 1)))
    direct = DIRECTNESS_SCORE.get(directness, 0.2)

    score = _W_RELIABILITY * rel + _W_AGREEMENT * agree + _W_DIRECTNESS * direct
    return max(0.0, min(1.0, score))
