"""3-signal confidence model (ROADMAP Phase 2b).

confidence = f(source_reliability, cross_source_agreement, directness)

STUB: weights and the reliability grade table are placeholders to be calibrated in
Phase 2b. The signature is stable; the body is not final.
"""

from __future__ import annotations

from osint_ai_pwg.schemas import Directness

# Admiralty-style source reliability grade -> score in [0, 1]. Calibrate in Phase 2b.
_RELIABILITY: dict[str, float] = {
    "A": 1.0, "B": 0.8, "C": 0.6, "D": 0.4, "E": 0.2, "F": 0.0,
}

# Signal weights, sum to 1.0. Placeholder.
_W_RELIABILITY = 0.4
_W_AGREEMENT = 0.4
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
        directness: stated vs inferred.
    """
    rel = _RELIABILITY.get(reliability_grade.upper(), 0.0)
    # Diminishing returns: 1 source -> 0.0, saturating toward 1.0.
    agree = 1.0 - (1.0 / (1 + max(0, n_agreeing_sources - 1)))
    direct = 1.0 if directness is Directness.STATED else 0.5

    score = _W_RELIABILITY * rel + _W_AGREEMENT * agree + _W_DIRECTNESS * direct
    return max(0.0, min(1.0, score))
