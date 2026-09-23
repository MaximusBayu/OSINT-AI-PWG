"""Seed = the minimal starting knowledge an attacker has about a target.

Realistic premise: you pick a person and know a handle/name/email, then gather the rest.
The seed is deliberately NOT the full ground truth — collection must recover the rest.
"""

from __future__ import annotations

from osint_ai_pwg.personas.schema import GroundTruth

# Fields allowed as starting knowledge (a handle/name/email you already have).
_SEED_FIELDS = ("name", "username", "email")


def derive_seed(gt: GroundTruth) -> dict[str, str]:
    """Minimal seed from a target's known handle/name/email (whatever is present)."""
    flat = gt.flatten_pii()
    return {k: flat[k] for k in _SEED_FIELDS if k in flat}
