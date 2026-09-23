"""Assign passwords to synthetic personas.

PII-laden passwords embed a token from the persona's own PII (name / birth year),
mirroring the empirical pattern (Li et al.: 60.1% of passwords contain >=1 PII type).
Random passwords contain none. Deterministic given an rng, for reproducibility.

This assigns known passwords to targets we control; it is not password cracking.
"""

from __future__ import annotations

import random
import string

from osint_ai_pwg.personas.schema import PasswordKind

_SYMBOLS = "!@#$%"


def _birth_year(pii_flat: dict[str, str]) -> str | None:
    bd = pii_flat.get("birthdate")
    return bd[:4] if bd and bd[:4].isdigit() else None


def _first_name(pii_flat: dict[str, str]) -> str | None:
    name = pii_flat.get("name")
    return name.split()[0] if name else None


def generate(pii_flat: dict[str, str], kind: PasswordKind, rng: random.Random) -> str:
    """Return a password of the requested kind for a persona described by `pii_flat`."""
    if kind is PasswordKind.RANDOM:
        alphabet = string.ascii_letters + string.digits
        return "".join(rng.choice(alphabet) for _ in range(rng.randint(8, 12)))

    # PII-laden: guarantee at least one PII token is present.
    token = _first_name(pii_flat) or _birth_year(pii_flat) or "user"
    year = _birth_year(pii_flat) or str(rng.randint(70, 99))
    patterns = [
        f"{token}{year}",
        f"{token.capitalize()}{year}{rng.choice(_SYMBOLS)}",
        f"{token}{rng.choice(_SYMBOLS)}{year}",
        f"{token.lower()}{rng.randint(1, 999)}",
    ]
    return rng.choice(patterns)


def contains_pii(password: str, pii_flat: dict[str, str]) -> bool:
    """True if the password embeds a name token or birth year (for tests/audits)."""
    fn = _first_name(pii_flat)
    yr = _birth_year(pii_flat)
    low = password.lower()
    return (fn is not None and fn.lower() in low) or (yr is not None and yr in password)
