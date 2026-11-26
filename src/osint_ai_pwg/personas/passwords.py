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
    # Nine-field profiles store birth_year directly; older four-field fixtures
    # store birthdate. Read both, otherwise the generator invents a random year.
    bd = pii_flat.get("birthdate") or pii_flat.get("birth_year")
    return bd[:4] if bd and bd[:4].isdigit() else None


def _first_name(pii_flat: dict[str, str]) -> str | None:
    name = pii_flat.get("name")
    return name.split()[0] if name else None


def _patterns(token: str, year: str | None, sym: str, rng: random.Random) -> list[str]:
    """Password shapes this persona can actually produce from its own PII.

    A persona with no birth year has no year to embed. Inventing one puts a number in
    the ground truth that no collection could ever recover, which makes the record
    uncrackable by construction.
    """
    digits = str(rng.randint(10, 9999))
    if year:
        return [
            f"{token}{year}",
            f"{token.capitalize()}{year}{sym}",
            f"{token}{sym}{year}",
            f"{token.lower()}{digits}",
        ]
    return [
        f"{token.lower()}{digits}",
        f"{token.capitalize()}{digits}{sym}",
        f"{token}{sym}{digits}",
    ]


def generate(pii_flat: dict[str, str], kind: PasswordKind, rng: random.Random) -> str:
    """Return a password of the requested kind for a persona described by `pii_flat`."""
    if kind is PasswordKind.RANDOM:
        alphabet = string.ascii_letters + string.digits
        return "".join(rng.choice(alphabet) for _ in range(rng.randint(8, 12)))

    # PII-laden: guarantee at least one PII token is present.
    token = _first_name(pii_flat) or _birth_year(pii_flat) or "user"
    year = _birth_year(pii_flat)
    patterns = _patterns(token, year, rng.choice(_SYMBOLS), rng)
    return rng.choice(patterns)


def contains_pii(password: str, pii_flat: dict[str, str]) -> bool:
    """True if the password embeds a name token or birth year (for tests/audits)."""
    fn = _first_name(pii_flat)
    yr = _birth_year(pii_flat)
    low = password.lower()
    return (fn is not None and fn.lower() in low) or (yr is not None and yr in password)
