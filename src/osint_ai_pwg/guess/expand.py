"""Deterministic PII candidate expansion for patterns PassLLM was not trained on.

PassLLM's synthetic training data only contains five PII patterns:
first+year, last+123, pet+day, username+!, city+2020. It never sees
username+number, first+last+number, or dotted/underscored name combinations, so
those candidates cannot be expected from the model even when the PII is perfect.

This module enumerates those patterns from the same NormalizedProfile and is meant
to sit in front of the PassLLM ranking. It is a rule-based complement, not a
replacement: the PassLLM-only condition stays the anchor, and the hybrid is
reported separately.

Ablation conditions C4a-C4d are honoured, so the expansion drops the same field
group the LLM prompt drops.
"""

from __future__ import annotations

import re

from osint_ai_pwg.guess.prompt import FIELD_TO_GROUP, _ABLATED
from osint_ai_pwg.schemas import Condition, NormalizedProfile

MIN_LEN = 5
MAX_LEN = 24

_SUFFIXES = [
    "", "1", "12", "123", "1234", "12345", "!", "!!", "@", "@@", "#", "$", "%",
    "01", "07", "99", "00", "007", "2020", "2021", "2022", "2023",
    "2024", "2025", "2026",
]

_SYMBOLS = "!@#$%"

_SEPARATORS = ["", ".", "_", "-"]

_LEET = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$"})


def _fields(profile: NormalizedProfile, condition: Condition) -> dict[str, str]:
    """Return the profile fields that survive the condition's ablation."""
    ablated = _ABLATED.get(condition, set())
    out: dict[str, str] = {}
    for name, pf in profile.fields.items():
        if FIELD_TO_GROUP.get(name) in ablated:
            continue
        value = str(pf.value).strip()
        if value:
            out[name] = value
    return out


def _name_bases(name: str) -> list[str]:
    parts = [p for p in name.replace(",", " ").split() if p]
    if not parts:
        return []
    bases: list[str] = []
    # Full name with each separator, first+last, last+first, and the leading
    # two or three tokens (a middle name is often part of the passphrase).
    for sep in _SEPARATORS:
        bases.append(sep.join(parts))
        if len(parts) >= 2:
            bases.append(sep.join([parts[0], parts[-1]]))
            bases.append(sep.join([parts[-1], parts[0]]))
    for n in (2, 3):
        if len(parts) >= n:
            chunk = parts[:n]
            for sep in _SEPARATORS:
                bases.append(sep.join(chunk))
    bases.append(parts[0])
    bases.append(parts[-1])
    if len(parts) >= 2:
        bases.append(parts[0] + parts[-1][0])
    return bases


def expand_candidates(
    profile: NormalizedProfile,
    condition: Condition = Condition.C2,
    limit: int = 5000,
) -> list[str]:
    """Return deterministic PII candidates, highest-priority first.

    Length is bounded to [MIN_LEN, MAX_LEN] so five to seven character targets
    are not silently unreachable.
    """
    f = _fields(profile, condition)
    bases: list[str] = []

    username = f.get("username")
    if username:
        bases.extend([username, username.lower(), username.upper(), username.capitalize()])

    name = f.get("name")
    if name:
        bases.extend(_name_bases(name))

    email = f.get("email")
    if email:
        local = email.split("@", 1)[0].strip()
        if local:
            bases.append(local)

    for key in ("city", "country"):
        value = f.get(key)
        if value:
            bases.extend([value, value.lower(), value.replace(" ", "")])

    year = f.get("birth_year", "")
    month = f.get("birth_month", "")
    day = f.get("birth_day", "")
    birthdate = f.get("birthdate", "")
    if birthdate and not year:
        year = birthdate[:4] if len(birthdate) >= 4 and birthdate[:4].isdigit() else ""
    if year:
        # Some sparse personas use the birth year itself as the token.
        bases.append(year)

    dynamic_suffixes = list(_SUFFIXES)
    for value in (year, month, day):
        if value and value not in dynamic_suffixes:
            dynamic_suffixes.append(value)
    if year:
        # The generator uses three families the model never saw: symbol+year,
        # year+symbol, and a 1-999 numeric tail. Two-digit years 70-99 are the
        # fallback when the persona has no birthdate.
        for symbol in _SYMBOLS:
            for value in (f"{symbol}{year}", f"{year}{symbol}"):
                if value not in dynamic_suffixes:
                    dynamic_suffixes.append(value)
        dynamic_suffixes.extend(str(n) for n in range(70, 100) if str(n) not in dynamic_suffixes)
    dynamic_suffixes.extend(str(n) for n in range(1, 1000) if str(n) not in dynamic_suffixes)
    if year and month:
        dynamic_suffixes.extend([f"{year}{month}", f"{month}{year}"])
    if year and day:
        dynamic_suffixes.extend([f"{year}{day}", f"{day}{year}"])
    if month and day:
        dynamic_suffixes.extend([f"{month}{day}", f"{day}{month}"])
    if year and month and day:
        dynamic_suffixes.extend([f"{year}{month}{day}", f"{day}{month}{year}"])

    # Numeric tails the person already exposes in the username or email are a
    # common password suffix (username digits are the strongest cue for max/max2).
    for source in (username or "", email or "", f.get("phone", "")):
        for digits in re.findall(r"\d+", source):
            if len(digits) <= 8 and digits not in dynamic_suffixes:
                dynamic_suffixes.append(digits)

    out: list[str] = []
    seen: set[str] = set()

    def add(candidate: str) -> None:
        candidate = candidate.strip()
        if not (MIN_LEN <= len(candidate) <= MAX_LEN):
            return
        if candidate in seen:
            return
        seen.add(candidate)
        out.append(candidate)

    # Priority order: the patterns a person is most likely to build from a name
    # and username, with the common suffixes first. Without this the exhaustive
    # suffix sweep pushes first+middle+123 past rank 300.
    priority_suffixes: list[str] = []
    for suffix in ["", "1", "123", "!", "12", "1234", year, "2024"]:
        if suffix and suffix not in priority_suffixes:
            priority_suffixes.append(suffix)
        elif not suffix:
            priority_suffixes.append(suffix)
    if username:
        for digits in re.findall(r"\d+", username):
            if digits not in priority_suffixes:
                priority_suffixes.append(digits)

    def add_base(base: str, suffixes: list[str]) -> None:
        if not base:
            return
        for suffix in suffixes:
            add(base + suffix)
            add(base.lower() + suffix)
            add(base.capitalize() + suffix)

    if username:
        add(username)
        add(username.lower())
        add(username.capitalize())
    if name:
        parts = [p for p in name.replace(",", " ").split() if p]
        # Username digits are the strongest numeric cue; put name+digits before
        # the wider suffix sweep so it lands in the first hundred.
        if username:
            for digits in re.findall(r"\d+", username):
                if len(parts) >= 2:
                    add_base(parts[0] + parts[-1] + digits, [""])
                if parts:
                    add_base(parts[0] + digits, [""])
        if len(parts) >= 2:
            add_base(parts[0] + parts[-1], priority_suffixes)
            add_base(parts[0] + parts[1], priority_suffixes)
            add_base(parts[-1] + parts[0], priority_suffixes)
        if parts:
            add_base(parts[0], priority_suffixes)
            add_base(parts[-1], priority_suffixes)
    if username:
        add_base(username, priority_suffixes)
    if email:
        add_base(email.split("@", 1)[0], priority_suffixes)

    for suffix in dynamic_suffixes:
        for base in bases:
            if not base:
                continue
            variants = [base, base.lower(), base.capitalize(), base.upper(), base.translate(_LEET)]
            for variant in variants:
                add(variant + suffix)
                if len(out) >= limit:
                    return out

    # Cross-field combinations that are common but not covered by base+suffix.
    first = name.split()[0] if name else ""
    last = name.split()[-1] if name else ""
    for left in (first, last, username or "", email.split("@", 1)[0] if email else ""):
        if not left:
            continue
        for right in (year, month, day):
            if right:
                add(left + right)
                add(right + left)
        for sep in _SEPARATORS:
            if first and last:
                add(first + sep + last + year)
                add(first + sep + last + "123")

    return out[:limit]
