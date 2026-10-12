"""Prompt builder: NormalizedProfile -> PassLLM input object (one JSON per target).

Revised design 2026-10: the normalized PII dictionary is fed to PassLLM via the Qwen3
chat template with ALL nine fields (name, email, birth_year, birth_month, birth_day,
phone, city, country, username). The old fixed 4-field JSONL schema (and its Location/
username blind spot) no longer applies -- confirm the exact chat-template key names on
the first real Colab run (ties to runner.parse_output).

No-PII conditions (C0 empty prompt, C1 trawling) send an empty object. Ablation
conditions C4a-C4d each drop one whole field group. C2/C0b/C5 send the full profile;
C3 (ground truth) is the full profile of the GT record, built by the caller.
"""

from __future__ import annotations

import json

from osint_ai_pwg.schemas import Condition, FieldGroup, NormalizedProfile

# Conditions that send NO PII to the engine (empty prompt).
_NO_PII: frozenset[Condition] = frozenset({Condition.C0, Condition.C1})

# Group removed under each grouped-ablation condition (revised design, C4a-C4d).
_ABLATED: dict[Condition, set[FieldGroup]] = {
    Condition.C4A: {FieldGroup.IDENTITY},
    Condition.C4B: {FieldGroup.TEMPORAL},
    Condition.C4C: {FieldGroup.LOCATION},
    Condition.C4D: {FieldGroup.CONTACT},
}

# Canonical profile field name -> its taxonomy group (for ablation). Revised taxonomy:
# email is Identity; Contact is phone only. Legacy single fields (birthdate, location)
# are kept so profiles produced before the collect-layer 9-field split still map.
FIELD_TO_GROUP: dict[str, FieldGroup] = {
    # Identity
    "name": FieldGroup.IDENTITY,
    "username": FieldGroup.IDENTITY,
    "email": FieldGroup.IDENTITY,
    # Temporal
    "birth_year": FieldGroup.TEMPORAL,
    "birth_month": FieldGroup.TEMPORAL,
    "birth_day": FieldGroup.TEMPORAL,
    "birthdate": FieldGroup.TEMPORAL,        # legacy (pre-split)
    # Location
    "city": FieldGroup.LOCATION,
    "country": FieldGroup.LOCATION,
    "location": FieldGroup.LOCATION,         # legacy (pre-split)
    # Contact
    "phone": FieldGroup.CONTACT,
}

# Canonical profile field -> PassLLM chat-template key. All nine fields are now sent.
# Legacy fields map to their split equivalents (birthdate -> birth_year via extraction,
# location -> city). Confirm the real key names against Tzohar/PassLLM on the first run.
_PASSLLM_KEY: dict[str, str] = {
    "name": "name",
    "username": "username",
    "email": "email",
    "birth_year": "birth_year",
    "birth_month": "birth_month",
    "birth_day": "birth_day",
    "birthdate": "birth_year",               # legacy: extract leading year
    "city": "city",
    "country": "country",
    "location": "city",                      # legacy
    "phone": "phone",
}


def _to_birth_year(value: str) -> str:
    """Extract a 4-digit leading year from a legacy 'birthdate' value."""
    return value[:4] if len(value) >= 4 and value[:4].isdigit() else value


def build_passllm_object(profile: NormalizedProfile, condition: Condition) -> dict[str, str]:
    """Build the PassLLM input dict for one (profile, condition).

    Empty dict for the no-PII conditions (C0, C1). C4a-C4d drop one group. Everything
    else (C2, C0b, C3, C5) sends the full profile.
    """
    if condition in _NO_PII:
        return {}

    ablated = _ABLATED.get(condition, set())
    obj: dict[str, str] = {}
    for name, pf in profile.fields.items():
        group = FIELD_TO_GROUP.get(name)
        if group in ablated:
            continue
        key = _PASSLLM_KEY.get(name)
        if key is None:                       # unknown field, no engine slot
            continue
        obj[key] = _to_birth_year(pf.value) if name == "birthdate" else pf.value
    return obj


def build_prompt(profile: NormalizedProfile, condition: Condition) -> str:
    """PassLLM JSONL line for one target. No-PII conditions -> empty string."""
    obj = build_passllm_object(profile, condition)
    return json.dumps(obj) if obj else ""
