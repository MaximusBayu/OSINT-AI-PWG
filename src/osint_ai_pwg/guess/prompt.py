"""Prompt builder: NormalizedProfile -> PassLLM input object (one JSON per target).

PassLLM (Tzohar/PassLLM) fixes its input schema: name, birth_year, email, phone,
previous passwords. There is NO slot for Location or username, so those PII fields
cannot be fed to this engine (recorded as a limitation; affects RQ3 for Location).

C0 (no-PII baseline) is an empty prompt. Ablation conditions drop whole field groups.
"""

from __future__ import annotations

import json

from osint_ai_pwg.schemas import Condition, FieldGroup, NormalizedProfile

# Groups removed under each ablation condition (ROADMAP section 1).
_ABLATED: dict[Condition, set[FieldGroup]] = {
    Condition.C3: {FieldGroup.IDENTITY},
    Condition.C4: {FieldGroup.TEMPORAL},
    Condition.C5: {FieldGroup.LOCATION, FieldGroup.CONTACT},
}

# Canonical profile field name -> its taxonomy group (for ablation).
FIELD_TO_GROUP: dict[str, FieldGroup] = {
    "name": FieldGroup.IDENTITY,
    "username": FieldGroup.IDENTITY,
    "birthdate": FieldGroup.TEMPORAL,
    "city": FieldGroup.LOCATION,
    "location": FieldGroup.LOCATION,
    "email": FieldGroup.CONTACT,
    "phone": FieldGroup.CONTACT,
}

# Canonical profile field -> PassLLM input key. Fields absent here have no engine slot
# (username, city/location) and are never sent, regardless of condition.
_PASSLLM_KEY: dict[str, str] = {
    "name": "name",
    "birthdate": "birth_year",
    "email": "email",
    "phone": "phone",
}


def _to_birth_year(value: str) -> str:
    """PassLLM wants birth_year. Extract a 4-digit leading year from a birthdate."""
    return value[:4] if len(value) >= 4 and value[:4].isdigit() else value


def build_passllm_object(profile: NormalizedProfile, condition: Condition) -> dict[str, str]:
    """Build the PassLLM input dict for one (profile, condition). Empty dict for C0."""
    if condition is Condition.C0:
        return {}

    ablated = _ABLATED.get(condition, set())
    obj: dict[str, str] = {}
    for name, pf in profile.fields.items():
        group = FIELD_TO_GROUP.get(name)
        if group in ablated:
            continue
        key = _PASSLLM_KEY.get(name)
        if key is None:                       # no PassLLM slot (e.g. location, username)
            continue
        obj[key] = _to_birth_year(pf.value) if key == "birth_year" else pf.value
    return obj


def build_prompt(profile: NormalizedProfile, condition: Condition) -> str:
    """PassLLM JSONL line for one target. C0 -> empty string (no PII)."""
    obj = build_passllm_object(profile, condition)
    return json.dumps(obj) if obj else ""
