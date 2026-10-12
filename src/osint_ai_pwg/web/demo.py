"""Offline stand-ins for the VPS/GPU parts, so the web demo runs without them.

- DemoCollector: simulates OSINT by recovering a NOISY SUBSET of a target's planted PII,
  with recall scaled by footprint tier (rich recovers most, sparse little). This is the
  'noise' the thesis measures — real OSINT tools replace it on the VPS.
- DemoEngine: a PII-pattern password guesser standing in for PassLLM. It enumerates the
  same PII-laden pattern family used to assign persona passwords, so it cracks a PII-laden
  password WHEN it has the needed PII (name + birth year) and misses otherwise.

Neither is used in the real experiment; both are labelled demo mode in the UI.
"""

from __future__ import annotations

import hashlib

from osint_ai_pwg.personas.schema import GroundTruth
from osint_ai_pwg.schemas import Directness, FieldGroup, Observation

# Fraction of planted fields OSINT recovers, by tier (deterministic which ones).
_RECALL = {"rich": 0.9, "moderate": 0.6, "sparse": 0.3}
# Field -> its group, for emitting Observations.
_GROUP = {
    "name": FieldGroup.IDENTITY, "username": FieldGroup.IDENTITY,
    "email": FieldGroup.IDENTITY,          # revised taxonomy: email is Identity
    "birthdate": FieldGroup.TEMPORAL,
    "city": FieldGroup.LOCATION,
    "phone": FieldGroup.CONTACT,
}


def _keep(target_id: str, field: str, recall: float) -> bool:
    """Deterministic per (target, field): keep if its hash falls under the recall fraction."""
    h = hashlib.sha256(f"{target_id}:{field}".encode()).hexdigest()
    return (int(h[:8], 16) / 0xFFFFFFFF) < recall


class DemoCollector:
    """Recovers a noisy subset of a target's planted PII. Holds the roster (the 'truth online')."""

    name = "demo"

    def __init__(self, roster: dict[str, GroundTruth]) -> None:
        self._roster = roster

    def collect(self, target_id: str, seed: dict[str, str]) -> list[Observation]:
        gt = self._roster.get(target_id)
        if gt is None:
            return []
        recall = _RECALL.get(gt.footprint_tier.value, 0.5)
        obs: list[Observation] = []
        for group, fields in gt.pii.items():
            for field, value in fields.items():
                # seed fields are already known; other fields recovered per recall
                if not (field in seed or _keep(target_id, field, recall)):
                    continue
                # recover the field from EVERY platform it was planted on — each platform is
                # an independent source, so cross-source agreement (and confidence) grows with
                # how widely the field is exposed.
                platforms = gt.planted.get(field) or ["web"]
                for platform in platforms:
                    obs.append(Observation(
                        target_id, field, _GROUP.get(field, FieldGroup.IDENTITY),
                        value, f"demo:{platform}", Directness.STATED,
                    ))
        return obs


class DemoEngine:
    """Stand-in for PassLLM: enumerates PII-laden password patterns from the given PII."""

    _SYMBOLS = "!@#$%"
    _COMMON = ["123456", "password", "qwerty", "111111", "abc123"]

    def guesses(self, passllm_obj: dict[str, str]) -> list[str]:
        out: list[str] = []
        name = passllm_obj.get("name")
        year = passllm_obj.get("birth_year")
        if name and year:
            token = name.split()[0]
            for sym in self._SYMBOLS:
                out += [f"{token}{year}", f"{token.capitalize()}{year}{sym}", f"{token}{sym}{year}"]
            out += [f"{token.lower()}{n}" for n in range(1, 1000)]
        out += self._COMMON
        # dedupe preserving order (PII patterns first = low guess numbers)
        seen: set[str] = set()
        return [g for g in out if not (g in seen or seen.add(g))]
