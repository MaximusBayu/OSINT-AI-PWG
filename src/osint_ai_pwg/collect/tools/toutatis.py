"""Toutatis wrapper: Instagram profile -> full name, public email/phone.

Toutatis talks to Instagram's private web API and requires a ``sessionid`` cookie. It is a
no-op unless ``INSTAGRAM_SESSIONID`` is set. Output is line-based:

    Full Name              : Maximus Bayu
    Public Email           : ...
    Public Phone number    : ...
"""

from __future__ import annotations

import os
import re

from osint_ai_pwg.collect.subprocess_tool import SubprocessCollector
from osint_ai_pwg.schemas import Directness, FieldGroup, Observation

_FIELD = re.compile(
    r"^(Full Name|Public Email|Obfuscated email|Public Phone number)\s*:\s*(.+)$",
    re.MULTILINE,
)


class ToutatisCollector(SubprocessCollector):
    name = "toutatis"

    def build_cmd(self, seed: dict[str, str]) -> list[str] | None:
        user = seed.get("username")
        session = os.environ.get("INSTAGRAM_SESSIONID")
        if not user or not session:
            return None
        return ["toutatis", "-u", user, "-s", session]

    def parse(self, stdout: str, seed: dict[str, str], target_id: str) -> list[Observation]:
        obs: list[Observation] = []
        for label, value in _FIELD.findall(stdout):
            value = value.strip()
            if not value:
                continue
            lowered = label.lower()
            if label == "Full Name":
                obs.append(Observation(target_id, "name", FieldGroup.IDENTITY, value,
                                       "toutatis:instagram", Directness.STATED))
            elif "email" in lowered and "@" in value:
                obs.append(Observation(target_id, "email", FieldGroup.IDENTITY, value,
                                       "toutatis:instagram", Directness.STATED))
            elif "phone" in lowered:
                obs.append(Observation(target_id, "phone", FieldGroup.CONTACT, value,
                                       "toutatis:instagram", Directness.STATED))
        return obs
