"""Holehe wrapper: email -> services where that email is registered.

Confirms the email (Contact) and reveals service usage. Parses holehe output lines that
mark a used service, e.g.:
    [+] twitter.com
"""

from __future__ import annotations

import re

from osint_ai_pwg.collect.subprocess_tool import SubprocessCollector
from osint_ai_pwg.schemas import Directness, FieldGroup, Observation

name = "holehe"

_USED = re.compile(r"\[\+\]\s*(\S+)")


class HoleheCollector(SubprocessCollector):
    name = "holehe"

    def build_cmd(self, seed: dict[str, str]) -> list[str] | None:
        email = seed.get("email")
        if not email:
            return None
        return ["holehe", "--only-used", email]

    def parse(self, stdout: str, seed: dict[str, str], target_id: str) -> list[Observation]:
        email = seed.get("email", "")
        obs: list[Observation] = []
        for site in _USED.findall(stdout):
            obs.append(
                Observation(
                    target_id=target_id,
                    field="email",
                    group=FieldGroup.CONTACT,
                    value=email,
                    source=f"holehe:{site.strip().lower()}",
                    directness=Directness.STATED,
                )
            )
        return obs
