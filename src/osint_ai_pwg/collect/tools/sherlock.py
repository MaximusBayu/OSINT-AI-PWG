"""Sherlock wrapper: username -> platforms where that username exists.

Confirms account presence (Identity/username) and yields the platform per hit, which also
drives footprint-spread signals. Parses `sherlock <user> --print-found` output lines like:
    [+] GitHub: https://github.com/user
"""

from __future__ import annotations

import re

from osint_ai_pwg.collect.subprocess_tool import SubprocessCollector
from osint_ai_pwg.schemas import Directness, FieldGroup, Observation

name = "sherlock"

_FOUND = re.compile(r"\[\+\]\s*([^:]+):\s*(\S+)")


class SherlockCollector(SubprocessCollector):
    name = "sherlock"

    def build_cmd(self, seed: dict[str, str]) -> list[str] | None:
        user = seed.get("username")
        if not user:
            return None
        return ["sherlock", user, "--print-found", "--timeout", "10"]

    def parse(self, stdout: str, seed: dict[str, str], target_id: str) -> list[Observation]:
        user = seed.get("username", "")
        obs: list[Observation] = []
        for site, _url in _FOUND.findall(stdout):
            obs.append(
                Observation(
                    target_id=target_id,
                    field="username",
                    group=FieldGroup.IDENTITY,
                    value=user,
                    source=f"sherlock:{site.strip().lower()}",
                    directness=Directness.STATED,
                )
            )
        return obs
