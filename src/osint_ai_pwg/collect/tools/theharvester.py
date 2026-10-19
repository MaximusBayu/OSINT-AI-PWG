"""theHarvester wrapper: email domain -> emails exposed on that domain.

A general OSINT tool (thesis-required, always runs when the seed has an email). Given a
seed email, it harvests addresses visible on that email's domain. Each recovered address
is an Identity observation; recovering the seed email itself is a confirmation.

Parses recent theHarvester text output, which lists an emails block such as:
    [*] Emails found:
    ----------------------
    jane@example.com
    john@example.com

Output format varies across theHarvester builds, so the email extraction is isolated and
deliberately lenient (any address-shaped token). Against a real instance, verify the block
headers if tightening is wanted.
"""

from __future__ import annotations

import re

from osint_ai_pwg.collect.subprocess_tool import SubprocessCollector
from osint_ai_pwg.schemas import Directness, FieldGroup, Observation

name = "theharvester"

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


class TheHarvesterCollector(SubprocessCollector):
    name = "theharvester"

    def build_cmd(self, seed: dict[str, str]) -> list[str] | None:
        email = seed.get("email")
        if not email or "@" not in email:
            return None
        domain = email.rsplit("@", 1)[1].strip().lower()
        if not domain:
            return None
        return ["theHarvester", "-d", domain, "-b", "all"]

    def parse(self, stdout: str, seed: dict[str, str], target_id: str) -> list[Observation]:
        domain = seed.get("email", "").rsplit("@", 1)[-1].strip().lower()
        obs: list[Observation] = []
        for addr in dict.fromkeys(m.lower() for m in _EMAIL.findall(stdout)):  # dedupe, keep order
            obs.append(
                Observation(
                    target_id=target_id,
                    field="email",
                    group=FieldGroup.IDENTITY,
                    value=addr,
                    source=f"theharvester:{domain}",
                    directness=Directness.STATED,
                )
            )
        return obs
