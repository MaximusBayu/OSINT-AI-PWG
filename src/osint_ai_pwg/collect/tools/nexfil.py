"""nexfil wrapper: username -> sites where the username exists (no auth required).

nexfil checks a few hundred sites and prints one URL per hit, interleaved with progress
bars (``\\r``). We scrape the URLs out of stdout; the tool already tolerates per-site
timeouts. Each distinct host becomes a distinct source.
"""

from __future__ import annotations

import re
import subprocess
from urllib.parse import urlparse

from osint_ai_pwg.collect.subprocess_tool import SubprocessCollector
from osint_ai_pwg.schemas import Directness, FieldGroup, Observation

name = "nexfil"

_URL = re.compile(r"https?://[^\s\r]+")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _run(cmd: list[str]) -> str:
    # nexfil sweeps hundreds of sites; outlive the 120s subprocess default.
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=75)
    return proc.stdout


class NexfilCollector(SubprocessCollector):
    name = "nexfil"

    def __init__(self, runner=None) -> None:
        super().__init__(runner or _run)

    def build_cmd(self, seed: dict[str, str]) -> list[str] | None:
        user = seed.get("username")
        if not user:
            return None
        return ["nexfil", "-u", user, "-t", "10"]

    def parse(self, stdout: str, seed: dict[str, str], target_id: str) -> list[Observation]:
        user = seed.get("username", "")
        obs: list[Observation] = []
        seen: set[str] = set()
        for raw in _URL.findall(_ANSI.sub("", stdout)):
            url = raw.rstrip(".,;:)]}\"'")
            if "nexfil" in url or "thewhiteh4t" in url:
                continue
            try:
                host = urlparse(url).netloc.lower()
            except ValueError:  # malformed URL in tool output
                continue
            if not host or host in seen:
                continue
            seen.add(host)
            obs.append(
                Observation(
                    target_id=target_id,
                    field="username",
                    group=FieldGroup.IDENTITY,
                    value=user,
                    source=f"nexfil:{host}",
                    directness=Directness.STATED,
                    url=url,
                )
            )
        return obs
