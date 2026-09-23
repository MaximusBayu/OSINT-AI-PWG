"""Base for OSINT tools invoked as external processes.

Subclasses define `build_cmd` (the CLI to run for a seed) and `parse` (tool stdout ->
Observations). A `runner` callable is injectable so tests exercise the parser without the
real binary. Per the Collector contract, tool failure yields [] rather than raising.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable

from osint_ai_pwg.collect.base import Collector
from osint_ai_pwg.schemas import Observation

Runner = Callable[[list[str]], str]


def _default_runner(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return proc.stdout


class SubprocessCollector(Collector):
    name = "subprocess"

    def __init__(self, runner: Runner | None = None) -> None:
        self._runner = runner or _default_runner

    def build_cmd(self, seed: dict[str, str]) -> list[str] | None:
        """Return the CLI argv for this seed, or None if the seed lacks required fields."""
        raise NotImplementedError

    def parse(self, stdout: str, seed: dict[str, str], target_id: str) -> list[Observation]:
        raise NotImplementedError

    def collect(self, target_id: str, seed: dict[str, str]) -> list[Observation]:
        cmd = self.build_cmd(seed)
        if cmd is None:
            return []
        try:
            out = self._runner(cmd)
            return self.parse(out, seed, target_id)
        except Exception:  # never raise: partial-failure tolerance (Collector contract)
            return []
