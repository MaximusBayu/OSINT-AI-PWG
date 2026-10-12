"""Invoke PassLLM's own app.py on a prepared JSONL (real run happens on Colab/GPU).

The runner is injectable for testing the command construction. Parsing PassLLM's stdout
into per-target guesses depends on the tool's actual output format, which must be confirmed
on the first real run (scripts/verify_checkpoint.py) — hence `parse_output` is a documented
hook, not a guess at the format.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

Runner = Callable[[list[str]], str]


def build_command(
    input_file: Path, weights_file: Path, fast: bool = True, base_only: bool = False
) -> list[str]:
    """The PassLLM inference command (run from inside the cloned PassLLM/ dir).

    base_only=True runs the raw base model WITHOUT the LoRA adapter (condition C0b, which
    isolates the LoRA contribution). Confirm the real flag name against Tzohar/PassLLM on
    the first Colab run; '--no-lora' is a placeholder.
    """
    cmd = ["python", "app.py", "--file", str(input_file), "--weights", str(weights_file)]
    if fast:
        cmd.append("--fast")
    if base_only:
        cmd.append("--no-lora")
    return cmd


def _default_runner(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def run(
    input_file: Path, weights_file: Path, runner: Runner | None = None,
    fast: bool = True, base_only: bool = False,
) -> str:
    """Run inference and return raw stdout. Feed the result to `parse_output`."""
    return (runner or _default_runner)(build_command(input_file, weights_file, fast, base_only))


def parse_output(raw: str, order: list[str]) -> dict[str, list[str]]:
    """Map PassLLM stdout to {target_id: [ranked guesses]}.

    TODO(Phase 3): implement against the real output format observed on the first Colab run.
    Kept as an explicit hook so no assumed format is silently baked in.
    """
    raise NotImplementedError(
        "Confirm PassLLM's output format on a real run, then implement parse_output."
    )
