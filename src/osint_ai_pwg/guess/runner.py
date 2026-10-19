"""Invoke Tzohar/PassLLM's app.py on a prepared target file (real run on Colab/GPU).

PassLLM's app.py is SINGLE-TARGET: it reads one JSON object (`json.load`), prints the
top-100 to stdout, and writes the full ranked candidate list to
`results/guesses_<name>.json`. This module matches that interface:

  build_command  -> ["python", "app.py", "--file", TARGET, "--weights", W, --<mode>]
  parse_output   -> read the results JSON (path printed to stdout) -> ranked passwords

Three PassLLM-side gaps are handled here and documented for the Colab clone:
  1. No `--no-lora` flag. Condition C0b (raw base model, no LoRA) needs a one-line
     patch to app.py adding a `--base` flag that skips inject_lora_layers() +
     load_state_dict(). build_command emits `--base`; apply the patch below.
  2. Empty profiles are rejected. app.py does `if not profile: sys.exit(1)`, so the
     no-PII conditions (C0 empty prompt, C1 trawling) can't send `{}`. Remove that
     guard (or add `--allow-empty`) on the clone for those conditions.
  3. Single-target only: pipeline.make_passllm_engine loops per target.

app.py patch (apply to the PassLLM clone on Colab):

    # argparse: add
    parser.add_argument("--base", action="store_true", help="run base model, no LoRA")
    # load(): skip the adapter when --base is set
    def load(base=False):
        model, tokenizer = build_model()
        if not base:
            model = inject_lora_layers(model)
            model.load_state_dict(torch.load(Config.WEIGHTS_FILE, map_location="cpu"),
                                  strict=False)
        model.eval(); return model, tokenizer
    # main(): load(args.base); and delete the `if not profile: sys.exit(1)` guard
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable
from pathlib import Path

Runner = Callable[[list[str]], str]

# PassLLM prints: "[+] Saving N candidates to: <path>"
_RESULTS_PATH = re.compile(r"Saving\s+\d+\s+candidates\s+to:\s*(\S+)")

# app.py's real beam-schedule flags (there is no --no-lora).
_MODES = {"fast": "--fast", "superfast": "--superfast", "deep": "--deep", "standard": None}


def build_command(
    input_file: Path,
    weights_file: Path,
    mode: str = "fast",
    base_only: bool = False,
) -> list[str]:
    """Build the PassLLM inference command (run from inside the cloned PassLLM/ dir).

    mode: one of fast | superfast | deep | standard (maps to app.py's argparse flags).
    base_only=True emits `--base` (condition C0b); `--base` is not a stock flag — see
    the app.py patch in this module's docstring.
    """
    if mode not in _MODES:
        raise ValueError(f"unknown mode {mode!r}; expected one of {sorted(_MODES)}")
    cmd = ["python", "app.py", "--file", str(input_file), "--weights", str(weights_file)]
    if _MODES[mode]:
        cmd.append(_MODES[mode])
    if base_only:
        cmd.append("--base")
    return cmd


def _default_runner(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def run(
    input_file: Path,
    weights_file: Path,
    runner: Runner | None = None,
    mode: str = "fast",
    base_only: bool = False,
) -> str:
    """Run inference and return raw stdout. Feed it to `parse_output`."""
    return (runner or _default_runner)(build_command(input_file, weights_file, mode, base_only))


def extract_results_path(raw: str) -> str | None:
    """Pull the results JSON path from PassLLM's 'Saving N candidates to:' line."""
    m = _RESULTS_PATH.search(raw)
    return m.group(1).strip() if m else None


def read_guesses(path: str | Path) -> list[str]:
    """Read a PassLLM results JSON (list of {password, confidence, log_score}) -> ranked."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        return []
    return [str(c["password"]) for c in data if isinstance(c, dict) and c.get("password")]


def parse_output(raw: str, order: list[str]) -> dict[str, list[str]]:
    """Map one PassLLM invocation's stdout to {target_id: [ranked guesses]}.

    Reads the results file PassLLM wrote (path printed in stdout); `order` holds the
    single target id for the per-target loop. Never raises — a missing/unreadable file
    maps to an empty list.
    """
    guesses: list[str] = []
    path = extract_results_path(raw)
    if path is not None:
        try:
            guesses = read_guesses(path)
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            guesses = []
    return {order[0]: guesses} if order else {}
