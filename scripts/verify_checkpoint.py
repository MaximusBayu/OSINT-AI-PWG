"""Verify the PassLLM checkpoint runs (ROADMAP Phase 0/3 gate).

Clones Tzohar/PassLLM, downloads the release weights (~126 MB), and runs its own app.py
on a THROWAWAY synthetic probe (never an eval target). Clears the Phase 3 gate if it
produces output.

Run in Colab (T4) or on a GPU host:
    python scripts/verify_checkpoint.py

License note: PassLLM is GPL-3.0. This script only clones + runs it; it does not vendor
its code into this repository. See ROADMAP risk register.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

REPO = "https://github.com/Tzohar/PassLLM.git"
WEIGHTS_URL = "https://github.com/Tzohar/PassLLM/releases/download/v1.3.0/PassLLM-Qwen3-4B-v1.0.pth"
WEIGHTS_REL = "models/PassLLM-Qwen3-4B-v1.0.pth"
WORKDIR = Path("PassLLM")

# Synthetic throwaway probe — NOT an evaluation target.
PROBE = {"name": "Test Persona", "birth_year": "1990", "email": "probe@example.com"}


def sh(cmd: list[str], cwd: Path | None = None) -> None:
    print("$", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, check=True)


def main() -> None:
    if not WORKDIR.exists():
        sh(["git", "clone", REPO, str(WORKDIR)])

    weights = WORKDIR / WEIGHTS_REL
    weights.parent.mkdir(parents=True, exist_ok=True)
    if not weights.exists():
        sh(["wget", "-O", str(weights), WEIGHTS_URL])

    probe_file = WORKDIR / "probe.jsonl"
    probe_file.write_text(json.dumps(PROBE) + "\n", encoding="utf-8")

    # Install repo deps if present, then run its inference on the probe.
    req = WORKDIR / "requirements.txt"
    if req.exists():
        sh(["python", "-m", "pip", "install", "-q", "-r", str(req)])

    sh(
        ["python", "app.py", "--file", "probe.jsonl", "--weights", WEIGHTS_REL, "--fast"],
        cwd=WORKDIR,
    )
    print("OK: PassLLM loaded + generated on the probe. Phase 3 gate cleared.")


if __name__ == "__main__":
    main()
