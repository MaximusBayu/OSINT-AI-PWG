"""run_matrix.py — drive PassLLM's app.py across the condition matrix (Colab).

Self-contained: runs inside the cloned PassLLM/ dir (next to app.py). No repo
imports — it mirrors src/osint_ai_pwg/guess/prompt.py + guess/runner.py so the
Colab side needs nothing but PassLLM itself.

Prereqs (do once, in order):
  1.  !git clone https://github.com/Tzohar/PassLLM.git  &&  cd PassLLM
  2.  !pip install -r requirements.txt
  3.  download weights to models/PassLLM_LoRA_Weights.pth  (see README)
  4.  apply the app.py patch (colab/passllm_app.patch): adds --base + allows
      empty profiles (C0/C1).

Input:  targets.json — list of targets, each with an OSINT profile, a
        ground-truth profile, and the true password. See targets.template.json.
Usage:  python run_matrix.py --targets targets.json --mode fast
        python run_matrix.py --targets targets.json --mode fast --post-url https://pwg.maxflow.space/api/passllm/import
Output: matrix_results.json (ranked guesses + crack result per target x condition),
        and — with --post-url — the results POSTed to the VPS so the web UI shows
        the real PassLLM guesses.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

# --- ablation model (mirrors src/osint_ai_pwg/guess/prompt.py) ---------------
# Canonical field -> taxonomy group.
FIELD_TO_GROUP = {
    "name": "identity", "username": "identity", "email": "identity",
    "birth_year": "temporal", "birth_month": "temporal", "birth_day": "temporal",
    "birthdate": "temporal",
    "city": "location", "country": "location", "location": "location",
    "phone": "contact",
}
# Group dropped under each grouped-ablation condition.
ABLATE = {"C4a": "identity", "C4b": "temporal", "C4c": "location", "C4d": "contact"}

# condition -> (profile source, use base model?)
#   profile source: "empty" | "osint" | "gt"
#   base model (no LoRA) only for C0b.
CONDITIONS = [
    ("C0",  "empty", False),   # empty prompt (inherent generation tendency)
    ("C1",  "empty", False),   # trawling: no PII (lower-bound reference)
    ("C0b", "osint", True),    # base model (no LoRA) + full OSINT PII
    ("C2",  "osint", False),   # full OSINT PII
    ("C3",  "gt",    False),   # full ground-truth PII
    ("C4a", "osint", False),   # OSINT minus Identity
    ("C4b", "osint", False),   # OSINT minus Temporal
    ("C4c", "osint", False),   # OSINT minus Location
    ("C4d", "osint", False),   # OSINT minus Contact
    ("C5",  "osint", False),   # full OSINT (tier stratification is in evaluation)
]

MODE_FLAG = {"fast": "--fast", "superfast": "--superfast", "deep": "--deep", "standard": None}
WEIGHTS = "models/PassLLM_LoRA_Weights.pth"


def build_profile(cond: str, osint: dict, gt: dict) -> dict:
    if cond in ("C0", "C1"):
        return {}
    if cond == "C3":
        return dict(gt)
    if cond in ABLATE:
        drop = ABLATE[cond]
        return {k: v for k, v in osint.items() if FIELD_TO_GROUP.get(k) != drop}
    return dict(osint)   # C0b, C2, C5 -> full OSINT


def run_app(profile: dict, mode: str, base: bool, tmp_dir: Path) -> str:
    """Write profile to a temp file, run app.py, return raw stdout."""
    pf = tmp_dir / "profile.json"
    pf.write_text(json.dumps(profile), encoding="utf-8")
    cmd = ["python", "app.py", "--file", str(pf), "--weights", WEIGHTS]
    flag = MODE_FLAG.get(mode)
    if flag:
        cmd.append(flag)
    if base:
        cmd.append("--base")
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=Path.cwd())
    if proc.returncode != 0:
        raise RuntimeError(f"app.py failed: {proc.stderr[-400:]}")
    return proc.stdout


def results_path(stdout: str) -> Path | None:
    for line in stdout.splitlines():
        if "Saving" in line and "candidates to:" in line:
            return Path(line.rsplit("to:", 1)[1].strip())
    return None


def read_guesses_full(path: Path | None) -> list[dict]:
    """PassLLM's results file -> ranked [{password, confidence, log_score}]."""
    if path is None or not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        return []
    return [
        {"password": str(c["password"]), "confidence": c.get("confidence"), "log_score": c.get("log_score")}
        for c in data if isinstance(c, dict) and c.get("password")
    ]


def guess_number(guesses: list[str], password: str) -> int | None:
    try:
        return guesses.index(password) + 1
    except ValueError:
        return None


def post_results(url: str, target_id: str, rows: list) -> None:
    """POST a target's ranked guesses to the VPS import endpoint."""
    conditions = {
        row["condition"]: row.get("top_10_full")
        or [{"password": p, "confidence": None} for p in row["top_10"]]
        for row in rows
    }
    payload = {"target_id": target_id, "conditions": conditions}
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        method="POST", headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=30)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", default="targets.json")
    ap.add_argument("--mode", default="fast", choices=["fast", "superfast", "deep", "standard"])
    ap.add_argument("--budget", type=int, default=1000)
    ap.add_argument("--post-url", default=None, help="POST results to this VPS /api/passllm/import endpoint")
    args = ap.parse_args()

    targets = json.loads(Path(args.targets).read_text(encoding="utf-8"))
    if isinstance(targets, dict):          # a single exported target entry
        targets = [targets]
    tmp = Path("_matrix_tmp")
    tmp.mkdir(exist_ok=True)

    out: dict[str, list] = {}
    for t in targets:
        tid = t["target_id"]
        osint = t.get("osint_profile", {})
        gt = t.get("gt_profile", {})
        password = t["password"]
        rows = []
        for cond, src, base in CONDITIONS:
            profile = build_profile(cond, osint, gt)
            try:
                stdout = run_app(profile, args.mode, base, tmp)
                full = read_guesses_full(results_path(stdout))
            except Exception as e:  # a bad condition must not sink the matrix
                print(f"[!] {tid} {cond}: {e}")
                full = []
            guesses = [g["password"] for g in full]
            gn = guess_number(guesses, password)
            rows.append({
                "condition": cond,
                "cracked": gn is not None and gn <= args.budget,
                "guess_number": gn,
                "num_guesses": len(guesses),
                "top_10": guesses[:10],
                "top_10_full": full[:10],
            })
            print(f"[+] {tid} {cond}: {len(guesses)} guesses, cracked={rows[-1]['cracked']} (gn={gn})")
        out[tid] = rows

        if args.post_url:
            try:
                post_results(args.post_url, tid, rows)
                print(f"[+] posted {tid} results to {args.post_url}")
            except Exception as e:
                print(f"[!] failed to post {tid}: {e}")

    Path("matrix_results.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("\n[+] wrote matrix_results.json")


if __name__ == "__main__":
    main()
