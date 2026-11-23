"""Score C3 results against the held-out ground-truth passwords.

Run locally after copying the GPU's results/ directory back:

    PYTHONPATH=src python scripts/check_c3.py \
        --results c3-results --targets max t01 t11

It prints PassLLM ranks plus the deterministic-expansion rank and the hybrid rank.
The ground-truth password is read locally and never printed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from osint_ai_pwg.guess.expand import expand_candidates
from osint_ai_pwg.guess.prompt import build_passllm_object
from osint_ai_pwg.personas.schema import GroundTruth
from osint_ai_pwg.schemas import Condition, NormalizedProfile, ProfileField


def gt_profile(gt: GroundTruth) -> NormalizedProfile:
    fields: dict[str, ProfileField] = {}
    for group in gt.pii.values():
        for name, value in group.items():
            fields[name] = ProfileField(value=str(value), confidence=1.0, sources=1)
    return NormalizedProfile(gt.target_id, fields, gt.footprint_tier)


def rank_of(passwords: list[str], target: str, casefold: bool = False) -> int | None:
    if casefold:
        target = target.lower()
    for index, password in enumerate(passwords, start=1):
        if (password.lower() if casefold else password) == target:
            return index
    return None


def main() -> None:
    ap = argparse.ArgumentParser(description="Score C3 results.")
    ap.add_argument("--results", type=Path, default=Path("c3-results"))
    ap.add_argument("--gt-dir", type=Path, default=Path.home() / "pwg-data/ground_truth")
    ap.add_argument("--targets", nargs="+", default=["max", "t01", "t11"])
    args = ap.parse_args()

    header = f"{'target':6} {'variant':10} {'keys':5} {'passllm':8} {'ci':5} {'expand':7} {'hybrid':7} {'hit100':7} {'hit1000':8}"
    print(header)
    print("-" * len(header))

    for target in args.targets:
        gt = GroundTruth.load(args.gt_dir / f"{target}.json")
        profile = gt_profile(gt)
        expanded = expand_candidates(profile, Condition.C3)
        safe_name = (gt.flatten_pii().get("name") or target).replace(" ", "_")

        for variant, project in (("full", False), ("projected", True)):
            path = args.results / variant / f"guesses_{safe_name}.json"
            if not path.exists():
                print(f"{target:6} {variant:10} (missing {path})")
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
            passwords = [item["password"] for item in data]
            p_rank = rank_of(passwords, gt.password)
            p_rank_ci = rank_of(passwords, gt.password, casefold=True)
            e_rank = expanded.index(gt.password) + 1 if gt.password in expanded else None
            hybrid = list(dict.fromkeys(expanded + passwords))
            h_rank = rank_of(hybrid, gt.password)
            keys = len(build_passllm_object(profile, Condition.C3, project_to_trained=project))
            print(f"{target:6} {variant:10} {keys:<5} {str(p_rank):8} {str(p_rank_ci):5} "
                  f"{str(e_rank):7} {str(h_rank):7} "
                  f"{str(bool(p_rank and p_rank <= 100)):7} {str(bool(p_rank and p_rank <= 1000)):8}")


if __name__ == "__main__":
    main()
