"""Build the C3 (ground-truth PII) input files for the first engine checkup.

C3 asks one question only: can PassLLM guess when the PII is perfect? It is the
upper bound, not the OSINT condition. Each target gets two prompt variants:

  full/       the nine-field prompt the thesis currently sends
  projected/  only name, birth_year, username, sister_pw (the keys PassLLM trained on)

The ground-truth password is deliberately NOT written here; it stays in the local
GroundTruth file. Upload only the c3-check/ directory to the GPU box.

Usage:
    PYTHONPATH=src python scripts/build_c3.py --targets max t01 t11
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from osint_ai_pwg.guess.prompt import build_passllm_object
from osint_ai_pwg.personas.schema import GroundTruth
from osint_ai_pwg.schemas import Condition, NormalizedProfile, ProfileField


def gt_profile(gt: GroundTruth) -> NormalizedProfile:
    """Ground-truth PII as a NormalizedProfile with certainty 1.0."""
    fields: dict[str, ProfileField] = {}
    for group in gt.pii.values():
        for name, value in group.items():
            fields[name] = ProfileField(value=str(value), confidence=1.0, sources=1)
    return NormalizedProfile(
        target_id=gt.target_id,
        fields=fields,
        footprint_tier=gt.footprint_tier,
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Build C3 PassLLM input files.")
    ap.add_argument("--targets", nargs="+", default=["max", "t01", "t11"])
    ap.add_argument("--gt-dir", type=Path, default=Path.home() / "pwg-data/ground_truth")
    ap.add_argument("--out", type=Path, default=Path("c3-check"))
    args = ap.parse_args()

    full_dir = args.out / "full"
    projected_dir = args.out / "projected"
    full_dir.mkdir(parents=True, exist_ok=True)
    projected_dir.mkdir(parents=True, exist_ok=True)

    manifest = []
    for target in args.targets:
        gt = GroundTruth.load(args.gt_dir / f"{target}.json")
        profile = gt_profile(gt)
        full = build_passllm_object(profile, Condition.C3)
        projected = build_passllm_object(profile, Condition.C3, project_to_trained=True)

        for directory, obj in ((full_dir, full), (projected_dir, projected)):
            (directory / f"{target}.jsonl").write_text(
                json.dumps(obj, ensure_ascii=False) + "\n", encoding="utf-8"
            )

        manifest.append({
            "target_id": gt.target_id,
            "tier": gt.footprint_tier.value,
            "password_kind": gt.password_kind.value,
            "password_length": len(gt.password),
            "pii_fields": sorted(gt.flatten_pii()),
            "full_prompt_keys": sorted(full),
            "projected_prompt_keys": sorted(projected),
        })

    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    print(f"\nwrote {args.out}/full and {args.out}/projected")


if __name__ == "__main__":
    main()
