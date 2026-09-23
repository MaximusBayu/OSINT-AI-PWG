"""Generate stratified synthetic ground-truth targets (Phase 1).

Pure builder `build_targets()` is testable; `main()` writes JSON to data/ground_truth/.
Passwords follow the ~60/40 PII-laden split (docs/ethics-and-governance.md section 6).
Targets are stratified across the three footprint tiers.

Every generated record names the platforms each field is 'planted' on. Those plantings
are what the operator actually creates online (see docs/phase1-persona-protocol.md) so
Phase 2 OSINT collection has something to recover.
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path

from osint_ai_pwg.personas import passwords as pw
from osint_ai_pwg.personas.schema import GroundTruth, PasswordKind, validate
from osint_ai_pwg.personas.tiers import classify
from osint_ai_pwg.schemas import FootprintTier

_FIRST = ["Alex", "Sam", "Rina", "Budi", "Maya", "Toni", "Nadia", "Eko", "Lisa", "Dedi"]
_LAST = ["Persona", "Test", "Sample", "Contoh", "Dummy", "Mock"]
_CITY = ["Examplecity", "Testville", "Jakarta", "Bandung", "Sampletown"]
_PLATFORMS = ["twitter", "instagram", "linkedin", "tokopedia", "github", "facebook"]

# How many populated groups + platforms each tier gets (must satisfy tiers.CRITERIA).
_TIER_PLAN: dict[FootprintTier, tuple[int, int]] = {
    FootprintTier.RICH: (4, 4),
    FootprintTier.MODERATE: (2, 2),
    FootprintTier.SPARSE: (1, 1),
}


def _make_pii(rng: random.Random, n_groups: int) -> dict[str, dict[str, str]]:
    first = rng.choice(_FIRST)
    last = rng.choice(_LAST)
    year = rng.randint(1980, 2003)
    handle = f"{first.lower()}{rng.randint(1, 99)}"
    # Group order defines how breadth grows with n_groups.
    all_groups = [
        ("Identity", {"name": f"{first} {last}", "username": handle}),
        ("Temporal", {"birthdate": f"{year}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}"}),
        ("Contact", {"email": f"{handle}@example.com", "phone": f"+62{rng.randint(10**8, 10**9-1)}"}),
        ("Location", {"city": rng.choice(_CITY)}),
    ]
    return {g: fields for g, fields in all_groups[:n_groups]}


def _plant(pii: dict[str, dict[str, str]], rng: random.Random, n_platforms: int) -> dict[str, list[str]]:
    platforms = rng.sample(_PLATFORMS, k=min(n_platforms, len(_PLATFORMS)))
    planted: dict[str, list[str]] = {}
    fields = [f for group in pii.values() for f in group]
    for i, fld in enumerate(fields):
        # spread fields across the chosen platforms; ensure every platform is used
        assigned = {platforms[i % len(platforms)]}
        if i < len(platforms):
            assigned.add(platforms[i])
        planted[fld] = sorted(assigned)
    return planted


def build_targets(n: int, seed: int = 20260923) -> list[GroundTruth]:
    """Build n stratified synthetic ground-truth targets, deterministic given seed."""
    rng = random.Random(seed)
    tiers = list(_TIER_PLAN)
    out: list[GroundTruth] = []
    for i in range(n):
        tier = tiers[i % len(tiers)]                 # round-robin stratification
        n_groups, n_platforms = _TIER_PLAN[tier]
        pii = _make_pii(rng, n_groups)
        planted = _plant(pii, rng, n_platforms)
        kind = PasswordKind.PII_LADEN if rng.random() < 0.6 else PasswordKind.RANDOM
        flat = {f: v for g in pii.values() for f, v in g.items()}
        password = pw.generate(flat, kind, rng)
        gt = GroundTruth(
            target_id=f"t{i+1:02d}",
            footprint_tier=classify(pii, planted),   # trust the classifier, not the plan
            pii=pii,
            password=password,
            password_kind=kind,
            planted=planted,
        )
        assert not validate(gt), validate(gt)
        out.append(gt)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate synthetic ground-truth targets (Phase 1).")
    ap.add_argument("-n", type=int, default=15, help="number of targets (pilot: 10-20)")
    ap.add_argument("--seed", type=int, default=20260923)
    ap.add_argument("--out", type=Path, default=Path("data/ground_truth"))
    args = ap.parse_args()

    targets = build_targets(args.n, args.seed)
    for gt in targets:
        gt.save(args.out)
    counts: dict[str, int] = {}
    for gt in targets:
        counts[gt.footprint_tier.value] = counts.get(gt.footprint_tier.value, 0) + 1
    n_pii = sum(1 for gt in targets if gt.password_kind is PasswordKind.PII_LADEN)
    print(f"wrote {len(targets)} targets to {args.out}")
    print(f"tiers: {counts}")
    print(f"pii-laden passwords: {n_pii}/{len(targets)} ({n_pii/len(targets):.0%})")
    print("NEXT: plant each record's footprints online per docs/phase1-persona-protocol.md")


if __name__ == "__main__":
    main()
