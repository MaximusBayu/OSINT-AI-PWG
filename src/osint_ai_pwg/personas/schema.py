"""Ground-truth record: known PII + password for one synthetic/self target.

Fully specifies the C2 condition. Persisted as data/ground_truth/{target_id}.json (gitignored).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path

from osint_ai_pwg.schemas import FieldGroup, FootprintTier


class PasswordKind(str, Enum):
    PII_LADEN = "pii_laden"   # embeds a PII token (mirrors real user behavior)
    RANDOM = "random"         # no PII


@dataclass
class GroundTruth:
    """Known ground truth for one target. `planted` records where each field was seeded
    online, so Phase 2 OSINT collection has something to recover."""

    target_id: str
    footprint_tier: FootprintTier
    pii: dict[str, dict[str, str]]                 # group name -> {field: value}
    password: str
    password_kind: PasswordKind
    planted: dict[str, list[str]] = field(default_factory=dict)  # field -> [platforms]

    def flatten_pii(self) -> dict[str, str]:
        """All fields as a flat {field: value} map, across groups."""
        out: dict[str, str] = {}
        for group_fields in self.pii.values():
            out.update(group_fields)
        return out

    def to_dict(self) -> dict:
        d = asdict(self)
        d["footprint_tier"] = self.footprint_tier.value
        d["password_kind"] = self.password_kind.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "GroundTruth":
        return cls(
            target_id=d["target_id"],
            footprint_tier=FootprintTier(d["footprint_tier"]),
            pii=d["pii"],
            password=d["password"],
            password_kind=PasswordKind(d["password_kind"]),
            planted=d.get("planted", {}),
        )

    def save(self, out_dir: Path) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{self.target_id}.json"
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path) -> "GroundTruth":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


_VALID_GROUPS = {g.value for g in FieldGroup}


def validate(gt: GroundTruth) -> list[str]:
    """Return a list of problems; empty list means valid."""
    problems: list[str] = []
    if not gt.target_id:
        problems.append("empty target_id")
    if not gt.password:
        problems.append("empty password")
    bad_groups = set(gt.pii) - _VALID_GROUPS
    if bad_groups:
        problems.append(f"unknown PII groups: {sorted(bad_groups)}")
    if not gt.flatten_pii():
        problems.append("no PII fields present")
    return problems
