"""Run manifest: everything needed to reproduce one (condition) guessing run."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from osint_ai_pwg.schemas import Condition, utcnow_iso


@dataclass
class RunManifest:
    condition: Condition
    config_hash: str
    seed: int
    order: list[str]                 # target ids, aligned to input JSONL lines
    input_file: str
    weights_file: str
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["condition"] = self.condition.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "RunManifest":
        return cls(
            condition=Condition(d["condition"]),
            config_hash=d["config_hash"],
            seed=d["seed"],
            order=d["order"],
            input_file=d["input_file"],
            weights_file=d["weights_file"],
            created_at=d.get("created_at", utcnow_iso()),
        )

    def save(self, path: Path) -> Path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return Path(path)

    @classmethod
    def load(cls, path: Path) -> "RunManifest":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
