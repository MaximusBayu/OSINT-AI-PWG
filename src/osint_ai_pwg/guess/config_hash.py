"""Deterministic hash of the experiment config, stamped into every run for reproducibility."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


def config_hash(cfg: dict) -> str:
    """16-hex-char digest of a config dict, stable across key ordering."""
    canonical = json.dumps(cfg, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def hash_config_file(path: Path) -> str:
    cfg = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return config_hash(cfg)
