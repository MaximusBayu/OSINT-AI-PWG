"""Assemble the collector list for a run: general tools + region plugins.

General OSINT tools always run (subject to the seed having the fields they need). Region
scrapers come from config/regions.yaml, keeping the core region-agnostic.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from osint_ai_pwg.collect.base import Collector
from osint_ai_pwg.collect.scrapers import REGION_SCRAPERS
from osint_ai_pwg.collect.tools.holehe import HoleheCollector
from osint_ai_pwg.collect.tools.sherlock import SherlockCollector

_DEFAULT_CONFIG = Path("config/regions.yaml")


def _region_scraper_names(region: str | None, config_path: Path) -> list[str]:
    if region is None or not config_path.exists():
        return []
    cfg = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    return list((cfg.get("regions", {}).get(region, {}) or {}).get("scrapers", []) or [])


def build_collectors(
    region: str | None = None,
    config_path: Path = _DEFAULT_CONFIG,
    runner=None,
) -> list[Collector]:
    """General tools + any region scrapers configured for `region`."""
    collectors: list[Collector] = [SherlockCollector(runner), HoleheCollector(runner)]
    for scraper_name in _region_scraper_names(region, config_path):
        cls = REGION_SCRAPERS.get(scraper_name)
        if cls is not None:
            collectors.append(cls(runner))
    return collectors
