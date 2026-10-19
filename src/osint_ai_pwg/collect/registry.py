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
from osint_ai_pwg.collect.tools.spiderfoot import SpiderFootCollector
from osint_ai_pwg.collect.tools.theharvester import TheHarvesterCollector

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
    spiderfoot_url: str | None = None,
) -> list[Collector]:
    """General OSINT tools + any region scrapers configured for `region`.

    General tools (Sherlock, Holehe, theHarvester) always run. SpiderFoot is a general tool
    too, but needs a hosted instance, so it is only added when `spiderfoot_url` is given.
    """
    collectors: list[Collector] = [
        SherlockCollector(runner),
        HoleheCollector(runner),
        TheHarvesterCollector(runner),
    ]
    if spiderfoot_url:
        collectors.append(SpiderFootCollector(spiderfoot_url))
    for scraper_name in _region_scraper_names(region, config_path):
        cls = REGION_SCRAPERS.get(scraper_name)
        if cls is not None:
            collectors.append(cls(runner))
    return collectors
