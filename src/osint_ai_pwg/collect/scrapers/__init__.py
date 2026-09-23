"""Region scraper plugins. Selected per config/regions.yaml so the core stays region-agnostic.

Each scraper is a Collector. The Indonesian plugins (tokopedia, bukalapak) are stubs here;
their real scraping is implemented on the collection host in Phase 2a (needs live access +
BeautifulSoup). Keeping them as no-op Collectors proves the plugin wiring end to end.
"""

from __future__ import annotations

from osint_ai_pwg.collect.base import Collector
from osint_ai_pwg.schemas import Observation


class _StubScraper(Collector):
    """Region scraper placeholder: wired in, returns nothing until implemented on the VPS."""

    def __init__(self, runner=None) -> None:  # signature parity with SubprocessCollector
        self._runner = runner

    def collect(self, target_id: str, seed: dict[str, str]) -> list[Observation]:
        return []


class TokopediaScraper(_StubScraper):
    name = "tokopedia"


class BukalapakScraper(_StubScraper):
    name = "bukalapak"


# name (as used in config/regions.yaml) -> scraper class
REGION_SCRAPERS: dict[str, type[Collector]] = {
    "tokopedia": TokopediaScraper,
    "bukalapak": BukalapakScraper,
}
