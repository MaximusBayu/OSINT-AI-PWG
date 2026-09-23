"""Common interface every collection tool wrapper implements.

Concrete wrappers (theHarvester, Sherlock, SpiderFoot, Holehe, region scrapers)
land here in Phase 2a. Region scrapers are selected via config/regions.yaml so the
collection core stays region-agnostic (fixed decision: mixed/international).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from osint_ai_pwg.schemas import Observation


class Collector(ABC):
    """A single OSINT source. Must tolerate partial failure without raising."""

    name: str

    @abstractmethod
    def collect(self, target_id: str, seed: dict[str, str]) -> list[Observation]:
        """Return observations for a target.

        Args:
            target_id: pseudonym for the target.
            seed: known handles/emails/etc. to bootstrap the search.

        Returns:
            Possibly empty list. Never raises on tool failure; log and return [].
        """
        raise NotImplementedError
