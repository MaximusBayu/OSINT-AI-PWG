"""A hung collector must not hold the real-run job after the overall timeout."""

from __future__ import annotations

import time

from osint_ai_pwg.collect.base import Collector
from osint_ai_pwg.collect.orchestrator import collect_target


class _Hang(Collector):
    name = "hang"

    def collect(self, target_id: str, seed: dict[str, str]):
        time.sleep(1.5)
        return []


class _Fast(Collector):
    name = "fast"

    def collect(self, target_id: str, seed: dict[str, str]):
        return []


def test_hung_collector_does_not_block_the_job() -> None:
    events: list[tuple[str, str]] = []
    t0 = time.time()
    out = collect_target(
        "t",
        {},
        [_Hang(), _Fast()],
        timeout_s=0.3,
        on_collector=lambda e, n, c=0: events.append((e, n)),
    )
    elapsed = time.time() - t0
    assert elapsed < 1.0, f"collect_target blocked for {elapsed:.1f}s"
    assert out == []
    assert ("timeout", "hang") in events
