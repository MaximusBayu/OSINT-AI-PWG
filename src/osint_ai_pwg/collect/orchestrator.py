"""Run collectors for a target concurrently, tolerating per-tool failure/timeout.

OSINT tools hang and fail often, so a slow or crashing collector must not sink the run.
Each collector runs in a thread; failures and timeouts are dropped. Results are deduped.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from osint_ai_pwg.collect.base import Collector
from osint_ai_pwg.schemas import Observation


def _dedupe(obs: list[Observation]) -> list[Observation]:
    seen: set[tuple[str, str, str]] = set()
    out: list[Observation] = []
    for o in obs:
        key = (o.field, o.value, o.source)
        if key not in seen:
            seen.add(key)
            out.append(o)
    return out


def collect_target(
    target_id: str,
    seed: dict[str, str],
    collectors: list[Collector],
    timeout_s: float = 60.0,
) -> list[Observation]:
    """Gather observations from all collectors; drop any that error or exceed timeout_s."""
    if not collectors:
        return []
    results: list[Observation] = []
    with ThreadPoolExecutor(max_workers=len(collectors)) as ex:
        futures = [(c, ex.submit(c.collect, target_id, seed)) for c in collectors]
        for _c, fut in futures:
            try:
                results.extend(fut.result(timeout=timeout_s))
            except Exception:  # timeout or collector error -> skip this collector
                continue
    return _dedupe(results)
