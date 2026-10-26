"""Run collectors for a target concurrently, tolerating per-tool failure/timeout.

OSINT tools hang and fail often, so a slow or crashing collector must not sink the run.
Each collector runs in a thread; failures and timeouts are dropped. Results are deduped.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    on_collector: Callable[..., None] | None = None,
) -> list[Observation]:
    """Gather observations from all collectors; drop any that error or exceed timeout_s.

    `on_collector(event, name, count)` fires "start" before each collector runs and
    "done"/"fail"/"timeout" as each finishes — lets the caller drive a verbose progress
    UI that shows which tool is currently running.
    """
    if not collectors:
        return []
    on_collector = on_collector or (lambda *a, **k: None)
    results: list[Observation] = []
    with ThreadPoolExecutor(max_workers=len(collectors)) as ex:
        fut_map = {ex.submit(c.collect, target_id, seed): c for c in collectors}
        for c in collectors:
            on_collector("start", c.name)
        try:
            for fut in as_completed(fut_map, timeout=timeout_s):
                c = fut_map[fut]
                try:
                    obs = fut.result()
                    results.extend(obs)
                    on_collector("done", c.name, len(obs))
                except Exception:  # collector error -> skip this collector
                    on_collector("fail", c.name)
        except TimeoutError:  # remaining collectors still running -> drop them
            for fut, c in fut_map.items():
                if not fut.done():
                    on_collector("timeout", c.name)
    return _dedupe(results)
