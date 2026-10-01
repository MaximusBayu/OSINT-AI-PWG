"""Tiny in-process job store for slow real-OSINT runs.

Real scans take minutes, so the web app starts a background thread and the client polls.
In-memory only (single process) — fine for a research demo; swap for a real queue if it
ever needs to scale or survive restarts.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable

# A job body receives a progress callback: progress(percent, message).
Progress = Callable[[int, str], None]
JobBody = Callable[[Progress], dict]


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    def _set(self, job_id: str, **kw) -> None:
        with self._lock:
            self._jobs.setdefault(job_id, {}).update(kw)

    def get(self, job_id: str) -> dict | None:
        with self._lock:
            j = self._jobs.get(job_id)
            return dict(j) if j is not None else None

    def start(self, body: JobBody) -> str:
        job_id = uuid.uuid4().hex[:12]
        self._set(job_id, status="running", progress=0, message="starting", result=None, error=None)

        def progress(pct: int, msg: str) -> None:
            self._set(job_id, progress=max(0, min(99, pct)), message=msg)

        def run() -> None:
            try:
                result = body(progress)
                self._set(job_id, status="done", progress=100, message="complete", result=result)
            except Exception as e:  # surface the failure to the poller
                self._set(job_id, status="error", message="failed", error=str(e))

        threading.Thread(target=run, daemon=True).start()
        return job_id
