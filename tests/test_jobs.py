"""JobStore tests."""

from __future__ import annotations

import time

from osint_ai_pwg.web.jobs import JobStore


def _wait(store: JobStore, job_id: str, timeout: float = 3.0) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        j = store.get(job_id)
        if j and j["status"] in ("done", "error"):
            return j
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def test_job_success_carries_result() -> None:
    store = JobStore()
    jid = store.start(lambda progress: (progress(50, "half"), {"ok": True})[1])
    done = _wait(store, jid)
    assert done["status"] == "done" and done["result"] == {"ok": True} and done["progress"] == 100


def test_job_error_is_captured() -> None:
    store = JobStore()

    def boom(progress):
        raise RuntimeError("nope")

    done = _wait(store, store.start(boom))
    assert done["status"] == "error" and "nope" in done["error"]


def test_unknown_job_is_none() -> None:
    assert JobStore().get("missing") is None
