"""FastAPI app for the research demo. Run:  uvicorn osint_ai_pwg.web.app:app --reload

Needs the 'web' extra (fastapi, uvicorn) and a synthetic roster in data/ground_truth.
Endpoints are read-only + roster-locked; there is no arbitrary-target input.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from osint_ai_pwg.web.jobs import JobStore
from osint_ai_pwg.web.passllm_results import load_results, save_results
from osint_ai_pwg.web.service import (
    ConsentRequired,
    TargetNotAllowed,
    create_self_target,
    list_targets,
    load_roster,
    run_demo,
    run_real,
)

_GT_DIR = Path(os.environ.get("GROUND_TRUTH_DIR", "data/ground_truth"))
_STATIC = Path(__file__).parent / "static"
_MODE = os.environ.get("OSINT_MODE", "demo").lower()          # demo | real
_SPIDERFOOT_URL = os.environ.get("SPIDERFOOT_URL", "").rstrip("/")
_THEHARVESTER_URL = os.environ.get("THEHARVESTER_URL", "").rstrip("/")
_PASSLLM_DIR = Path(os.environ.get("PASSLLM_DIR", "data/passllm"))

app = FastAPI(title="OSINT-AI-PWG demo (research, synthetic targets only)")
_jobs = JobStore()


def _roster():
    if not _GT_DIR.exists():
        return {}
    return load_roster(_GT_DIR)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (_STATIC / "index.html").read_text(encoding="utf-8")


@app.get("/api/targets")
def targets() -> dict:
    return {"targets": list_targets(_roster()), "demo_mode": True}


@app.post("/api/run")
def run(payload: dict) -> dict:
    target_id = str(payload.get("target_id", ""))
    try:
        real = load_results(_PASSLLM_DIR, target_id)
        return run_demo(target_id, _roster(), real_guesses=(real or {}).get("conditions"))
    except TargetNotAllowed as e:
        raise HTTPException(status_code=403, detail=str(e)) from e


@app.post("/api/self-target")
def add_self_target(payload: dict) -> dict:
    _GT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        return create_self_target(payload, _GT_DIR)
    except ConsentRequired as e:
        raise HTTPException(status_code=403, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.get("/api/config")
def config() -> dict:
    """Tells the UI which mode is active and whether real OSINT is available."""
    return {"mode": _MODE, "real_available": _MODE == "real" and bool(_SPIDERFOOT_URL)}


@app.post("/api/collect")
def collect(payload: dict) -> dict:
    """Start a REAL SpiderFoot-backed run as a background job (roster-locked)."""
    target_id = str(payload.get("target_id", ""))
    roster = _roster()
    if target_id not in roster:
        raise HTTPException(status_code=403, detail=f"{target_id!r} is not in the roster")
    if _MODE != "real" or not _SPIDERFOOT_URL:
        raise HTTPException(status_code=400, detail="real mode not enabled (set OSINT_MODE=real + SPIDERFOOT_URL)")

    def body(progress):
        real = load_results(_PASSLLM_DIR, target_id)
        return run_real(target_id, roster, _SPIDERFOOT_URL, progress=progress,
                        theharvester_url=_THEHARVESTER_URL,
                        real_guesses=(real or {}).get("conditions"))

    return {"job_id": _jobs.start(body)}


@app.post("/api/passllm/import")
def import_passllm(payload: dict) -> dict:
    """Import real PassLLM results (computed on Colab) for a roster target.

    Body: {"target_id": "...", "conditions": {"C2": [{"password": "...", "confidence": 0.8}, ...]}}
    """
    target_id = str(payload.get("target_id", ""))
    if target_id not in _roster():
        raise HTTPException(status_code=403, detail=f"{target_id!r} is not in the roster")
    conditions = payload.get("conditions")
    if not isinstance(conditions, dict):
        raise HTTPException(status_code=400, detail="conditions must be a dict of cond -> [guesses]")
    norm: dict[str, list[dict]] = {}
    for cond, glist in conditions.items():
        if not isinstance(glist, list):
            raise HTTPException(status_code=400, detail=f"conditions[{cond!r}] must be a list")
        cleaned: list[dict] = []
        for g in glist:
            if isinstance(g, str):
                cleaned.append({"password": g, "confidence": None})
            elif isinstance(g, dict) and g.get("password"):
                cleaned.append({"password": str(g["password"]), "confidence": g.get("confidence")})
            else:
                raise HTTPException(status_code=400, detail=f"conditions[{cond!r}] has an invalid guess")
        norm[cond] = cleaned
    save_results(_PASSLLM_DIR, target_id, {"target_id": target_id, "engine": "passllm", "conditions": norm})
    return {"ok": True, "target_id": target_id, "conditions": len(norm)}


@app.get("/api/passllm/{target_id}")
def get_passllm(target_id: str) -> dict:
    r = load_results(_PASSLLM_DIR, target_id)
    if r is None:
        raise HTTPException(status_code=404, detail="no PassLLM results for this target")
    return r


@app.get("/api/job/{job_id}")
def job(job_id: str) -> dict:
    j = _jobs.get(job_id)
    if j is None:
        raise HTTPException(status_code=404, detail="unknown job")
    return j
