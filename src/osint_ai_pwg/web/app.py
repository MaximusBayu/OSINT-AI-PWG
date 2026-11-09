"""FastAPI app for the research demo. Run:  uvicorn osint_ai_pwg.web.app:app --reload

Needs the 'web' extra (fastapi, uvicorn) and a synthetic roster in data/ground_truth.
Endpoints are read-only + roster-locked; there is no arbitrary-target input.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from osint_ai_pwg.visualize.entity_graph import (
    build_payload,
    load_ground_truth,
    load_observations,
    render_html,
)
from osint_ai_pwg.guess.prompt import build_passllm_object
from osint_ai_pwg.normalize.normalize import normalize
from osint_ai_pwg.schemas import Condition
from osint_ai_pwg.web.jobs import JobStore
from osint_ai_pwg.web.passllm_results import load_results, save_results
from osint_ai_pwg.web.runs import load_run, save_run
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
_OBS_DIR = Path(os.environ.get("OBSERVATIONS_DIR", "data/observations"))
_RUNS_DIR = Path(os.environ.get("RUNS_DIR", "data/runs"))
_PASSLLM_SERVICE = os.environ.get("PASSLLM_URL", "").rstrip("/")
_PASSLLM_SERVICE_TOKEN = os.environ.get("PASSLLM_TOKEN", "")

app = FastAPI(title="OSINT-AI-PWG demo (research, synthetic targets only)")
_jobs = JobStore()


def _roster():
    if not _GT_DIR.exists():
        return {}
    return load_roster(_GT_DIR)


def _service_call(path: str, payload: dict | None = None, timeout: int = 600) -> dict:
    """Call the GPU-side PassLLM service, forwarding the bearer token."""
    if not _PASSLLM_SERVICE:
        raise HTTPException(status_code=503,
                            detail="PassLLM GPU service not configured (set PASSLLM_URL)")
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if _PASSLLM_SERVICE_TOKEN:
        headers["Authorization"] = f"Bearer {_PASSLLM_SERVICE_TOKEN}"
    req = urllib.request.Request(
        f"{_PASSLLM_SERVICE}{path}",
        data=body,
        method="POST" if body is not None else "GET",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (operator-set URL)
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise HTTPException(status_code=e.code, detail=e.read().decode()[:300]) from e
    except Exception as e:
        raise HTTPException(status_code=502,
                            detail=f"PassLLM service unreachable: {e}") from e


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
        result = run_demo(target_id, _roster(), real_guesses=(real or {}).get("conditions"))
    except TargetNotAllowed as e:
        raise HTTPException(status_code=403, detail=str(e)) from e
    save_run(_RUNS_DIR, target_id, result)
    return result


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
    return {
        "mode": _MODE,
        "real_available": _MODE == "real" and bool(_SPIDERFOOT_URL),
        "passllm_live": bool(_PASSLLM_SERVICE),
    }


@app.get("/targets/{target_id}/graph", response_class=HTMLResponse)
def target_graph(target_id: str, view: str = "provenance") -> str:
    """Dark interactive entity graph for one roster target (person -> PII -> source)."""
    if target_id not in _roster():
        raise HTTPException(status_code=403, detail=f"{target_id!r} is not in the roster")
    if view not in ("entities", "provenance"):
        raise HTTPException(status_code=400, detail="view must be 'entities' or 'provenance'")
    obs = load_observations(_OBS_DIR, target_id)
    gt = load_ground_truth(_GT_DIR, target_id)
    payload = build_payload(obs, target_id, ground_truth=gt, view=view)
    return render_html(payload, f"Entity graph — {payload['label']}")


@app.get("/api/targets/{target_id}/graph")
def target_graph_json(target_id: str, view: str = "provenance") -> dict:
    """Graph payload ({nodes, links}) for a roster target.

    view=entities (person + PII) or view=provenance (adds source nodes).
    """
    if target_id not in _roster():
        raise HTTPException(status_code=403, detail=f"{target_id!r} is not in the roster")
    if view not in ("entities", "provenance"):
        raise HTTPException(status_code=400, detail="view must be 'entities' or 'provenance'")
    obs = load_observations(_OBS_DIR, target_id)
    gt = load_ground_truth(_GT_DIR, target_id)
    return build_payload(obs, target_id, ground_truth=gt, view=view)


@app.get("/api/runs/{target_id}")
def last_run(target_id: str) -> dict:
    """Return the last saved run for a roster target (revisit a searched profile)."""
    if target_id not in _roster():
        raise HTTPException(status_code=403, detail=f"{target_id!r} is not in the roster")
    result = load_run(_RUNS_DIR, target_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"no saved run for {target_id!r}")
    return result


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
        result = run_real(target_id, roster, _SPIDERFOOT_URL, progress=progress,
                          theharvester_url=_THEHARVESTER_URL,
                          real_guesses=(real or {}).get("conditions"),
                          obs_dir=_OBS_DIR)
        save_run(_RUNS_DIR, target_id, result)
        return result

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


@app.get("/api/passllm/status")
def passllm_status() -> dict:
    """Health of the GPU-side PassLLM service."""
    return _service_call("/health", timeout=10)


@app.get("/api/passllm/{target_id}")
def get_passllm(target_id: str) -> dict:
    r = load_results(_PASSLLM_DIR, target_id)
    if r is None:
        raise HTTPException(status_code=404, detail="no PassLLM results for this target")
    return r


@app.post("/api/passllm/guess")
def passllm_guess(payload: dict) -> dict:
    """Run live PassLLM inference on the GPU service for a roster target.

    Profile is the C2 (OSINT-derived) object built from that target's persisted
    observations — same input the offline matrix uses, so numbers stay comparable.
    """
    target_id = str(payload.get("target_id", ""))
    roster = _roster()
    if target_id not in roster:
        raise HTTPException(status_code=403, detail=f"{target_id!r} is not in the roster")

    mode = str(payload.get("mode", "fast"))
    if mode not in ("superfast", "fast", "standard", "deep"):
        raise HTTPException(status_code=400,
                            detail="mode must be superfast, fast, standard or deep")

    gt = roster[target_id]
    obs = load_observations(_OBS_DIR, target_id)
    osint = normalize(obs, gt.footprint_tier)
    profile = build_passllm_object(osint, Condition.C2)

    result = _service_call("/guess", {
        "profile": profile,
        "mode": mode,
        "runs": payload.get("runs"),
    })

    saved = load_run(_RUNS_DIR, target_id) or {"target_id": target_id}
    saved["passllm_live"] = {
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "profile": profile,
        "guesses": result.get("guesses", []),
    }
    save_run(_RUNS_DIR, target_id, saved)
    return {"target_id": target_id, "profile": profile, **result}


@app.get("/api/job/{job_id}")
def job(job_id: str) -> dict:
    j = _jobs.get(job_id)
    if j is None:
        raise HTTPException(status_code=404, detail="unknown job")
    return j
