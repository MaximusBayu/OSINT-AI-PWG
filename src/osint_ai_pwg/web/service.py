"""Demo service: run one synthetic target through the whole pipeline, step by step.

Research guardrail: `target_id` MUST be in the provided synthetic roster, else it is
refused. There is no path to run against an arbitrary/real person.
"""

from __future__ import annotations

from pathlib import Path

from osint_ai_pwg.collect.orchestrator import collect_target
from osint_ai_pwg.collect.registry import build_collectors
from osint_ai_pwg.collect.seed import derive_seed
from osint_ai_pwg.collect.store import save_observations
from osint_ai_pwg.collect.verify import verify_observations
from osint_ai_pwg.evaluate.metrics import guess_number
from osint_ai_pwg.guess.prompt import build_passllm_object
from osint_ai_pwg.normalize.normalize import normalize
from osint_ai_pwg.normalize.summary import confidence_tier, profile_summary
from osint_ai_pwg.personas.schema import GroundTruth, validate
from osint_ai_pwg.personas.self_target import build_self_target
from osint_ai_pwg.web.demo import DemoCollector, DemoEngine
from osint_ai_pwg.schemas import Condition, NormalizedProfile, Observation, ProfileField

# Demo subset (revised design). Engine-only conditions (C0b base-no-LoRA, C5 tier-strat,
# C6 Hashcat, C7 random) are out of the demo's scope.
_CONDITIONS = [
    Condition.C0, Condition.C1, Condition.C2, Condition.C3,
    Condition.C4A, Condition.C4B, Condition.C4C, Condition.C4D,
]
_TOP_N = 8          # how many guesses to surface in the UI
_BUDGET = 1000      # crack budget for the demo


class TargetNotAllowed(Exception):
    """Raised when a target_id is not in the synthetic roster."""


class ConsentRequired(Exception):
    """Raised when a self-target is submitted without explicit consent."""


def create_self_target(payload: dict, out_dir: Path) -> dict:
    """Create a consenting self-target record from a UI form. Consent is mandatory.

    Guardrail: this is for yourself / a consenting person only. The password is stored in a
    local gitignored file — use a throwaway, not a real credential.
    """
    if not payload.get("consent"):
        raise ConsentRequired("consent is required: confirm this is you or a consenting person")
    password = str(payload.get("password", "")).strip()
    if not password:
        raise ValueError("a (throwaway) password is required")

    platforms = payload.get("platforms") or None
    if isinstance(platforms, str):
        platforms = [p.strip() for p in platforms.replace(",", " ").split() if p.strip()]

    gt = build_self_target(
        target_id=str(payload.get("id") or "self01").strip(),
        password=password,
        name=payload.get("name") or None,
        username=payload.get("username") or None,
        email=payload.get("email") or None,
        birthdate=payload.get("birthdate") or None,
        city=payload.get("city") or None,
        phone=payload.get("phone") or None,
        platforms=platforms,
    )
    problems = validate(gt)
    if problems:
        raise ValueError(f"invalid record: {problems}")
    gt.save(out_dir)
    return {
        "target_id": gt.target_id,
        "tier": gt.footprint_tier.value,
        "password_kind": gt.password_kind.value,
    }


def load_roster(ground_truth_dir: Path) -> dict[str, GroundTruth]:
    roster: dict[str, GroundTruth] = {}
    for p in sorted(Path(ground_truth_dir).glob("*.json")):
        gt = GroundTruth.load(p)
        roster[gt.target_id] = gt
    return roster


def _gt_profile(gt: GroundTruth) -> NormalizedProfile:
    """Full ground-truth PII as a profile (confidence 1.0) — the C3 input (revised design)."""
    fields = {
        f: ProfileField(v, 1.0, 99)
        for group in gt.pii.values() for f, v in group.items()
    }
    return NormalizedProfile(gt.target_id, fields, gt.footprint_tier)


def _export_entry(gt: GroundTruth, osint: NormalizedProfile, gt_prof: NormalizedProfile) -> dict:
    """targets.json entry for run_matrix.py: OSINT + GT profiles in PassLLM key form."""
    return {
        "target_id": gt.target_id,
        "osint_profile": build_passllm_object(osint, Condition.C2),
        "gt_profile": build_passllm_object(gt_prof, Condition.C2),
        "password": gt.password,
    }


def _obj_for(cond: Condition, osint: NormalizedProfile, gt_prof: NormalizedProfile) -> dict[str, str]:
    # Revised design: C0/C1 send no PII; C3 is full ground truth; C2 + C4a-d come from OSINT.
    if cond in (Condition.C0, Condition.C1):
        return {}
    if cond is Condition.C3:
        return build_passllm_object(gt_prof, Condition.C2)   # full GT, no ablation (C2 = full sentinel)
    return build_passllm_object(osint, cond)                 # C2 full OSINT, or C4a-d ablations


def _assemble_result(
    gt: GroundTruth, seed: dict[str, str], observations: list[Observation], engine, mode: str,
    real_guesses: dict[str, list[dict]] | None = None,
) -> dict:
    """Normalize -> guess every condition -> evaluate. Shared by demo and real modes.

    `real_guesses` maps a condition (e.g. "C2") to PassLLM's ranked output
    `[{"password", "confidence", "log_score"}]`, imported from Colab. When present for a
    condition, the real guesses are used for the crack verdict instead of the demo engine.
    """
    osint_profile = normalize(observations, gt.footprint_tier)
    gt_profile = _gt_profile(gt)
    real = real_guesses or {}

    conditions_out = []
    for cond in _CONDITIONS:
        obj = _obj_for(cond, osint_profile, gt_profile)
        key = cond.value
        if key in real:
            glist = real[key]
            guesses = [g["password"] for g in glist]
            top = [{"password": g["password"], "confidence": g.get("confidence")} for g in glist[:_TOP_N]]
            eng = "passllm"
        else:
            guesses = engine.guesses(obj)
            top = [{"password": g, "confidence": None} for g in guesses[:_TOP_N]]
            eng = "demo"
        gn = guess_number(guesses, gt.password)
        cracked = gn is not None and gn <= _BUDGET
        conditions_out.append({
            "condition": cond.value,
            "engine": eng,
            "pii_sent": obj,
            "top_guesses": top,
            "cracked": cracked,
            "guess_number": gn if cracked else None,
        })

    return {
        "target_id": gt.target_id,
        "footprint_tier": gt.footprint_tier.value,
        "mode": mode,
        "guess_engine": "passllm" if real else "demo",
        "seed": seed,
        "observations": [
            {"field": o.field, "value": o.value, "source": o.source, "url": o.url} for o in observations
        ],
        "profile": {
            f: {
                "value": pf.value,
                "confidence": round(pf.confidence, 3),
                "sources": pf.sources,
                "tier": confidence_tier(pf.confidence),
            }
            for f, pf in osint_profile.fields.items()
        },
        "profile_summary": profile_summary(osint_profile),
        "budget": _BUDGET,
        "conditions": conditions_out,
        "export": _export_entry(gt, osint_profile, gt_profile),
    }


def run_demo(
    target_id: str,
    roster: dict[str, GroundTruth],
    collector: DemoCollector | None = None,
    engine: DemoEngine | None = None,
    real_guesses: dict[str, list[dict]] | None = None,
) -> dict:
    """Demo mode: simulated OSINT recovery from the planted ground truth."""
    gt = roster.get(target_id)
    if gt is None:
        raise TargetNotAllowed(f"{target_id!r} is not in the synthetic roster")
    collector = collector or DemoCollector(roster)
    engine = engine or DemoEngine()
    seed = derive_seed(gt)
    observations = collector.collect(target_id, seed)
    return _assemble_result(gt, seed, observations, engine, mode="demo", real_guesses=real_guesses)


def run_real(
    target_id: str,
    roster: dict[str, GroundTruth],
    spiderfoot_url: str,
    engine: DemoEngine | None = None,
    progress=None,
    theharvester_url: str | None = None,
    collectors: list | None = None,
    real_guesses: dict[str, list[dict]] | None = None,
    obs_dir: Path | None = None,
    verify_links: bool = True,
) -> dict:
    """Real mode: live OSINT from all wired tools, then normalize -> guess -> evaluate.

    Roster-locked (consenting self-targets only). Collection runs sherlock, holehe,
    maigret, theharvester, and SpiderFoot in parallel (deduped), so it takes minutes and
    must run inside a background job. Guessing still uses the demo engine — real PassLLM
    is a separate GPU stage. `progress(pct, msg)` is called for the job UI. `collectors`
    is injectable for tests.
    """
    gt = roster.get(target_id)
    if gt is None:
        raise TargetNotAllowed(f"{target_id!r} is not in the synthetic roster")
    if not spiderfoot_url:
        raise ValueError("SPIDERFOOT_URL is not configured")
    progress = progress or (lambda pct, msg: None)
    engine = engine or DemoEngine()

    seed = derive_seed(gt)
    progress(5, "collect — starting (all tools in parallel)")
    if collectors is None:
        collectors = build_collectors(
            spiderfoot_url=spiderfoot_url,
            theharvester_url=theharvester_url or None,
        )

    total = max(1, len(collectors))
    state = {"done": 0}

    def on_collector(event: str, name: str, count: int = 0) -> None:
        if event == "start":
            progress(10, f"collect — {name} running…")
        elif event == "done":
            state["done"] += 1
            pct = 10 + int(65 * state["done"] / total)
            progress(pct, f"collect — {name} done ({count} hits)")
        elif event == "fail":
            state["done"] += 1
            pct = 10 + int(65 * state["done"] / total)
            progress(pct, f"collect — {name} failed")
        elif event == "timeout":
            state["done"] += 1
            pct = 10 + int(65 * state["done"] / total)
            progress(pct, f"collect — {name} timed out")

    observations = collect_target(target_id, seed, collectors, timeout_s=120, on_collector=on_collector)
    if verify_links:
        progress(76, "verify — checking proof links")
        observations, dropped, _ = verify_observations(observations)
        progress(79, f"verify — {len(observations)} kept, {len(dropped)} dropped")
    if obs_dir is not None:
        save_observations(target_id, observations, Path(obs_dir))
    progress(80, "normalize — dedupe + confidence scoring")
    result = _assemble_result(gt, seed, observations, engine, mode="real", real_guesses=real_guesses)
    progress(98, "guess + evaluate — complete")
    return result


def list_targets(roster: dict[str, GroundTruth]) -> list[dict]:
    return [{"target_id": tid, "tier": gt.footprint_tier.value} for tid, gt in roster.items()]
