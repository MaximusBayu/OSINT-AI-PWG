# OSINT-AI-PWG

Pilot pipeline for the thesis **"Improving LLM Password Guessing with OSINT-Derived
Personally Identifiable Information."** Measures how OSINT-sourced PII (noisy, incomplete)
affects LLM password-guessing performance versus ground-truth PII, under the Ur et al.
evaluation protocol.

> Research use only. Targets are self-consenting researchers + fully synthetic personas.
> See `docs/ethics-and-governance.md` (local) before collecting anything.

## What it does

Four-layer pipeline, one shared guessing engine, twelve experimental conditions
(revised 2026-10 design):

```
collect → normalize → prompt → PassLLM → assemble → evaluate → report
(Layer 1) (Layer 2)  (Layer 3, external engine)     (Layer 4)
```

| Condition | Meaning |
|-----------|---------|
| C0  | no-PII baseline (empty input) |
| C0b | full OSINT PII on base Qwen3-4B **without** the LoRA adapter (isolates the fine-tune) |
| C1  | no-PII trawling lower bound (common-password style) |
| C2  | **full OSINT PII** — the OSINT condition (drives RQ1 + RQ2) |
| C3  | full ground-truth PII — the upper-bound ceiling |
| C4a–C4d | C2 minus one field group each: Identity / Temporal / Location / Contact (ablation) |
| C5  | confidence-tier-stratified OSINT (validation) |
| C6  | Hashcat rule-based reference on C2 (no LLM) |
| C7  | random passwords matching ground-truth length/charset (sanity floor) |

Field groups: **Identity** = name, username, email · **Temporal** = birth year/month/day ·
**Location** = city, country · **Contact** = phone.

Research questions: **RQ1** does OSINT completeness affect accuracy (by footprint tier) ·
**RQ2** OSINT-vs-ground-truth gap, i.e. noise penalty Γ = CR(C3) − CR(C2) · **RQ3** which PII
groups matter most (the C4a–d ablations).

## Layout

```
src/osint_ai_pwg/
├── schemas.py          shared types: Observation, NormalizedProfile, GuessRun, enums
├── personas/           Phase 1: synthetic targets + tiers + password assignment
├── collect/            Layer 1: OSINT tool wrappers + orchestrator + region plugins
├── normalize/          Layer 2: merge + 3-signal confidence → NormalizedProfile
├── guess/              Layer 3 glue: prompt builder, JSONL, manifest, run assembly
├── evaluate/           Layer 4: crack rate, GNC, bootstrap CI, RQ deltas, report
└── pipeline.py         Phase 5: run the full condition matrix
config/                 regions.yaml (scraper plugins), experiment.yaml (model, budgets)
scripts/                setup_kali.sh (VPS), verify_checkpoint.py (Colab)
data/                   gitignored: personas, ground_truth, observations, runs
```

Engine: **Tzohar/PassLLM** (Qwen3-4B + LoRA), GPL-3.0 — cloned + run separately, never vendored.

## Setup

```bash
pip install -e '.[dev]'          # core + tests
pip install -e '.[analysis]'     # + matplotlib for GNC plots
# guess extra (torch/transformers/peft) installs on Colab, not locally
```

## Run

```bash
# tests (all offline logic)
pytest -q

# Phase 1: generate synthetic ground-truth targets (writes to gitignored data/)
python -m osint_ai_pwg.personas.generate -n 15 --out data/ground_truth

# OSINT collection host (Kali VPS)
bash scripts/setup_kali.sh

# guessing engine check (Colab / GPU)
python scripts/verify_checkpoint.py
```

### Web demo (research, synthetic targets only)

Single-target UI: pick a synthetic persona → watch it flow through collect → normalize →
guess → evaluate, with each condition's crack result shown. Runs **offline in demo mode**
(simulated OSINT recovery + a PII-pattern guesser standing in for PassLLM); swap in the real
orchestrator + PassLLM on VPS/Colab without touching the web layer.

```bash
pip install -e '.[web]'
python -m osint_ai_pwg.personas.generate -n 15 --out data/ground_truth   # roster
uvicorn osint_ai_pwg.web.app:app --reload                                # http://127.0.0.1:8000
```

Guardrail: the UI can only run targets already in your synthetic roster — no arbitrary-target
input, enforced server-side (`TargetNotAllowed`). It is not a "type a person → get password" tool.

Pipeline in code:

```python
from osint_ai_pwg.pipeline import run_matrix, make_passllm_engine
from osint_ai_pwg.evaluate.report import build_report, tiers_from_ground_truth
from osint_ai_pwg.evaluate.harness import passwords_from_ground_truth

engine = make_passllm_engine(weights_file)          # real run (Colab)
results = run_matrix(profiles, conditions, engine, config_hash)
report  = build_report(results, passwords, tiers, budgets=[100,1000,10000], primary_budget=100)
```

## Status

Every offline-testable layer is built and green (`pytest`): collection orchestration,
normalization, guessing glue, evaluation, pipeline driver, reporting. The whole flow runs
end-to-end in tests with an injectable fake engine.

General OSINT tools are wrapped (Sherlock, Holehe, theHarvester) and SpiderFoot is wired into
`build_collectors` (pass `spiderfoot_url=`). Remaining work needs real environments (not offline code):
- **VPS:** implement the Western custom scrapers (`collect/scrapers/` linkedin/github — currently
  stubs returning `[]`); verify the theHarvester/SpiderFoot parsers against the hosted instances;
  collect against planted footprints.
- **Colab:** implement `guess/runner.py::parse_output` against real PassLLM stdout; confirm the
  `--no-lora` flag for C0b; run the matrix.
- **Manual:** plant persona footprints (`docs/phase1-persona-protocol.md`); run hashcat for C6.

## Known limitation

Earlier the PassLLM input schema had no slot for **Location** or **username**. The revised design
feeds all 9 fields (name, username, email, birth y/m/d, phone, city, country) via the Qwen3 chat
template, so that blind spot should be gone — **to confirm on the first real Colab run** before
relying on the C4c (Location) ablation.

## Guides (local, untracked)

`ROADMAP.md` — full build plan, per-phase status, decisions, risks.
`docs/` — ethics & governance, Phase 1 persona protocol.
