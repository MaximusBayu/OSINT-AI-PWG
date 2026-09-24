# OSINT-AI-PWG

Pilot pipeline for the thesis **"Improving LLM Password Guessing with OSINT-Derived
Personally Identifiable Information."** Measures how OSINT-sourced PII (noisy, incomplete)
affects LLM password-guessing performance versus ground-truth PII, under the Ur et al.
evaluation protocol.

> Research use only. Targets are self-consenting researchers + fully synthetic personas.
> See `docs/ethics-and-governance.md` (local) before collecting anything.

## What it does

Four-layer pipeline, one shared guessing engine, seven experimental conditions:

```
collect → normalize → prompt → PassLLM → assemble → evaluate → report
(Layer 1) (Layer 2)  (Layer 3, external engine)     (Layer 4)
```

| Condition | Meaning |
|-----------|---------|
| C0 | no-PII baseline (trawling) |
| C1 | OSINT PII (full) |
| C2 | ground-truth PII (full) |
| C3–C5 | C1 minus a field group (ablation) |
| C6 | Hashcat rule-based reference (no LLM) |

Research questions: **RQ1** does OSINT completeness affect accuracy · **RQ2** OSINT-vs-ground-truth
gap (noise penalty) · **RQ3** which PII groups matter most.

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

Remaining work needs real environments (not offline code):
- **VPS:** finish theHarvester/SpiderFoot parsers + Tokopedia/Bukalapak scraping; collect against planted footprints.
- **Colab:** implement `guess/runner.py::parse_output` against real PassLLM stdout; run the matrix.
- **Manual:** plant persona footprints (`docs/phase1-persona-protocol.md`); run hashcat for C6.

## Known limitation

PassLLM's input schema has no slot for **Location** or **username**, so those fields never
reach the engine: RQ3 cannot measure Location's contribution, and C5 reduces to removing
Contact. Recorded as a thesis limitation.

## Guides (local, untracked)

`ROADMAP.md` — full build plan, per-phase status, decisions, risks.
`docs/` — ethics & governance, Phase 1 persona protocol.
