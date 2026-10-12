"""OSINT collection-quality + stability metrics (revised design 2026-10).

Evaluates Layer-1/2 output against known ground truth:
  - per-field Precision / Recall / F1 (how accurate + complete OSINT recovery is)
  - per-field Jaccard stability J_f across two collection runs (48h apart, different IP)

These feed the RQ2 noise characterisation and provide a direct validity check on the
collection layer. Operate on Observations (gitignored data at runtime) + a flat ground-truth
PII dict {field: value}; nothing here persists PII.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from osint_ai_pwg.evaluate.metrics import jaccard, precision_recall_f1
from osint_ai_pwg.schemas import Observation


def _values_by_field(observations: Sequence[Observation]) -> dict[str, set[str]]:
    by_field: dict[str, set[str]] = defaultdict(set)
    for o in observations:
        by_field[o.field].add(o.value)
    return by_field


def field_quality(
    observations: Sequence[Observation], ground_truth: dict[str, str]
) -> dict[str, dict[str, float]]:
    """Per-field Precision/Recall/F1 of OSINT recovery vs the target's ground-truth PII.

    For field f: collected = distinct values OSINT returned; correct = 1 if the true value
    is among them, else 0; ground_truth present = 1 (the field exists in the record).
    Low precision -> substitution/hallucination noise; low recall -> omission noise.
    """
    collected = _values_by_field(observations)
    out: dict[str, dict[str, float]] = {}
    for field, true_value in ground_truth.items():
        vals = collected.get(field, set())
        correct = 1 if true_value in vals else 0
        out[field] = precision_recall_f1(correct=correct, collected=len(vals), ground_truth=1)
    return out


def field_stability(
    observations_run1: Sequence[Observation], observations_run2: Sequence[Observation]
) -> dict[str, float]:
    """Per-field Jaccard J_f between two collection runs (stable >= 0.80)."""
    a = _values_by_field(observations_run1)
    b = _values_by_field(observations_run2)
    return {f: jaccard(a.get(f, set()), b.get(f, set())) for f in set(a) | set(b)}
