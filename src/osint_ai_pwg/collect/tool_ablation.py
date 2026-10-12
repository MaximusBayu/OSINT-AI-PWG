"""Tool-level ablation: per-tool, per-field recovery matrix (revised design 2026-10).

During the first collection pass each tool is run ALONE on a few representative profiles
(one per footprint tier) with all other tools disabled. Its output is compared to the
target's ground truth to see which fields it recovers. The matrix shows which tools are
essential for which fields (e.g. Sherlock for username) and which contribute nothing — a
tool that recovers zero accurate PII across all fields is deprecated before the main run.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from osint_ai_pwg.collect.base import Collector


def tool_recovery_matrix(
    target_id: str,
    seed: dict[str, str],
    collectors: Sequence[Collector],
    ground_truth: dict[str, str],
) -> dict[str, dict[str, bool]]:
    """{tool_name: {field: recovered_correct_value?}} for one target.

    Each collector runs alone; a field is True if the tool returned the true value for it.
    """
    matrix: dict[str, dict[str, bool]] = {}
    for collector in collectors:
        by_field: dict[str, set[str]] = defaultdict(set)
        for o in collector.collect(target_id, seed):
            by_field[o.field].add(o.value)
        matrix[collector.name] = {
            field: true_value in by_field.get(field, set())
            for field, true_value in ground_truth.items()
        }
    return matrix


def deprecatable_tools(matrix: dict[str, dict[str, bool]]) -> list[str]:
    """Tools that recovered zero accurate fields across the sampled profiles — drop before the
    main run to reduce collection noise."""
    return [tool for tool, fields in matrix.items() if not any(fields.values())]
