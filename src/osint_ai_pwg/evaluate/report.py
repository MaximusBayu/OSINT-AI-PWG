"""Build the pilot results report from run results (Phase 6).

Produces a JSON-serializable dict answering RQ1-RQ3, plus an optional GNC plot.
Descriptive only — no hypothesis testing (pilot scope).
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from osint_ai_pwg.evaluate.harness import (
    ablation_delta,
    bootstrap_ci,
    condition_crack_rate,
    guess_number_curve,
    paired_delta,
)
from osint_ai_pwg.schemas import Condition, FootprintTier, GuessRun

# Which group each ablation condition removes (RQ3 labels).
_ABLATION_LABEL = {
    Condition.C3: "Identity",
    Condition.C4: "Temporal",
    Condition.C5: "Location+Contact",
}


def tiers_from_ground_truth(gts) -> dict[str, FootprintTier]:
    return {gt.target_id: gt.footprint_tier for gt in gts}


def crack_rate_by_tier(
    runs: list[GuessRun], passwords: dict[str, str], tiers: dict[str, FootprintTier], budget: int
) -> dict[str, float]:
    """RQ1: crack rate grouped by the target's planted footprint tier."""
    buckets: dict[str, list[GuessRun]] = defaultdict(list)
    for r in runs:
        tier = tiers.get(r.target_id)
        if tier is not None:
            buckets[tier.value].append(r)
    return {tier: condition_crack_rate(rs, passwords, budget) for tier, rs in buckets.items()}


def build_report(
    results: dict[Condition, list[GuessRun]],
    passwords: dict[str, str],
    tiers: dict[str, FootprintTier],
    budgets: list[int],
    primary_budget: int,
) -> dict:
    """Assemble the descriptive results report (JSON-serializable)."""
    report: dict = {"primary_budget": primary_budget, "conditions": {}}

    for cond, runs in results.items():
        report["conditions"][cond.value] = {
            "crack_rate": {str(b): condition_crack_rate(runs, passwords, b) for b in budgets},
            "gnc": [[b, r] for b, r in guess_number_curve(runs, passwords, budgets)],
            "ci95": list(bootstrap_ci(runs, passwords, primary_budget)),
        }

    if Condition.C1 in results:
        report["rq1_by_tier"] = crack_rate_by_tier(
            results[Condition.C1], passwords, tiers, primary_budget
        )

    if Condition.C1 in results and Condition.C2 in results:
        report["rq2_noise_penalty"] = paired_delta(
            results[Condition.C1], results[Condition.C2], passwords, primary_budget
        )

    rq3: dict[str, float] = {}
    for cond, label in _ABLATION_LABEL.items():
        if cond in results and Condition.C1 in results:
            rq3[label] = ablation_delta(
                results[Condition.C1], results[cond], passwords, primary_budget
            )
    report["rq3_group_delta"] = rq3
    return report


def save_report(report: dict, path: Path) -> Path:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return Path(path)


def plot_gnc(report: dict, path: Path) -> Path:
    """Plot Guess Number Curves per condition (log-x). Requires the 'analysis' extra."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("plot_gnc needs matplotlib: pip install -e '.[analysis]'") from e

    fig, ax = plt.subplots()
    for cond, data in report["conditions"].items():
        xs = [b for b, _ in data["gnc"]]
        ys = [r for _, r in data["gnc"]]
        ax.plot(xs, ys, marker="o", label=cond)
    ax.set_xscale("log")
    ax.set_xlabel("guesses")
    ax.set_ylabel("crack rate")
    ax.set_title("Guess Number Curves")
    ax.legend()
    fig.savefig(path, dpi=120, bbox_inches="tight")
    plt.close(fig)
    return Path(path)
