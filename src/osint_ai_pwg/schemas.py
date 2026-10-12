"""Core data schemas shared across all four layers.

Frozen early per ROADMAP.md section 5. All PII lives in gitignored data/ at runtime;
nothing here carries real values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class FieldGroup(str, Enum):
    """PII taxonomy groups. Also define the C4a-C4d ablation split (revised design).

    Revised 2026-10: email moved Contact -> Identity; Contact is phone only.
    Nine canonical fields: name, username, email (Identity); birth_year, birth_month,
    birth_day (Temporal); city, country (Location); phone (Contact).
    """

    IDENTITY = "Identity"   # name, username, email
    TEMPORAL = "Temporal"   # birth_year, birth_month, birth_day
    LOCATION = "Location"   # city, country
    CONTACT = "Contact"     # phone


class Directness(str, Enum):
    """How explicitly a value was observed (revised design: 4 levels, scored in confidence.py).

    explicit 1.0 (STATED) / strongly-implied 0.7 / weakly-implied 0.4 / inferred 0.2.
    """

    STATED = "stated"                       # explicit: directly present at source (1.0)
    STRONGLY_IMPLIED = "strongly_implied"   # strong pattern (0.7)
    WEAKLY_IMPLIED = "weakly_implied"       # weak pattern (0.4)
    INFERRED = "inferred"                   # derived / guessed (0.2)


class FootprintTier(str, Enum):
    """RQ1 independent variable: how much recoverable PII a target exposes."""

    RICH = "rich"
    MODERATE = "moderate"
    SPARSE = "sparse"


class ConfidenceTier(str, Enum):
    """Per-field / per-profile confidence band (revised design: drives condition C5).

    High >= 0.70, Medium 0.40-0.69, Low < 0.40. Distinct from FootprintTier.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


def confidence_tier_of(value: float, high: float = 0.70, medium: float = 0.40) -> ConfidenceTier:
    """Bucket a confidence in [0, 1] into its tier (revised-design thresholds)."""
    if value >= high:
        return ConfidenceTier.HIGH
    if value >= medium:
        return ConfidenceTier.MEDIUM
    return ConfidenceTier.LOW


class Condition(str, Enum):
    """Experimental conditions (revised design 2026-10). Within-subjects: every target runs every one.

    9 primary conditions (13 incl. C4 sub-conditions). See Password_guess_test.pdf s2.3.3.
    """

    C0 = "C0"    # PassLLM empty prompt: no PII (inherent generation tendency)
    C0B = "C0b"  # raw base model, NO LoRA, + full OSINT PII (isolates LoRA contribution)
    C1 = "C1"    # trawling: no PII (lower-bound reference)
    C2 = "C2"    # full OSINT PII (9 fields) -- the OSINT condition (RQ1 + RQ2)
    C3 = "C3"    # ground-truth PII, full (upper bound, RQ2)
    C4A = "C4a"  # OSINT minus Identity group
    C4B = "C4b"  # OSINT minus Temporal group
    C4C = "C4c"  # OSINT minus Location group
    C4D = "C4d"  # OSINT minus Contact group
    C5 = "C5"    # OSINT, confidence-tier stratified (pipeline validation)
    C6 = "C6"    # Hashcat rule-based on C2 PII (non-LLM comparison)
    C7 = "C7"    # random pw matching gt length/charset (trivial sanity floor)


def utcnow_iso() -> str:
    """ISO-8601 UTC timestamp, e.g. '2026-01-01T00:00:00+00:00'."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Observation:
    """Layer 1 output: one raw fact about a target from one source."""

    target_id: str            # pseudonym, never a real identity
    field: str                # taxonomy field, e.g. "birthdate"
    group: FieldGroup
    value: str
    source: str               # e.g. "sherlock:twitter"
    directness: Directness = Directness.STATED
    collected_at: str = field(default_factory=utcnow_iso)


@dataclass
class ProfileField:
    """One normalized field with its confidence."""

    value: str
    confidence: float         # [0, 1]
    sources: int              # count of independent sources that concurred


@dataclass
class NormalizedProfile:
    """Layer 2 output / Layer 3 input."""

    target_id: str
    fields: dict[str, ProfileField] = field(default_factory=dict)
    footprint_tier: FootprintTier = FootprintTier.MODERATE


@dataclass
class GuessRun:
    """Layer 3 output / Layer 4 input: ranked guesses for one (target, condition)."""

    target_id: str
    condition: Condition
    config_hash: str
    guesses: list[str] = field(default_factory=list)
