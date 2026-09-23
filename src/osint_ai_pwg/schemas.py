"""Core data schemas shared across all four layers.

Frozen early per ROADMAP.md section 5. All PII lives in gitignored data/ at runtime;
nothing here carries real values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class FieldGroup(str, Enum):
    """PII taxonomy groups. Also define the C3-C5 ablation split."""

    IDENTITY = "Identity"   # name, username
    TEMPORAL = "Temporal"   # birthdate
    LOCATION = "Location"
    CONTACT = "Contact"     # email, phone


class Directness(str, Enum):
    STATED = "stated"       # explicitly present at source
    INFERRED = "inferred"   # derived / guessed


class FootprintTier(str, Enum):
    """RQ1 independent variable: how much recoverable PII a target exposes."""

    RICH = "rich"
    MODERATE = "moderate"
    SPARSE = "sparse"


class Condition(str, Enum):
    """Experimental conditions (ROADMAP section 1). Within-subjects: every target runs every one."""

    C0 = "C0"  # no-PII baseline (empty prompt / trawling)
    C1 = "C1"  # OSINT PII, full
    C2 = "C2"  # ground-truth PII, full
    C3 = "C3"  # OSINT minus Identity
    C4 = "C4"  # OSINT minus Temporal
    C5 = "C5"  # OSINT minus Location/Contact
    C6 = "C6"  # Hashcat rule-based comparison (no LLM)


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
