"""Source reliability grades (Admiralty A-F) per OSINT tool.

One input to the 3-signal confidence model. Grades are defaults calibrated in Phase 2b;
account-existence tools (sherlock, holehe) are graded higher than broad aggregators.
"""

from __future__ import annotations

# tool prefix (before ':' in a source tag) -> Admiralty reliability grade
SOURCE_GRADE: dict[str, str] = {
    "sherlock": "B",
    "holehe": "B",
    "theharvester": "C",
    "spiderfoot": "C",
    "tokopedia": "C",
    "bukalapak": "C",
}
DEFAULT_GRADE = "D"


def grade_for(source: str) -> str:
    """Reliability grade for a source tag like 'sherlock:github'."""
    tool = source.split(":", 1)[0].strip().lower()
    return SOURCE_GRADE.get(tool, DEFAULT_GRADE)
