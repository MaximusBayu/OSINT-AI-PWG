"""Phase 2a tests: tool parsers, orchestrator tolerance/dedupe, registry, store roundtrip."""

from __future__ import annotations

from pathlib import Path

from osint_ai_pwg.collect.base import Collector
from osint_ai_pwg.collect.orchestrator import collect_target
from osint_ai_pwg.collect.registry import build_collectors
from osint_ai_pwg.collect.seed import derive_seed
from osint_ai_pwg.collect.store import load_observations, save_observations
from osint_ai_pwg.collect.tools.holehe import HoleheCollector
from osint_ai_pwg.collect.tools.sherlock import SherlockCollector
from osint_ai_pwg.personas.schema import GroundTruth, PasswordKind
from osint_ai_pwg.schemas import FieldGroup, FootprintTier, Observation

SHERLOCK_OUT = """
[*] Checking username rina48 on:
[+] GitHub: https://github.com/rina48
[+] Twitter: https://twitter.com/rina48
[-] Reddit: not found
"""

HOLEHE_OUT = """
[+] twitter.com
[+] spotify.com
[-] amazon.com
"""


def _fixed_runner(output: str):
    return lambda cmd: output


def test_sherlock_parse() -> None:
    c = SherlockCollector(runner=_fixed_runner(SHERLOCK_OUT))
    obs = c.collect("t01", {"username": "rina48"})
    sources = {o.source for o in obs}
    assert sources == {"sherlock:github", "sherlock:twitter"}
    assert all(o.group is FieldGroup.IDENTITY and o.value == "rina48" for o in obs)


def test_holehe_parse() -> None:
    c = HoleheCollector(runner=_fixed_runner(HOLEHE_OUT))
    obs = c.collect("t01", {"email": "rina48@example.com"})
    assert {o.source for o in obs} == {"holehe:twitter.com", "holehe:spotify.com"}
    assert all(o.group is FieldGroup.IDENTITY for o in obs)   # email is Identity (revised)


THEHARVESTER_OUT = """
[*] Emails found:
----------------------
rina48@example.com
careers@example.com

[*] Hosts found:
----------------------
mail.example.com:10.0.0.1
"""


def test_theharvester_parse() -> None:
    from osint_ai_pwg.collect.tools.theharvester import TheHarvesterCollector

    c = TheHarvesterCollector(runner=_fixed_runner(THEHARVESTER_OUT))
    obs = c.collect("t01", {"email": "rina48@example.com"})
    values = {o.value for o in obs}
    assert values == {"rina48@example.com", "careers@example.com"}   # emails only, host dropped
    assert all(o.group is FieldGroup.IDENTITY and o.source == "theharvester:example.com" for o in obs)
    # no email in seed -> no command, nothing recovered
    assert TheHarvesterCollector(runner=_fixed_runner(THEHARVESTER_OUT)).collect("t01", {}) == []


def test_missing_seed_field_yields_nothing() -> None:
    # Sherlock needs a username; without one, no command, no observations.
    assert SherlockCollector(runner=_fixed_runner(SHERLOCK_OUT)).collect("t01", {}) == []


class _Boom(Collector):
    name = "boom"

    def collect(self, target_id: str, seed: dict[str, str]) -> list[Observation]:
        raise RuntimeError("tool crashed")


class _Ok(Collector):
    name = "ok"

    def collect(self, target_id: str, seed: dict[str, str]) -> list[Observation]:
        return [Observation(target_id, "name", FieldGroup.IDENTITY, "X", "ok:src")]


def test_orchestrator_tolerates_failure_and_dedupes() -> None:
    ok = _Ok()
    # two ok collectors return the same observation -> deduped to one; boom is dropped.
    out = collect_target("t01", {}, [ok, _Boom(), _Ok()], timeout_s=5)
    assert len(out) == 1
    assert out[0].source == "ok:src"


def test_registry_general_plus_region(tmp_path: Path) -> None:
    # Revised design: Western region custom scrapers (linkedin, github).
    cfg = tmp_path / "regions.yaml"
    cfg.write_text("regions:\n  western:\n    scrapers: [linkedin, github]\n", encoding="utf-8")
    names = {c.name for c in build_collectors(region="western", config_path=cfg)}
    assert {"sherlock", "holehe", "theharvester", "linkedin", "github"} <= names
    # no region -> general tools only (Sherlock, Holehe, theHarvester always run)
    assert {c.name for c in build_collectors(region=None, config_path=cfg)} == {
        "sherlock", "holehe", "theharvester"}
    # SpiderFoot is general too, but only wired in when a hosted instance URL is given.
    with_sf = {c.name for c in build_collectors(region=None, config_path=cfg,
                                                spiderfoot_url="http://sf.local")}
    assert "spiderfoot" in with_sf


def test_tool_recovery_matrix_and_deprecation() -> None:
    from osint_ai_pwg.collect.tool_ablation import deprecatable_tools, tool_recovery_matrix

    class _Fake:
        def __init__(self, name, obs):
            self.name = name
            self._obs = obs

        def collect(self, target_id, seed):
            return self._obs

    good = _Fake("sherlock", [Observation("t01", "username", FieldGroup.IDENTITY, "alex48", "sherlock:gh")])
    dud = _Fake("theharvester", [])                      # recovers nothing
    gt = {"username": "alex48", "email": "a@x.com"}
    matrix = tool_recovery_matrix("t01", {}, [good, dud], gt)
    assert matrix["sherlock"] == {"username": True, "email": False}
    assert matrix["theharvester"] == {"username": False, "email": False}
    assert deprecatable_tools(matrix) == ["theharvester"]


def test_seed_is_minimal() -> None:
    gt = GroundTruth(
        target_id="t01", footprint_tier=FootprintTier.MODERATE,
        pii={"Identity": {"name": "Rina P", "username": "rina48"},
             "Temporal": {"birthdate": "1995-06-01"},
             "Contact": {"email": "rina48@example.com"}},
        password="x", password_kind=PasswordKind.RANDOM,
    )
    seed = derive_seed(gt)
    assert seed == {"name": "Rina P", "username": "rina48", "email": "rina48@example.com"}
    assert "birthdate" not in seed  # birthdate must be RECOVERED, not seeded


def test_store_roundtrip(tmp_path: Path) -> None:
    obs = [Observation("t01", "email", FieldGroup.IDENTITY, "a@b", "holehe:x")]
    path = save_observations("t01", obs, tmp_path)
    assert load_observations(path)[0].source == "holehe:x"
