"""Phase 2a tests: tool parsers, orchestrator tolerance/dedupe, registry, store roundtrip."""

from __future__ import annotations

import json
from pathlib import Path

from osint_ai_pwg.collect.base import Collector
from osint_ai_pwg.collect.orchestrator import collect_target
from osint_ai_pwg.collect.registry import build_collectors
from osint_ai_pwg.collect.seed import derive_seed
from osint_ai_pwg.collect.store import load_observations, save_observations
from osint_ai_pwg.collect.tools.holehe import HoleheCollector
from osint_ai_pwg.collect.tools.maigret import MaigretCollector
from osint_ai_pwg.collect.tools.sherlock import SherlockCollector
from osint_ai_pwg.collect.tools.theharvester import TheHarvesterCollector
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

MAIGRET_REPORT = {
    "GitHub": {
        "status": {"status": "Claimed",
                   "ids": {"fullname": "The Octocat", "location": "San Francisco"}},
    },
    "GitHubGist [GitHub]": {
        "status": {"status": "Claimed", "ids": {}},
    },
    "NotAThing": {"status": {"status": "Available", "ids": {}}},
}


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


def test_maigret_collect_maps_claimed_sites_and_extracted_pii() -> None:
    c = MaigretCollector(report_runner=lambda cmd: MAIGRET_REPORT)
    obs = c.collect("t01", {"username": "octocat"})
    # 2 claimed sites -> 2 username confirmations + 1 name + 1 city = 4 observations.
    assert len(obs) == 4
    usernames = [o for o in obs if o.field == "username"]
    assert {o.source for o in usernames} == {"maigret:github", "maigret:githubgist"}
    assert all(o.group is FieldGroup.IDENTITY and o.value == "octocat" for o in usernames)
    names = [o for o in obs if o.field == "name"]
    assert len(names) == 1 and names[0].value == "The Octocat"
    assert names[0].group is FieldGroup.IDENTITY
    cities = [o for o in obs if o.field == "city"]
    assert len(cities) == 1 and cities[0].value == "San Francisco"
    assert cities[0].group is FieldGroup.LOCATION


def test_maigret_missing_username_yields_nothing() -> None:
    c = MaigretCollector(report_runner=lambda cmd: MAIGRET_REPORT)
    assert c.collect("t01", {}) == []
    assert c.collect("t01", {"email": "x@example.com"}) == []


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
    assert {"sherlock", "holehe", "maigret", "linkedin", "github"} <= names
    # no region -> general tools only
    base = {"sherlock", "holehe", "maigret", "h8mail", "tavily",
            "nexfil", "github-api", "ghunt", "instaloader", "toutatis"}
    assert {c.name for c in build_collectors(region=None, config_path=cfg)} == base


def test_registry_includes_hosted_services_when_urls_given() -> None:
    names = {c.name for c in build_collectors(
        spiderfoot_url="https://sf.example", theharvester_url="https://harvest.example")}
    assert {"sherlock", "holehe", "maigret", "spiderfoot", "theharvester"} <= names
    # no URLs -> hosted services stay out
    base = {"sherlock", "holehe", "maigret", "h8mail", "tavily",
            "nexfil", "github-api", "ghunt", "instaloader", "toutatis"}
    assert {c.name for c in build_collectors()} == base


class FakeHarvestHttp:
    def __init__(self, emails: list[str]) -> None:
        self._emails = emails
        self.urls: list[str] = []

    def get(self, url: str) -> str:
        self.urls.append(url)
        return json.dumps({"emails": self._emails, "hosts": ["a.example.com"]})


def test_theharvester_extracts_domain_and_maps_emails() -> None:
    http = FakeHarvestHttp(["a@example.com", "b@example.com"])
    c = TheHarvesterCollector("https://harvest.example", http=http)
    obs = c.collect("t01", {"email": "rina@example.com"})
    assert {o.value for o in obs} == {"a@example.com", "b@example.com"}
    assert all(o.field == "email" and o.group is FieldGroup.IDENTITY for o in obs)
    assert all(o.source == "theharvester:restful" for o in obs)
    # queried the seed's domain, with the default source list
    assert "domain=example.com" in http.urls[0]
    assert "source=crtsh" in http.urls[0]


def test_theharvester_no_email_no_query() -> None:
    http = FakeHarvestHttp([])
    c = TheHarvesterCollector("https://harvest.example", http=http)
    assert c.collect("t01", {"username": "rina48"}) == []   # no email -> no domain
    assert http.urls == []


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


def test_sherlock_captures_profile_url() -> None:
    c = SherlockCollector(runner=_fixed_runner(SHERLOCK_OUT))
    obs = c.collect("t01", {"username": "rina48"})
    assert {o.url for o in obs} == {"https://github.com/rina48", "https://twitter.com/rina48"}


def test_on_collector_callbacks_fire() -> None:
    events: list[tuple[str, str, int]] = []

    def on(event: str, name: str, count: int = 0) -> None:
        events.append((event, name, count))

    collect_target("t01", {}, [_Ok(), _Ok()], timeout_s=5, on_collector=on)
    starts = [e for e in events if e[0] == "start"]
    dones = [e for e in events if e[0] == "done"]
    assert len(starts) == 2 and len(dones) == 2
    assert all(d[2] == 1 for d in dones)          # each _Ok returns 1 obs (pre-dedupe)
