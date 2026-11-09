"""Tests for the visualize layer (entity graph payload + HTML rendering)."""

from __future__ import annotations

from osint_ai_pwg.schemas import Directness, FieldGroup, Observation
from osint_ai_pwg.visualize.entity_graph import build_payload, render_html


def _obs(field, value, source, group=FieldGroup.IDENTITY, directness=Directness.STATED):
    return Observation(
        target_id="t99",
        field=field,
        group=group,
        value=value,
        source=source,
        directness=directness,
        collected_at="2026-01-01T00:00:00+00:00",
    )


def test_entities_view_merges_sources_and_hides_source_nodes():
    obs = [
        _obs("name", "Tom Test", "sherlock:reddit"),
        _obs("name", "Tom Test", "spiderfoot:reddit"),
        _obs("city", "Springfield", "tavily:twitter", FieldGroup.LOCATION),
    ]
    p = build_payload(obs, "t99", view="entities")

    ids = {n["id"] for n in p["nodes"]}
    assert "person" in ids
    assert "name:Tom Test" in ids
    assert "city:Springfield" in ids

    name_node = next(n for n in p["nodes"] if n["id"] == "name:Tom Test")
    assert name_node["sources"] == 2, "two distinct tools reported the same name"
    assert p["origin"] == "observations"
    assert not any(n["kind"] == "source" for n in p["nodes"])


def test_provenance_view_adds_source_nodes_and_edges():
    obs = [_obs("name", "Tom Test", "sherlock:reddit")]
    p = build_payload(obs, "t99", view="provenance")

    assert any(n["kind"] == "source" for n in p["nodes"])
    assert any(link["rel"] == "reported by" for link in p["links"])


def test_falls_back_to_ground_truth_when_no_observations():
    gt = {
        "target_id": "t01",
        "pii": {"Identity": {"name": "Tom Test"}, "Temporal": {"birthdate": "1989-04-14"}},
        "planted": {"name": ["reddit"], "birthdate": ["instagram"]},
    }
    p = build_payload([], "t01", ground_truth=gt, view="provenance")

    assert p["origin"] == "ground_truth"
    assert p["label"] == "Tom Test"
    assert any(link["rel"] == "planted in" for link in p["links"])
    assert {n["id"] for n in p["nodes"]} >= {"name:Tom Test", "birthdate:1989-04-14"}


def test_render_html_is_self_contained_and_embeds_graph():
    obs = [_obs("name", "Tom Test", "sherlock:reddit")]
    html = render_html(build_payload(obs, "t99"), "Test graph")

    assert "Test graph" in html
    assert "d3" in html
    assert "name:Tom Test" in html
    assert "__GRAPH__" not in html, "placeholder must be substituted"


def test_url_round_trip_and_payload():
    from osint_ai_pwg.collect.store import obs_from_dict, obs_to_dict

    o = _obs("username", "tom48", "sherlock:github")
    o.url = "https://github.com/tom48"

    d = obs_to_dict(o)
    assert d["url"] == "https://github.com/tom48", "store must not drop the proof URL"
    assert obs_from_dict(d).url == "https://github.com/tom48"

    p = build_payload([o], "t99", view="entities")
    node = next(n for n in p["nodes"] if n["id"] == "username:tom48")
    assert node["url"] == "https://github.com/tom48"
    assert node["urls"] == ["https://github.com/tom48"]


def test_run_real_persists_observations(tmp_path):
    from pathlib import Path

    from osint_ai_pwg.personas.schema import GroundTruth
    from osint_ai_pwg.web.service import run_real

    gt = GroundTruth.load(Path("data/ground_truth/t01.json"))
    roster = {gt.target_id: gt}

    class _Fake:
        name = "fake-tool"

        def collect(self, target_id, seed):
            o = _obs("username", "tom48", "fake-tool")
            o.url = "https://example.test/tom48"
            return [o]

    run_real(gt.target_id, roster, "http://unused", collectors=[_Fake()], obs_dir=tmp_path, verify_links=False)

    out = tmp_path / f"{gt.target_id}.jsonl"
    assert out.exists(), "run_real must persist observations for the graph"
    assert "https://example.test/tom48" in out.read_text(encoding="utf-8")
