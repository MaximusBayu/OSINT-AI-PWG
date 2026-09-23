"""Phase 3 glue tests: input JSONL + order, config hash, manifest, run assembly, store."""

from __future__ import annotations

import json
from pathlib import Path

from osint_ai_pwg.guess.assemble import build_runs
from osint_ai_pwg.guess.config_hash import config_hash
from osint_ai_pwg.guess.jsonl import build_input, write_input
from osint_ai_pwg.guess.manifest import RunManifest
from osint_ai_pwg.guess.runner import build_command
from osint_ai_pwg.guess.store import load_runs, save_runs
from osint_ai_pwg.schemas import Condition, NormalizedProfile, ProfileField


def _profiles() -> list[NormalizedProfile]:
    return [
        NormalizedProfile("t01", {
            "name": ProfileField("Rina P", 0.9, 2),
            "birthdate": ProfileField("1995-06-01", 0.7, 1),
        }),
        NormalizedProfile("t02", {"name": ProfileField("Budi T", 0.8, 1)}),
    ]


def test_build_input_order_and_condition() -> None:
    text, order = build_input(_profiles(), Condition.C1)
    assert order == ["t01", "t02"]
    lines = [json.loads(ln) for ln in text.strip().splitlines()]
    assert lines[0]["birth_year"] == "1995"        # birthdate -> birth_year
    assert lines[1] == {"name": "Budi T"}

    # C0 = empty objects, one per target, order preserved.
    c0_text, c0_order = build_input(_profiles(), Condition.C0)
    assert c0_order == ["t01", "t02"]
    assert [json.loads(x) for x in c0_text.strip().splitlines()] == [{}, {}]


def test_write_input(tmp_path: Path) -> None:
    order = write_input(_profiles(), Condition.C1, tmp_path / "in.jsonl")
    assert order == ["t01", "t02"]
    assert (tmp_path / "in.jsonl").read_text(encoding="utf-8").count("\n") == 2


def test_config_hash_stable_and_sensitive() -> None:
    a = config_hash({"model": {"base": "Qwen3-4B"}, "seed": 1})
    b = config_hash({"seed": 1, "model": {"base": "Qwen3-4B"}})   # key order irrelevant
    c = config_hash({"model": {"base": "Qwen3-4B"}, "seed": 2})
    assert a == b and a != c and len(a) == 16


def test_manifest_roundtrip(tmp_path: Path) -> None:
    m = RunManifest(Condition.C1, "deadbeef", 20260923, ["t01", "t02"], "in.jsonl", "w.pth")
    p = m.save(tmp_path / "manifest.json")
    assert RunManifest.load(p).to_dict() == m.to_dict()


def test_build_runs_preserves_order_and_defaults_empty() -> None:
    runs = build_runs(["t01", "t02"], {"t01": ["pw1", "pw2"]}, Condition.C1, "h")
    assert [r.target_id for r in runs] == ["t01", "t02"]
    assert runs[0].guesses == ["pw1", "pw2"]
    assert runs[1].guesses == []                    # missing output -> empty


def test_runs_store_roundtrip(tmp_path: Path) -> None:
    runs = build_runs(["t01"], {"t01": ["a", "b"]}, Condition.C2, "h")
    p = save_runs(runs, tmp_path / "runs.jsonl")
    loaded = load_runs(p)
    assert loaded[0].guesses == ["a", "b"] and loaded[0].condition is Condition.C2


def test_build_command() -> None:
    cmd = build_command(Path("target.jsonl"), Path("models/w.pth"))
    assert cmd[:3] == ["python", "app.py", "--file"] and "--fast" in cmd
