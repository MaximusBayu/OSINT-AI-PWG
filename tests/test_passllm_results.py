"""PassLLM results store + real-guess integration tests."""

from __future__ import annotations

from osint_ai_pwg.personas.generate import build_targets
from osint_ai_pwg.web.passllm_results import load_results, save_results
from osint_ai_pwg.web.service import run_demo


def _roster() -> dict:
    return {gt.target_id: gt for gt in build_targets(n=15, seed=20260923)}


def test_save_load_roundtrip(tmp_path) -> None:
    payload = {
        "target_id": "t01",
        "engine": "passllm",
        "conditions": {"C2": [{"password": "x", "confidence": 0.9}]},
    }
    save_results(tmp_path, "t01", payload)
    assert load_results(tmp_path, "t01") == payload
    assert load_results(tmp_path, "missing") is None


def test_run_demo_uses_real_guesses_when_present() -> None:
    roster = _roster()
    tid = next(iter(roster))
    real = {
        "C2": [{"password": "correct", "confidence": 0.95},
               {"password": "wrong", "confidence": 0.4}],
    }
    out = run_demo(tid, roster, real_guesses=real)
    conds = {c["condition"]: c for c in out["conditions"]}
    assert conds["C2"]["engine"] == "passllm"
    assert conds["C2"]["top_guesses"][0] == {"password": "correct", "confidence": 0.95}
    assert conds["C0"]["engine"] == "demo"          # not in real -> falls back
    assert out["guess_engine"] == "passllm"


def test_run_demo_without_real_guesses_stays_demo() -> None:
    roster = _roster()
    tid = next(iter(roster))
    out = run_demo(tid, roster)
    assert out["guess_engine"] == "demo"
    assert all(c["engine"] == "demo" for c in out["conditions"])
    # demo top_guesses have no confidence
    assert all(g["confidence"] is None for c in out["conditions"] for g in c["top_guesses"])
