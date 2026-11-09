"""Tests for saved-run persistence (revisit a searched profile)."""

from __future__ import annotations

from osint_ai_pwg.web.runs import load_run, save_run


def test_save_and_load_run(tmp_path):
    result = {
        "target_id": "t99",
        "mode": "real",
        "observations": [{"field": "name", "value": "X", "source": "tool", "url": ""}],
    }
    path = save_run(tmp_path, "t99", result)
    assert path.exists(), "save_run must write <target>.json"

    loaded = load_run(tmp_path, "t99")
    assert loaded is not None
    assert loaded["target_id"] == "t99"
    assert loaded["observations"][0]["value"] == "X"
    assert "saved_at" in loaded, "saved run must be timestamped for the UI"


def test_load_run_missing_returns_none(tmp_path):
    assert load_run(tmp_path, "never-ran") is None
