"""Live PassLLM proxy: profile build, forwarding, roster lock, persistence."""

from __future__ import annotations

from fastapi.testclient import TestClient

from osint_ai_pwg.web import app as web


def test_live_guess_builds_c2_profile_and_saves(monkeypatch, tmp_path):
    monkeypatch.setattr(web, "_RUNS_DIR", tmp_path)

    def fake_service(path, payload=None, timeout=600):
        assert path == "/guess"
        assert payload is not None and payload["mode"] == "fast"
        return {
            "mode": "fast",
            "runs": 3,
            "count": 1,
            "elapsed_s": 0.01,
            "guesses": [{"password": "hunter2", "score": -1.0, "confidence": 0.5}],
        }

    monkeypatch.setattr(web, "_service_call", fake_service)
    client = TestClient(web.app)
    r = client.post("/api/passllm/guess", json={"target_id": "t01", "mode": "fast"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["guesses"][0]["password"] == "hunter2"
    assert isinstance(body["profile"], dict)
    assert "hunter2" in (tmp_path / "t01.json").read_text()


def test_live_guess_rejects_unknown_target(monkeypatch):
    monkeypatch.setattr(web, "_service_call", lambda *a, **k: {})
    r = TestClient(web.app).post(
        "/api/passllm/guess", json={"target_id": "nope", "mode": "fast"}
    )
    assert r.status_code == 403


def test_live_guess_rejects_bad_mode(monkeypatch):
    monkeypatch.setattr(web, "_service_call", lambda *a, **k: {})
    r = TestClient(web.app).post(
        "/api/passllm/guess", json={"target_id": "t01", "mode": "turbo"}
    )
    assert r.status_code == 400
