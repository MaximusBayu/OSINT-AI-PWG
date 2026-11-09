"""Proof-link verification: dead links and root-only URLs must not reach the graph."""

from __future__ import annotations

import urllib.error

from osint_ai_pwg.collect import verify
from osint_ai_pwg.schemas import FieldGroup, Observation


def _obs(url: str, value: str = "Lordmax4581") -> Observation:
    return Observation(
        target_id="t",
        field="username",
        group=FieldGroup.IDENTITY,
        value=value,
        source="test",
        url=url,
    )


def test_root_only_url_is_not_proof() -> None:
    check = verify.check_link("https://example.com/")
    assert not check.ok
    assert check.reason == "root-only"


def test_verify_drops_404_and_root_keeps_good_and_no_url(monkeypatch) -> None:
    def fake(url: str, timeout: float = 6.0) -> verify.LinkCheck:
        if url == "https://ok.test/u":
            return verify.LinkCheck(url, True, 200, "ok")
        if url == "https://gone.test/u":
            return verify.LinkCheck(url, False, 404, "http-404")
        return verify.LinkCheck(url, False, None, "root-only")

    monkeypatch.setattr(verify, "check_link", fake)
    obs = [
        _obs("https://ok.test/u"),
        _obs("https://gone.test/u"),
        _obs("https://root.test/"),
        _obs(""),
    ]
    kept, dropped, checks = verify.verify_observations(obs)

    assert [o.url for o in kept] == ["https://ok.test/u", ""]
    assert len(dropped) == 2
    assert checks["https://gone.test/u"].status == 404


def test_head_403_falls_back_to_get(monkeypatch) -> None:
    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_urlopen(req, timeout=None):
        if req.get_method() == "HEAD":
            raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", None, None)
        return _Resp()

    monkeypatch.setattr(verify.urllib.request, "urlopen", fake_urlopen)
    check = verify.check_link("https://ok.test/u", timeout=1)
    assert check.ok
    assert check.status == 200


def test_one_http_check_per_distinct_url(monkeypatch) -> None:
    calls: list[str] = []

    def fake(url: str, timeout: float = 6.0) -> verify.LinkCheck:
        calls.append(url)
        return verify.LinkCheck(url, True, 200, "ok")

    monkeypatch.setattr(verify, "check_link", fake)
    verify.verify_observations([_obs("https://a.test/u"), _obs("https://a.test/u")])
    assert calls == ["https://a.test/u"]
