"""Tests for the added collectors: nexfil, GitHub API, toutatis."""

from __future__ import annotations

from osint_ai_pwg.collect.tools.github_api import GitHubAPICollector
from osint_ai_pwg.collect.tools.nexfil import NexfilCollector
from osint_ai_pwg.collect.tools.toutatis import ToutatisCollector


def test_nexfil_parses_urls_and_dedupes_hosts():
    out = (
        "[>] Progress : 12\rhttps://lemmy.eus/u/tom48\r"
        "[>] Progress : 13\rhttps://svidbook.ru\r"
        "[>] Progress : 14\rhttps://lemmy.eus/u/tom48\r"
    )
    obs = NexfilCollector(runner=lambda cmd: out).parse(out, {"username": "tom48"}, "t99")
    assert len(obs) == 2, "same host must be deduped"
    assert {o.source for o in obs} == {"nexfil:lemmy.eus", "nexfil:svidbook.ru"}
    assert all(o.field == "username" and o.value == "tom48" for o in obs)


def test_github_api_maps_profile_fields():
    def fake_fetch(url):
        assert url.endswith("/users/tom48")
        return {
            "html_url": "https://github.com/tom48",
            "name": "Tom Test",
            "location": "Springfield",
            "email": "tom@example.test",
        }

    obs = GitHubAPICollector(fetch=fake_fetch).collect("t99", {"username": "tom48"})
    fields = {o.field: o.value for o in obs}
    assert fields == {"name": "Tom Test", "city": "Springfield", "email": "tom@example.test"}
    assert all(o.url == "https://github.com/tom48" for o in obs)


def test_github_api_returns_empty_on_404():
    obs = GitHubAPICollector(fetch=lambda url: {"message": "Not Found"}).collect(
        "t99", {"username": "nobody"}
    )
    assert obs == []


def test_toutatis_parses_labelled_lines(monkeypatch):
    monkeypatch.setenv("INSTAGRAM_SESSIONID", "abc")
    out = (
        "Informations about     : tom48\n"
        "Full Name              : Tom Test\n"
        "Public Email           : tom@example.test\n"
        "Public Phone number    : +1 555 0100\n"
    )
    c = ToutatisCollector(runner=lambda cmd: out)
    assert c.build_cmd({"username": "tom48"}) == ["toutatis", "-u", "tom48", "-s", "abc"]
    obs = c.parse(out, {"username": "tom48"}, "t99")
    fields = {o.field: o.value for o in obs}
    assert fields == {"name": "Tom Test", "email": "tom@example.test", "phone": "+1 555 0100"}


def test_toutatis_without_session_is_noop(monkeypatch):
    monkeypatch.delenv("INSTAGRAM_SESSIONID", raising=False)
    assert ToutatisCollector().collect("t99", {"username": "tom48"}) == []


def test_nexfil_strips_ansi_and_skips_banner():
    out = (
        "[+] Created By   : thewhiteh4t\n"
        " |---> Twitter   : https://twitter.com/thewhiteh4t\n"
        "[>] Progress : 1\rhttps://\x1b[33mgiphy.com\x1b[0m/explore/tom48\r"
        "https://github.com/thewhiteh4t/nexfil\r"
    )
    obs = NexfilCollector(runner=lambda cmd: out).parse(out, {"username": "tom48"}, "t99")
    assert [o.source for o in obs] == ["nexfil:giphy.com"]
