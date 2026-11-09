"""Tavily discovery collector tests (mock client — no live API calls)."""

from __future__ import annotations

from osint_ai_pwg.collect.tools.tavily import TavilyCollector
from osint_ai_pwg.schemas import Directness


class _FakeClient:
    def __init__(self, results_by_query: dict) -> None:
        self.results_by_query = results_by_query
        self.calls: list[str] = []

    def search(self, query, max_results=5, search_depth="basic"):
        self.calls.append(query)
        return {"results": self.results_by_query.get(query, [])}


SEED = {
    "name": "Maximus Bayu Proudiasto",
    "username": "Lordmax4581",
    "email": "maximusbayu9b16@gmail.com",
}


def test_no_key_returns_empty() -> None:
    c = TavilyCollector(api_key="")
    assert c.collect("t01", SEED) == []


def test_consistency_gate_drops_wrong_person() -> None:
    # same first name, different surname -> must not be mined as the target
    client = _FakeClient({
        "Maximus Bayu Proudiasto": [
            {"title": "Maximus Bahou", "url": "https://linkedin.com/in/maximus-bahou",
             "content": "Maximus Bahou works at PharMerica"},
        ],
    })
    c = TavilyCollector(client=client)
    assert c.collect("t01", SEED) == []


def test_discovers_pii_and_tags_inferred() -> None:
    client = _FakeClient({
        "Maximus Bayu Proudiasto": [
            {"title": "Maximus Bayu Proudiasto CV",
             "url": "https://example.com/cv",
             "content": "Maximus Bayu Proudiasto, born 2002, Bandung. "
                        "Contact +62 812-3456-7890 or m.bayu.p@work.com"},
        ],
    })
    c = TavilyCollector(client=client)
    obs = c.collect("t01", SEED)
    assert obs
    assert all(o.directness == Directness.INFERRED for o in obs)
    fields = {o.field: o.value for o in obs}
    assert fields.get("email") == "m.bayu.p@work.com"
    assert fields.get("birth_year") == "2002"
    assert any(o.field == "phone" for o in obs)


def test_discovers_new_username_from_profile_url() -> None:
    client = _FakeClient({
        "Lordmax4581": [
            {"title": "Lordmax4581", "url": "https://github.com/Lordmax4581",
             "content": "Lordmax4581 github"},
            {"title": "max on steam", "url": "https://steamcommunity.com/id/maxbayu2002",
             "content": "Maximus Bayu Proudiasto steam profile"},
        ],
    })
    c = TavilyCollector(client=client)
    obs = c.collect("t01", SEED)
    usernames = {o.value for o in obs if o.field == "username"}
    assert "maxbayu2002" in usernames          # discovered handle
    assert "Lordmax4581" not in usernames       # seed handle is not re-emitted


def test_source_url_is_kept() -> None:
    client = _FakeClient({
        "maximusbayu9b16@gmail.com": [
            {"title": "Maximus Bayu Proudiasto", "url": "https://blog.example.com/me",
             "content": "Maximus Bayu Proudiasto, born 2002"},
        ],
    })
    c = TavilyCollector(client=client)
    obs = c.collect("t01", SEED)
    assert obs
    assert all(o.url == "https://blog.example.com/me" for o in obs)
    assert all(o.source.startswith("tavily:") for o in obs)


def test_discovers_full_schema_fields() -> None:
    client = _FakeClient({
        "Maximus Bayu Proudiasto": [
            {"title": "Maximus Bayu Proudiasto",
             "url": "https://example.com/me",
             "content": "Maximus Bayu Proudiasto, born 2002, birthday May 15, "
                        "from Bandung, Indonesia. Address: Jl. Merdeka No. 10"},
        ],
    })
    c = TavilyCollector(client=client)
    obs = c.collect("t01", SEED)
    fields = {o.field: o.value for o in obs}
    assert fields.get("birth_year") == "2002"
    assert fields.get("birth_month") == "May"
    assert fields.get("birth_day") == "15"
    assert fields.get("city") == "Bandung"
    assert fields.get("country") == "Indonesia"
    assert fields.get("address") == "Jl. Merdeka No. 10"
    assert all(o.directness == Directness.INFERRED for o in obs)
