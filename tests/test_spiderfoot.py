"""SpiderFoot collector tests — mocked HTTP, no live instance."""

from __future__ import annotations

import json

from osint_ai_pwg.collect.tools.spiderfoot import SpiderFootCollector
from osint_ai_pwg.schemas import FieldGroup


class FakeHttp:
    """Scripts a start -> finished -> results exchange."""

    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows
        self.calls: list[str] = []

    def post(self, url: str, data: dict) -> str:
        self.calls.append("POST " + url)
        return json.dumps(["SUCCESS", "scan123"])

    def get(self, url: str) -> str:
        self.calls.append("GET " + url)
        if "/scanstatus" in url:
            # SpiderFoot v4: [name, target, created, started, ended, STATUS, counts]
            return json.dumps(["pwg-x", "example.com", "0", "0", "0", "FINISHED", {"HIGH": 0}])
        if "/scanexportjsonmulti" in url:
            return json.dumps(self._rows)
        return "[]"


ROWS = [
    {"event_type": "EMAILADDR", "data": "rina@example.com", "module": "sfp_hunter"},
    {"event_type": "HUMAN_NAME", "data": "Rina Example", "module": "sfp_fullcontact"},
    {"event_type": "PHONE_NUMBER", "data": "+620000", "module": "sfp_abstractapi"},
    {"event_type": "MALICIOUS_EMAILADDR", "data": "ignore", "module": "sfp_x"},   # unmapped -> skipped
]


def test_maps_events_to_observations() -> None:
    c = SpiderFootCollector("https://sf.example", http=FakeHttp(ROWS), poll_interval=0)
    obs = c.collect("t01", {"email": "rina@example.com"})
    by_field = {o.field: o for o in obs}
    assert set(by_field) == {"email", "name", "phone"}       # malicious event dropped
    assert by_field["email"].group is FieldGroup.IDENTITY   # email is Identity (revised)
    assert by_field["name"].source == "spiderfoot:sfp_fullcontact"


def test_no_seed_no_scan() -> None:
    http = FakeHttp(ROWS)
    assert SpiderFootCollector("https://sf.example", http=http).collect("t01", {}) == []
    assert http.calls == []                                   # never started a scan


def test_start_id_parsing() -> None:
    assert SpiderFootCollector._parse_scan_id('["SUCCESS", "abc"]') == "abc"
    assert SpiderFootCollector._parse_scan_id('"rawid"') == "rawid"


def test_source_url_extracted_from_source_data() -> None:
    row = {
        "event_type": "HUMAN_NAME",
        "data": "Rina Example",
        "module": "sfp_names",
        "source_data": "{'profileUrl': 'https://gravatar.com/rina48', 'displayName': 'Rina'}",
    }
    assert SpiderFootCollector._source_url(row) == "https://gravatar.com/rina48"
    assert SpiderFootCollector._source_url({"event_type": "X"}) == ""
