"""h8mail collector tests — injected report runner, no live breach lookup."""

from __future__ import annotations

from osint_ai_pwg.collect.tools.h8mail import H8mailCollector, _flatten, _service_of
from osint_ai_pwg.schemas import FieldGroup

REPORT = {
    "targets": [
        {
            "target": "rina@example.com",
            "pwn_num": 2,
            "data": [
                [
                    "SCYLLA_USERNAME:rina48",
                    "SCYLLA_EMAIL:rina@example.com",
                    "SCYLLA_PASSWORD:hunter2",
                    "SCYLLA_SOURCE:scylla.sh",
                ],
                [
                    "SNUS_NAME:Rina Example",
                    "SNUS_USERNAME:rina48",
                    "SNUS_SOURCE:snusbase",
                ],
            ],
        }
    ]
}


def test_h8mail_maps_identity_from_breach() -> None:
    c = H8mailCollector(report_runner=lambda cmd: REPORT)
    obs = c.collect("t01", {"email": "rina@example.com"})
    fields = {(o.field, o.value) for o in obs}
    # username, name, email recovered; leaked password deliberately NOT mapped.
    assert ("username", "rina48") in fields
    assert ("name", "Rina Example") in fields
    assert ("email", "rina@example.com") in fields
    assert all(o.group is FieldGroup.IDENTITY for o in obs)
    assert not any(o.value == "hunter2" for o in obs)


def test_h8mail_missing_email_yields_nothing() -> None:
    c = H8mailCollector(report_runner=lambda cmd: REPORT)
    assert c.collect("t01", {}) == []
    assert c.collect("t01", {"username": "rina48"}) == []


def test_service_prefix_mapping() -> None:
    assert _service_of("SCYLLA_USERNAME") == "scylla"
    assert _service_of("SNUS_NAME") == "snusbase"
    assert _service_of("WEIRD_FIELD") == "breach"


def test_flatten_groups() -> None:
    data = [["SCYLLA_USERNAME:rina48", "SCYLLA_EMAIL:r@x.com"], ["SNUS_NAME:Rina"]]
    assert _flatten(data) == [
        ("SCYLLA_USERNAME", "rina48"),
        ("SCYLLA_EMAIL", "r@x.com"),
        ("SNUS_NAME", "Rina"),
    ]
