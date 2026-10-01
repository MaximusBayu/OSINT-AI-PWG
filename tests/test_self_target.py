"""Self-target record builder tests."""

from __future__ import annotations

from osint_ai_pwg.personas.schema import PasswordKind, validate
from osint_ai_pwg.personas.self_target import build_self_target
from osint_ai_pwg.schemas import FootprintTier


def test_self_target_full_is_rich_and_valid() -> None:
    gt = build_self_target(
        "self01", password="Rina!1995",
        name="Rina Example", username="rina_x", email="rina@example.com",
        birthdate="1995-06-01", city="Testville", phone="+620000000000",
        platforms=["twitter", "instagram", "linkedin", "github"],
    )
    assert validate(gt) == []
    assert gt.footprint_tier is FootprintTier.RICH        # 4 groups, 4 platforms
    assert gt.password_kind is PasswordKind.PII_LADEN     # contains "Rina" + "1995"


def test_self_target_minimal_is_sparse() -> None:
    gt = build_self_target("self02", password="xY7q!pla2", name="Solo", platforms=["twitter"])
    assert gt.footprint_tier is FootprintTier.SPARSE      # 1 group, 1 platform
    assert gt.password_kind is PasswordKind.RANDOM        # no PII token in password
    assert list(gt.pii) == ["Identity"]
