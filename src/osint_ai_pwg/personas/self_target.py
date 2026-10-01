"""Create a CONSENTING self-target ground-truth record (Phase 1, ethics doc section 1).

You are allowed to test the pipeline on yourself (or a consenting teammate). This writes a
data/ground_truth/{id}.json for you, which then appears in the web demo roster automatically.

Two rules, enforced/warned here:
  1. Consent is explicit (--i-consent) — no accidental profiling of others.
  2. Do NOT use a password you actually use anywhere. It is stored in a local (gitignored)
     file. Pick a realistic but throwaway one.

Demo mode only SIMULATES OSINT recovery from what you enter here. Real OSINT-on-self runs
the tools on the Kali VPS against your handles.
"""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from osint_ai_pwg.personas import passwords as pw
from osint_ai_pwg.personas.schema import GroundTruth, PasswordKind, validate
from osint_ai_pwg.personas.tiers import classify

_DEFAULT_PLATFORMS = ["twitter", "instagram", "linkedin", "github"]


def build_self_target(
    target_id: str,
    password: str,
    name: str | None = None,
    username: str | None = None,
    email: str | None = None,
    birthdate: str | None = None,
    city: str | None = None,
    phone: str | None = None,
    platforms: list[str] | None = None,
) -> GroundTruth:
    """Assemble a self-target GroundTruth from the fields you provide (only non-empty ones)."""
    identity = {k: v for k, v in {"name": name, "username": username}.items() if v}
    temporal = {"birthdate": birthdate} if birthdate else {}
    contact = {k: v for k, v in {"email": email, "phone": phone}.items() if v}
    location = {"city": city} if city else {}
    pii = {
        g: fields for g, fields in
        {"Identity": identity, "Temporal": temporal, "Contact": contact, "Location": location}.items()
        if fields
    }

    platforms = platforms or _DEFAULT_PLATFORMS
    planted = {f: list(platforms) for group in pii.values() for f in group}

    flat = {f: v for group in pii.values() for f, v in group.items()}
    kind = PasswordKind.PII_LADEN if pw.contains_pii(password, flat) else PasswordKind.RANDOM

    return GroundTruth(
        target_id=target_id,
        footprint_tier=classify(pii, planted),
        pii=pii,
        password=password,
        password_kind=kind,
        planted=planted,
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Create a consenting self-target record.")
    ap.add_argument("--id", default="self01", help="target id (dropdown label)")
    ap.add_argument("--name")
    ap.add_argument("--username")
    ap.add_argument("--email")
    ap.add_argument("--birthdate", help="YYYY-MM-DD")
    ap.add_argument("--city")
    ap.add_argument("--phone")
    ap.add_argument("--password", help="throwaway, realistic — NOT one you actually use")
    ap.add_argument("--platforms", nargs="*", default=_DEFAULT_PLATFORMS)
    ap.add_argument("--out", type=Path, default=Path("data/ground_truth"))
    ap.add_argument("--i-consent", action="store_true", help="required: you consent to profiling this identity")
    args = ap.parse_args()

    if not args.i_consent:
        raise SystemExit("Refused: pass --i-consent to confirm this is you / a consenting person.")

    password = args.password or getpass.getpass("Throwaway password (not a real one you use): ")
    if not password:
        raise SystemExit("Refused: a password is required.")

    gt = build_self_target(
        args.id, password, args.name, args.username, args.email,
        args.birthdate, args.city, args.phone, args.platforms,
    )
    problems = validate(gt)
    if problems:
        raise SystemExit(f"Invalid record: {problems}")

    path = gt.save(args.out)
    print(f"wrote {path}  (tier={gt.footprint_tier.value}, password_kind={gt.password_kind.value})")
    print("It now appears in the web demo dropdown. Reminder: demo OSINT is simulated.")


if __name__ == "__main__":
    main()
