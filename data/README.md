# data/ — Governance (READ BEFORE ADDING ANYTHING)

This directory holds **PII and passwords**. It is gitignored (`data/*`, except this README
and `.gitkeep`). Nothing in here is ever committed.

## Rules

1. **No raw PII or passwords in git.** Ever. If you think a file is safe, it is not — leave it here.
2. **Pseudonymous IDs only.** Every target is referenced by an opaque `target_id` in code, logs,
   and results. The mapping from `target_id` to any real identity, if one exists, stays in an
   encrypted file here and is never logged.
3. **Encryption at rest.** Store the sensitive contents encrypted (e.g. an encrypted volume or
   an age/gpg-encrypted archive). Decrypt only in memory during a run.
4. **No PII in logs.** Log `target_id`, field *names*, and metrics — never field *values* or passwords.

## Layout

```
data/
├── personas/       # synthetic persona definitions + record of every planted footprint field
└── ground_truth/   # {target_id}.json = planted PII by group + known password + footprint tier
```

`ground_truth/{id}.json` fully specifies the C2 condition. Structure (synthetic example):

```json
{
  "target_id": "t01",
  "footprint_tier": "moderate",
  "pii": {
    "Identity": { "name": "Synthetic Persona", "username": "spersona" },
    "Temporal": { "birthdate": "1998-04-12" },
    "Location": { "city": "Examplecity" },
    "Contact":  { "email": "spersona@example.com", "phone": "+000000000000" }
  },
  "password": "REDACTED"
}
```

## Retention & destruction

- Retention window: duration of the thesis, up to and including examination/defense (supervisor may override — see `docs/ethics-and-governance.md` §7).
- Destruction: securely wipe personas + ground truth (and any ID maps) within 30 days after examination; tear down any live synthetic accounts.

## Leakage rule (critical for validity)

Targets in `data/` are **evaluation only**. They must never appear in any model training corpus.
The guessing checkpoint is pre-fine-tuned externally; confirm its training data does not overlap
these identities (ROADMAP Phase 3 provenance check).
