# Ethics & Data Governance — OSINT-AI-PWG Pilot

**For supervisor review and sign-off (ROADMAP Phase 0).**
Study: measuring LLM password-guessing performance when PII is sourced from OSINT vs. ground truth.
Author: Maximus Bayu Proudiasto (NIM 203022520004). Supervisor (I): Niken Dwi Wahyu Cahyani, S.T., M.Kom, Ph.D.

---

## 1. Study design & why it is low-risk

Targets are **the researcher/teammates (self-consenting) plus fully synthetic personas** — no
non-consenting third parties are profiled. Ground-truth PII and passwords are known by construction,
so there is no attempt to deanonymize or attack any real external individual.

The pilot is a **feasibility study** (n = 10–20), descriptive only, no human-participant recruitment
beyond the consenting research team.

## 2. Legal / ethical basis

- **No breach data.** The project deliberately does **not** use leaked credential databases as its PII
  source — that is the gap the thesis studies. OSINT collection targets only self/synthetic identities.
- **Public-source collection only**, exercised against identities the team controls.
- **No attack on real systems.** Guessing is evaluated offline against known passwords the team assigned;
  no login endpoint of any real service is ever probed with a guess.

## 3. Data categories handled

| Category | Example (synthetic) | Handling |
|----------|--------------------|----------|
| Pseudonymous target ID | `t01` | Used everywhere in code/logs/results. |
| Planted PII | name, username, birthdate `1998-04-12`, email `spersona@example.com` | Encrypted at rest in `data/`. |
| Assigned password | `REDACTED` | Encrypted at rest; never logged. |
| Collected observations | source-tagged PII values | Encrypted at rest in `data/`. |

## 4. Data minimization & security

- **Pseudonymous IDs only** in code, logs, results. Any ID→identity map (for self subjects) stays in an
  encrypted file in `data/`, never logged.
- **Encryption at rest** for all of `data/` (encrypted volume or age/gpg archive). Decrypt in memory only.
- **No PII in logs.** Log target IDs, field *names*, and metrics — never field *values* or passwords.
- **`data/` is gitignored.** Raw PII/passwords never enter version control.

## 5. Synthetic persona planting — venue policy (resolves open item 1)

- **Default: controlled sandbox.** Personas live in researcher-controlled environments/accounts wherever
  possible; every planted field is recorded in `data/personas/`.
- **Live public platforms only after a per-platform Terms-of-Service check** confirming test/synthetic
  accounts are permitted. Where ToS forbids it, use the sandbox. Document the decision per platform.

## 6. Password distribution for personas (resolves open item 2)

Assigned passwords mirror the empirical PII-in-passwords rate: **~60% embed PII** (per Li et al., 60.1%
of 12306 passwords contain ≥1 PII type), **~40% do not**. Spread across all three footprint tiers so the
engine is exercised on both PII-laden and PII-free targets.

## 7. Retention & destruction (fills the data/README TODOs)

- **Retention window:** for the duration of the thesis, up to and including the examination/defense.
- **Destruction:** securely wipe `data/personas/` and `data/ground_truth/` (and any ID maps) **within 30
  days after examination**. Tear down synthetic accounts created on live platforms.
- *Supervisor may override either value; record the agreed values here.*

## 8. Validity safeguard (leakage)

Pilot targets are **evaluation-only** and must never appear in any model training corpus. The guessing
model is a **pre-fine-tuned external checkpoint**; its training data provenance is checked in Phase 3 to
confirm no overlap with these identities.

## 9. Scope exclusions

No protocol-level attacks (WPA2, PKI), no offline hash cracking of real credentials, no MFA bypass, no
profiling of real non-consenting individuals. Online single-target guessing against known-answer targets only.

---

**Sign-off**

- [ ] Supervisor reviewed and approved: __________________________  Date: __________
- [ ] Retention/destruction values confirmed (§7).
- [ ] Planting venue policy confirmed (§5).
