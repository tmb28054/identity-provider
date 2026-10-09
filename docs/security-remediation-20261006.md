# Security Remediation Plan — Code Review idp-2026-10-06

This plan addresses the 7 findings from the AWS Security Agent code review report
(`code-review-report-idp-2026-10-06-1791538903264.pdf`). All 7 findings were
verified against the current source and confirmed valid.

## Findings summary

| # | Finding | Severity | Phase |
|---|---------|----------|-------|
| 1 | `config.yaml` + all `IDP_*` env overrides silently ignored by the gunicorn entrypoint; per-IP rate limits collapse onto the ingress address | High | 1 |
| 6 | GET `/admin` mints a privileged step-up token from a single-factor `idp_session` carrying the `idpadmin` claim (mandatory admin MFA bypass) | High | 2 |
| 2 | Account-eligibility re-check dropped on three second-leg auth handlers (SP TOTP, /user TOTP, admin passkey finish) | Medium | 2 |
| 3 | Logout performs no server-side session revocation; surrendered cookie still mints assertions; no CSRF, no audit | Medium | 3 |
| 7 | LDAP/AD bind runs with ldap3's `CERT_NONE` default; no code path enables certificate validation in ADFS mode | High | 3 |
| 4 | No maximum password length; a 73+ byte password raises a bcrypt `ValueError` → unhandled 500 that also skips failure accounting | Low | 4 |
| 5 | Durable-lockout response text discloses account existence (username enumeration) | Low | 4 |

## Phased approach

**Phase 1 — Config loader keystone (Finding 1).** Make `create_app` the single
configuration entry point so the documented production command honours config.
Add an unconsumed-config startup guard. Fix Dockerfile/manifests/docs. This
unblocks `trust_proxy`, `webauthn`, and real rate-limit settings that several
other fixes depend on.

**Phase 2 — Auth bypass + eligibility (Findings 6, 2).** Re-apply mandatory admin
MFA on the GET `/admin` cookie path (bind an auth-method/assurance claim into the
session token). Re-run the full eligibility predicate before issuance on all three
second-leg handlers.

**Phase 3 — Session revocation + LDAP TLS (Findings 3, 7).** Make logout bump the
session epoch, audit, and require CSRF/POST. Build a validating TLS context on the
secure LDAP branch with a `ca_certs_file` config key; keep `skip_ssl_verify` as the
only route to `CERT_NONE`. Correct the docs.

**Phase 4 — Hardening cleanup (Findings 4, 5).** Add a 72-byte password maximum,
short-circuit `_check_password` on over-long input, make failure bookkeeping
exception-proof. Make the locked and unknown login responses indistinguishable.

Each phase keeps pylint at 10/10, passes bandit, adds smoke tests, and holds
coverage at or above 80%.

## Outcome

All four phases were implemented, reviewed (two-model semantic review loop), and
merged to `main`. Each phase ran in its own git worktree with an
implement-and-review loop gated on reviewer approval.

| Phase | Findings | Commit | Status |
|-------|----------|--------|--------|
| 1 | F1 (config loader keystone) | `3e551c7` | Merged, APPROVED |
| 2 | F6 (admin MFA), F2 (eligibility) | `3cc0b04` | Merged, APPROVED |
| 3 | F3 (logout revocation), F7 (LDAP TLS) | `d26761b` | Merged, APPROVED |
| 4 | F4 (password length), F5 (lockout enumeration) | `3902ff9` | Merged, APPROVED |

Final verification on `main` (commit `3902ff9`):

- Full test suite: 727 passed, 28 skipped.
- Coverage: 100% (`--cov-fail-under=100` satisfied).
- Pylint: 10.00/10 on changed modules (`app.py`, `adfs.py`, `tokens.py`).
- Bandit: 0 Medium / 0 High. (Two B106 Low items are the dummy
  timing-equalization password constants, not real credentials.)

Pre-existing, out-of-scope pylint findings (a cyclic import between
`admin.py`/`app.py`, and an `os` reimport / nested-blocks in `admin.py`) were
left untouched — refactoring them risks the auth code and is unrelated to this
remediation.

All changes are on `main` locally; `origin/main` has not been pushed.
