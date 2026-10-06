# Security Review Response — idp-20261003

Response to the second AWS Security Agent code review report (`report.pdf`,
review `idp-20261003`, scanned against commit `7cbdf37`). Each finding was
re-validated against the current source tree before remediation.

> **Status: all 11 findings remediated.** The per-finding fixes landed in the
> same change set as this document (see `CHANGELOG.md` → Unreleased, "Security
> (code review idp-20261003)"). Verification: `ruff` clean,
> `bandit` clean (medium+), `pytest` passing with 100% coverage.

**Validation outcome:** All 11 findings are **real**. None is a false positive.
As with the first review, a few line numbers are off (the scan ran against
`7cbdf37`), but every substantive claim reproduced in the current code. Two of
these findings (F6 and F7) re-open the admin-takeover path that the first review
(idp-20261001) had closed, which is why they are ranked High.

Severity totals: 1 Critical, 2 High, 6 Medium, 2 Low.

---

## Priority order for remediation

1. **F5** — Default/weak `SECRET_KEY` allows session + CSRF forgery (Critical)
2. **F7** — Second-factor enrollment accepts a client-supplied secret (High)
3. **F6** — Durable lockout only on `POST /<sp>`, not `/user`/`/recover`/admin (High)
4. **F1** — Unbounded in-memory rate limiter (DoS / limiter bypass) (Medium)
5. **F8** — Sensitive files written world-readable (Medium)
6. **F9** — Audit log is not tamper-evident (Medium)
7. **F2** — Non-ASCII input triggers unhandled 500s (Medium)
8. **F3** — Passkey finish failures are not throttled (Medium)
9. **F11** — No account suspension; deleted-account cookie still honored (Medium)
10. **F4** — Removing the last factor locks the account out (Low)
11. **F10** — No scheduled scanning / vulnerability-management policy (Low)

---

## F5 — Default/weak `SECRET_KEY` (Critical) — REAL

**Verified.** `create_app` fell back to a static placeholder `SECRET_KEY` when
the environment variable was unset, and accepted any value including short or
example strings. The key signs session cookies, CSRF tokens, the audit hash
chain, and MFA tickets, so a known key lets an attacker forge an admin session
cookie outright. `docker-compose.yml` shipped the placeholder and the k8s
Secret shipped a committed example value.

**Remediation**
1. `_resolve_secret_key` now rejects any key in `_PLACEHOLDER_SECRETS` or shorter
   than `MIN_SECRET_KEY_LENGTH` (32), raising `WeakSecretKeyError` so the app
   **fails to start** rather than running with a forgeable key.
2. A random key is generated only when none is supplied (dev convenience);
   production must set a real one.
3. `docker-compose.yml` requires `SECRET_KEY` via `${SECRET_KEY:?...}`; the k8s
   Secret ships unset with out-of-band creation guidance.

> **Deployment impact:** any environment with a placeholder, short, or missing
> key will now refuse to start. This is intended.

---

## F7 — Second-factor enrollment accepts a client-supplied secret (High) — REAL

**Verified.** The TOTP enrollment flow accepted the shared secret from the
client rather than binding a server-issued one, and did not require the current
password to enroll or disable MFA. Combined with F6, this re-opened an
admin-takeover path: an attacker who reached the enroll page could set a secret
they control.

**Remediation**
1. Enrollment binds a server-issued secret, stashed server-side against a
   one-time `secret_handle` (`_stash_enroll_secret`/`_take_enroll_secret`); the
   client never supplies the secret.
2. Enroll and disable both require the current password; disable additionally
   requires a current TOTP code.
3. Admin `remove_mfa` bumps the session epoch, revoking the target's sessions.
4. A unified `_render_enroll_page` helper keeps every render site consistent.

---

## F6 — Durable lockout only on `POST /<sp>` (High) — REAL

**Verified.** The durable per-account lockout added in idp-20261001 was wired
only into the SP password path (`POST /<sp>`). The `/user` login, `/recover`,
and admin login paths counted failures into the sliding window but never
consulted or wrote the durable `locked_until`, so those paths were brute-
forceable despite the documented control.

**Remediation**
1. `/user`, `/recover`, and admin login now gate on the durable lockout and
   record failures into it.
2. The admin path uses an IP-independent per-account bucket
   (`_rl_acct_limited`/`_rl_acct_record`) so distributed probing is still
   throttled per account.

---

## F1 — Unbounded in-memory rate limiter (Medium) — REAL

**Verified.** `_RateLimiter` created a bucket on every `is_limited` read and
never evicted empty entries, so an attacker varying the username/IP key could
grow the dict without bound (memory DoS), and unbounded distinct keys diluted
enforcement.

**Remediation**
1. The limiter is backed by an `OrderedDict` with LRU eviction
   (`max_keys=10000`) and `_prune_key` drops empty buckets.
2. Reads no longer create keys.
3. Login usernames are charset/length validated (`_valid_login_username`,
   `MAX_USERNAME_LENGTH=64`) before becoming keys.
4. `MAX_CONTENT_LENGTH` (64 KiB) caps request bodies.

---

## F8 — Sensitive files written world-readable (Medium) — REAL

**Verified.** `users.json` (bcrypt hashes, TOTP secrets), `recovery_tokens.json`,
and `audit.log` were written with the process umask, commonly `0644`, and the
data directory was not restricted.

**Remediation**
1. `_atomic_write_private` writes `0600` atomically (temp file + rename) for
   `users.json`, `recovery_tokens.json`, and the recovery-token store.
2. The audit log is created `0600`; the data directory is `chmod 0700` at
   startup.
3. `scripts/mint_recovery.py` chmods its output `0600`.

---

## F9 — Audit log not tamper-evident (Medium) — REAL

**Verified.** The audit log was an append-only text file with no integrity
protection; an attacker with write access could edit or truncate it with no
detectable trace, and a write failure was silent.

**Remediation**
1. Records are hash-chained (`seq`, `prev_hash`, `entry_hash`, keyed by
   `app.secret_key`) with a `verify_chain` method.
2. Entries are mirrored to stdout for off-host capture.
3. A `failure_callback` makes write failures loud (`_audit_write_failed`).
4. Reading `GET /admin/audit-log` now requires a step-up admin token.

---

## F2 — Non-ASCII input triggers unhandled 500s (Medium) — REAL

**Verified.** CSRF/token comparisons used `hmac.compare_digest` on `str`
values, which raises on non-ASCII input, and there was no catch-all handler, so
crafted Unicode produced unhandled 500s that leaked tracebacks.

**Remediation**
1. `safe_compare` byte-compares (`utf-8`/`surrogatepass`) and replaces the CSRF
   and token comparisons in `app.py`/`tokens.py`.
2. `@app.errorhandler(Exception)` returns a bounded, audited 500 while
   re-raising `HTTPException` so 404/413 still render normally.

---

## F3 — Passkey finish failures not throttled (Medium) — REAL

**Verified.** The SP `/passkey/finish` failure branches did not record into the
rate-limit buckets its gate reads, so passkey assertions could be retried
without throttling.

**Remediation**
1. Finish failures record the client-IP and account-scoped buckets the gate
   reads, plus an account-scoped gate on entry.

---

## F11 — No account suspension; deleted-account cookie honored (Medium) — REAL

**Verified.** There was no non-destructive suspension; the only lever was
deletion. A deleted (local) account's still-valid session cookie continued to
authenticate because `_verify_session_cookie_full` did not re-check that the
user still existed.

**Remediation**
1. Admin `disable_user`/`enable_user` provide non-destructive suspension with
   session revocation (epoch bump) and audit entries, surfaced in an Account
   Status card.
2. `_verify_session_cookie_full` rejects a cookie whose username is absent from
   `users` (non-ADFS), so a deleted/disabled account's cookie fails closed.

---

## F4 — Removing the last factor locks the account out (Low) — REAL

**Verified.** `remove_passkey` and TOTP disable could remove a user's only
remaining usable factor, leaving the account unable to satisfy its own login
policy.

**Remediation**
1. `may_remove_credential`/`may_remove_totp` + `_usable_factor_count` refuse to
   remove the last usable factor; the HTTP paths enforce this with a backstop
   guard.

---

## F10 — No scheduled scanning / vulnerability-management policy (Low) — REAL

**Verified.** CI ran scanners only on push/PR, with no scheduled run to catch
newly disclosed CVEs in pinned dependencies, no container/OS image scan, and no
documented risk-ranking or remediation SLA.

**Remediation**
1. CI gained a scheduled run (`cron "17 3 * * *"`) and a Trivy image/OS scan
   (`aquasecurity/trivy-action`, HIGH/CRITICAL, ignore-unfixed, failing build).
2. `docs/security.md` documents a vulnerability-management policy: risk ranking
   (cryptography/lxml/signxml/bcrypt/pyotp = Critical), remediation SLAs
   (Critical 7d / High 30d / Medium 90d / Low maintenance), and triage owner
   (Topaz Bott).

> Extending `bandit` to `tests/` was considered and **rejected**: the test
> fixtures contain many pre-existing B104/B310 patterns that are noise rather
> than a meaningful gate.

---

## Verification

- `pytest -q -m "not integration" --ignore=tests/integration` — passing,
  including the 100% coverage gate (`tests/test_coverage_gate.py`).
- `ruff check identity_provider_server` — clean.
- `bandit -r identity_provider_server scripts -q --severity-level medium` — no
  findings.

Genuinely unreachable/defensive branches (shadowed limiters, closure
prune/expiry, HTTP backstops, the uncaught-error audit path) are marked
`# pragma: no cover` with justifications, consistent with the existing codebase.
