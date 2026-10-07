# Security Review Response — idp-2026-10-06

Response to the AWS Security Agent code review report
(`code-review-report-idp-2026-10-06-1791367937766.pdf`, review `idp-2026-10-06`,
scanned against commit `07f1381`). Each finding was re-validated against the
current source tree before remediation.

> **Status: 5 of 6 findings remediated in code; 1 (resilience) is documentation
> plus a flagged architectural follow-up.** The fixes landed across two change
> sets (see `CHANGELOG.md` → Unreleased, "Security (code review idp-2026-10-06)"
> and "Changed (code review idp-2026-10-06)"). Verification: `ruff` clean,
> `bandit` clean (medium+; the 13 pre-existing Low B105/B106 placeholder findings
> are unchanged from `origin/main`), `pytest` passing with 100% coverage
> (686 passed, 28 skipped), 32 smoke tests passing.

**Validation outcome:** All six findings are **real**. None is a false positive.
A few line numbers drifted (the scan ran against `07f1381`), but every
substantive claim reproduced in the current code. Finding 3 (`trust_proxy`) had
been partially addressed since the scan — the `create_app` parameter existed —
but the residual gap (default-on, no config/env wiring) was real and is now
closed.

Severity totals: 0 Critical, 1 High, 4 Medium, 1 Low.

---

## Priority order for remediation

1. **Finding 1** — Admin restore reaches only the unverified plaintext branch;
   forged archive extracted as root (High)
2. **Finding 5** — Session cookie resurrection after delete/recreate (Medium)
3. **Finding 2** — Bearer credentials in URL query strings; audit page not
   cache-suppressed (Medium)
4. **Finding 3** — `X-Forwarded-For` trusted with no off switch (Medium)
5. **Finding 4** — Audit log integrity / retention (Medium)
6. **Finding 6** — No RTO/RPO; single-point-of-failure by design (Low)

---

## Finding 1 — Unverified backup restore (High) — REAL

**Verified.** The backup writer produces authenticated-encrypted
`idp-<ts>.tar.gz.enc` archives with a detached SHA-256 sidecar, and
`restore_encrypted_archive` verifies the digest and Fernet tag before
extracting. But the admin portal restore guard required `archive.endswith(
".tar.gz")`, which is `False` for `.tar.gz.enc`, so the portal could only ever
select a legacy plaintext archive. `backup_cli.do_restore` then routed any
non-`.enc` name to `restore_archive`, which did member-shape validation only and
then `tar.extract()` as root with no `filter=`. The restore dropdown is
populated from whatever filenames exist on a third-party SMB share, so an
attacker with write access there could drop a forged plaintext archive that
becomes the newest/default entry — restoring it overwrites `users.json`,
`idp.key`, `config.yaml`, etc. with attacker-controlled contents.

**Remediation**
1. The admin portal restore guard now accepts only `.tar.gz.enc` archives
   (via `backup.ENCRYPTED_SUFFIX`), keeping the existing `/` and `..` rejection.
2. `backup_cli.do_restore` fails closed: the legacy plaintext fallback is
   removed entirely (no first-party plaintext producer exists, so a gated flag
   would be pure attack surface). Any archive that cannot be authenticated
   (digest + Fernet tag) is refused rather than silently extracted.
3. `restore_archive` extracts with `filter="data"` so archive-chosen modes,
   setuid bits and uid/gid are not applied by the root process; `validate_archive`
   now rejects members carrying setuid, setgid, sticky, group/other-write, or
   other-execute bits (not a strict `0600/0700`-only rule, which would reject
   legitimate `0644` backups).

Files: `admin.py`, `backup.py`, `backup_cli.py`; tests across the backup suite
plus a smoke-marked encrypted happy path. Merged as `3a566c2`.

---

## Finding 5 — Session cookie resurrection (Medium) — REAL

**Verified.** `delete_user` deleted the record with no `_bump_session_epoch` and
no tombstone, and `add_user` created records with no `session_epoch` key (so
`_user_session_epoch` returned 0). A stale cookie for a deleted-then-recreated
username (epoch still 0) re-authenticated as the new principal with the new
record's claims.

**Remediation**
1. `add_user` stamps a non-zero `session_epoch` floor (`int(time.time())`) so a
   recreated username never starts at 0.
2. `delete_user` bumps the epoch and persists a `data/deleted_epochs.json`
   tombstone (owner-only `0600`) recording the deleted account's last epoch.
3. `_user_session_epoch` returns the max of the live record epoch and the
   tombstone, so a resurrected epoch-0 cookie is rejected.

Files: `app.py`, `admin.py`; `tests/test_security_remediation_20261006.py`
(including a positive-control test and a smoke test).

---

## Finding 2 — Bearer credentials in URL query strings (Medium) — REAL

**Verified.** The admin panel linked `/admin/audit-log?auth_token=<token>` as a
GET href and the handler read the credential from `request.args`; the same
1-hour `PURPOSE_ADMIN` token authorizes all admin mutations, and gunicorn's
`--access-logfile -` writes the full request line. The audit-log response set no
`Cache-Control`, unlike the other sensitive admin renders. The OAuth RS256 JWT
was appended to the relying-party URL in 302 redirects at four sites.

**Remediation**
1. The audit-log link is now a POST form carrying the step-up token in the
   request body; `GET /admin/audit-log` returns 405. The step-up requirement is
   preserved.
2. The audit-log response sets
   `Cache-Control: no-store, no-cache, must-revalidate, max-age=0`.
3. The OAuth JWT is delivered via a URL fragment (`#token=`) at all four sites
   (SSO short-circuit GET, MFA tail, password tail, passkey JSON), so it is not
   sent to servers / not logged / not in the `Referer`. The SAML auto-POST path
   is unchanged.

**Caveat / relying-party impact:** fragment delivery requires the relying party
to read the token from `location.hash` client-side rather than from a
server-visible query parameter. This is a behavior change for any OAuth-style SP
that expected the token in the query string. It is called out in the changelog;
relying parties must be updated to read the fragment. (An auto-POST form was
considered but rejected for the OAuth path because the relying-party callbacks
are not guaranteed to accept a cross-origin POST.)

Files: `app.py`, `admin.py`, `static/passkey.js`; tests in `test_app_full.py`,
`test_admin_full.py`, `test_multisp_functional.py`.

---

## Finding 3 — `X-Forwarded-For` trusted with no off switch (Medium) — REAL

**Verified.** `create_app` installed `ProxyFix(x_for=1, …)` whenever
`trust_proxy` was true, and the parameter defaulted to `True` with no config
key, no env override, and no caller threading it through. The shipped
`docker-compose` publishes `:5000` directly with no proxy, so `X-Forwarded-For`
was attacker-controlled there — a per-IP rate-limit bypass and audit source-IP
forgery.

**Remediation**
1. New `server.trust_proxy` config field / `IDP_TRUST_PROXY` env var, defaulting
   to `False`, threaded through both entrypoints into `create_app`.
2. The `create_app` `trust_proxy` default is flipped to `False`, so an
   un-configured deployment keeps the real socket peer address.
3. `docker-compose.yml` documents that `IDP_TRUST_PROXY` must stay off without a
   trusted reverse proxy; the Kubernetes manifest sets it `true` because an
   Ingress fronts the pod. Documented in `docs/configuration.md`.

**Deployment impact:** a deployment that *does* sit behind a trusted proxy and
relied on the previous default-on behavior must now set `IDP_TRUST_PROXY=true`
explicitly, or per-IP rate limiting and audit IPs will key on the proxy address.

Files: `config.py`, `app.py`, `__main__.py`, `run_gunicorn.py`,
`examples/kubernetes/deployment.yaml`; tests in `test_config.py`,
`test_app_full.py`.

---

## Finding 4 — Audit log integrity / retention (Medium) — REAL

**Verified.** The hash chain was keyed with `app.secret_key` (the same root key
as sessions/CSRF/MFA tickets, ephemeral when `SECRET_KEY` was unset);
`verify_chain` had no non-test caller; and PII (username, IP, full User-Agent)
was mirrored verbatim to stdout. Retention was an unfilled placeholder in
`docs/security.md`.

**Remediation**
1. The chain is keyed by a dedicated `IDP_AUDIT_CHAIN_KEY`
   (config `security.audit_chain_key`) or a stable, auto-created `0600`
   `data/audit_chain.key` — never `app.secret_key`. A new `AuditChainKeyError`
   fails closed if no stable key can be established, matching the
   `WeakSecretKeyError` pattern from idp-20261003 F5.
2. `verify_chain` runs at startup (firing a `critical` `audit_chain_invalid`
   notification on failure) and on every admin audit-log render (in-page
   integrity banner on failure).
3. The stdout AUDIT mirror is redacted — the User-Agent is replaced with a short
   sha256 digest and the username is truncated — while the on-disk record and
   hash chain are byte-for-byte unchanged.
4. `docs/security.md` states a concrete 12-month retention (3 months hot) and
   the operator's rotation / append-only forwarding responsibilities;
   `docs/configuration.md` documents `IDP_AUDIT_CHAIN_KEY`.

**Residual (tied to Finding 6):** the in-memory chain cursor
(`_seq`/`_last_hash`) remains per-process. This is safe only in the shipped
single-worker topology; externalising chain state is deferred to the Finding 6
follow-up.

Files: `audit.py`, `app.py`, `admin.py`, `config.py`, `__main__.py`,
`run_gunicorn.py`, `docs/security.md`, `docs/configuration.md`; tests in
`tests/test_audit_integrity.py`.

---

## Finding 6 — No RTO/RPO; single point of failure by design (Low) — REAL

**Verified.** No RTO/RPO targets exist anywhere in the tree, and the architecture
pins a single replica (`replicas: 1`) and single worker (`--workers 1`) on
purpose: the rate limiter, MFA/captcha nonce stores, WebAuthn challenge store,
enrol-secret store and audit chain cursor are all per-process in-memory state,
and the app warns at startup that horizontal scaling would weaken these
anti-abuse controls. Raising the replica count alone is therefore *not* a safe
fix.

**Status: documentation + flagged architectural follow-up (not fully
remediated).** This is a design-level item, not a self-contained code fix. The
recommended path:

1. **Docs (near-term):** state an RPO derived from the nightly backup cadence and
   an RTO derived from the restore procedure in `docs/backups.md`, plus a
   capacity-plan section covering demand spikes and partial infrastructure loss.
2. **Architecture (larger effort, deferred):** externalise the per-process
   security state (rate limiter, nonce/challenge/enrol stores) and the audit
   chain cursor into a shared backend (e.g. Redis) so the state no longer forks
   per worker. Only *after* that is done can `replicas` / `--workers` be raised
   and a PodDisruptionBudget, topology spread and HorizontalPodAutoscaler be
   added.

This finding is recorded here as accepted-with-a-plan rather than resolved; it
needs a product decision on the Redis dependency before implementation.

---

## Verification summary

Run from the project root with the `py314` venv active:

- `ruff check identity_provider_server/` → clean
- `bandit -r identity_provider_server/` → 0 medium+ (13 pre-existing Low
  B105/B106 placeholder/UI-literal findings, identical to `origin/main`)
- `pytest -q` → 686 passed, 28 skipped
- `pytest --cov=identity_provider_server --cov-fail-under=100` → 100.00%
- `pytest -m smoke -q` → 32 passed
