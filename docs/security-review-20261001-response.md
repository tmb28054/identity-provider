# Security Review Response — idp-20261001

Response to the AWS Security Agent code review report dated October 1, 2026
(`code-review-report-idp-20261001-1790886149625.pdf`). Each finding was
re-validated against the current source tree before writing this plan.

> **Status: all 12 findings remediated.** The per-finding fixes landed in the
> same change set as this document (see `CHANGELOG.md` → Unreleased). Each
> finding below retains its original analysis; the code now implements the
> remediation described. Verification: `ruff` clean, `bandit` clean (medium+),
> `pytest` 592 passing with 100% coverage, `yamllint` clean on changed files.

**Validation outcome:** All 12 findings are **real**. None is a false positive.
The report's line numbers are occasionally off by a few lines (the scan ran
against commit `90bda2d`), but every substantive claim was reproduced in the
current code. Where the report overstates certainty it also says so itself
(e.g. SMB transport encryption is "possible rather than certain"); those nuances
are preserved below.

Severity totals: 3 High, 6 Medium, 3 Low.

---

## Priority order for remediation

1. **F3** — Disabled account not revoked on session/admin cookie paths (High, auth bypass)
2. **F1** — TOTP second factor brute-forceable (High, auth bypass)
3. **F4** — Lockout / password history / admin MFA / LDAP empty bind (High)
4. **F5** — No server-side absolute session lifetime (Medium)
5. **F6** — Audit gaps on credential + SP/backup mutations (Medium)
6. **F8** — Inconsistent enforcement (shares root cause with F3/F6) (Medium)
7. **F10** — Multi-worker voids per-process controls (Medium)
8. **F7** — Unencrypted/unsigned backups (Medium)
9. **F9** — Supply-chain pinning + non-blocking CI gates (Medium)
10. **F2** — Passkey begin enumeration (Low)
11. **F11** — `scripts/deploy.py` committed despite gitignore (Low)
12. **F12** — No incident-response communication plan (Low)

F3, F6, and F8 overlap heavily (the same missing account-state gate and the
same audit asymmetry). Fixing them together is the efficient path.

---

## F3 — Disabling an account does not revoke it (High) — REAL

**Verified.** The account-state gate `_user_can_login` (`app.py:557`) and
`_needs_password_change` are applied on every credential-proving path but
skipped on every path that authorizes from an `idp_session` cookie:

- `_handle_login_form` session-reuse branch uses a bare `if user:`
  (`app.py:1161-1163`) and then mints a SAML assertion / OAuth JWT and re-issues
  the cookie — no `_user_can_login`, no forced-rotation check.
- The admin predicate `_has_claim` (`admin.py:494-498`) checks only the claims
  list. All cookie-authorized admin routes gate on it alone: `GET /admin`
  (`682`), `GET /admin/audit-log` (`1372`), `GET /admin/backups` (`1599`),
  `GET /admin/user/<u>` (`1741`). `_require_admin` (`501-510`) does not recheck
  state either.
- By contrast the admin password path *does* check both flags
  (`admin.py:905-910`), and the SP password/passkey paths call
  `_user_can_login` — confirming the omission is an oversight, not a design
  choice.
- `verify_token` (`tokens.py:69-102`) is stateless: signature, purpose, age
  only. There is no revocation list or session epoch, so a live cookie survives
  disablement until it idles out.

**Remediation**
1. In `_handle_login_form`, replace `if user:` with
   `if user and _user_can_login(user) and not _needs_password_change(session_user):`
   and fall through to the login form otherwise.
2. Factor the `account_usable` test (`admin.py:905-910`) into a helper and call
   it alongside `_has_claim` at `682`, `1372`, `1599`, `1741`, and inside
   `_require_admin` so every mutation revalidates.
3. Add a revocable component to the session token: include a per-user
   `session_epoch` from the user record in the signed payload
   (`tokens.py:issue_token`) and bump it in `disable` / `set_claims` /
   `reset_password`. Reject cookies whose epoch is stale in
   `_verify_session_cookie`. This gives true server-side revocation and also
   closes the F5 replay window.

---

## F1 — TOTP second factor is brute-forceable (High) — REAL

**Verified.** The TOTP step records failures into a rate-limit bucket that no
caller ever reads, and the MFA ticket is not consumed on failure.

- Failed TOTP records only `rate_limiter.record(_rl_key(client_ip, auth_username))`
  (`app.py:1301`) — the composite `"ip|username"` key.
- Every `is_limited(...)` call site reads a *different* key: `client_ip`
  (`1243`, `1693`, `2371`, `2398`, `2618`) or `acct:{username}` (`1406`,
  `1797`). The composite key is never checked anywhere in `app.py` (contrast
  `admin.py:476`, which does check it). So wrong TOTP codes cost nothing.
- The only limiter consulted on the TOTP path is `is_limited(client_ip)` at
  `1243`, incremented only by failed passwords (`1429`) and recovery failures —
  never by TOTP failures.
- `_consume_mfa_nonce` runs only after `verify_code` succeeds
  (`1325-1326`); the failure branch re-renders `TOTP_FORM` with the same
  `mfa_ticket` (`1311-1322`), so one 120-second ticket is replayable for many
  guesses.
- `totp.py:21-23` uses `valid_window=2`, widening the accepted set to ~5 codes.

Precondition: the attacker already holds the password, so this is a
second-factor defeat, not initial access. `docs/security.md` claims rate
limiting/lockout on every credential endpoint, which this path contradicts.

**Remediation**
1. On the failing TOTP branch (`app.py:1301`, and the `/user` TOTP step at
   `1738`) also record the checked buckets: `rate_limiter.record(client_ip)` and
   `rate_limiter.record(f"acct:{auth_username}")` — or make `is_limited` at
   `1243` additionally test the composite key. The composite key written at
   `1301`, `1461`, `1738`, `2410`, `2416`, `2426` must be read somewhere.
2. Consume the ticket nonce *before* verifying the code (move
   `_consume_mfa_nonce` to right after `_read_mfa_ticket` succeeds) so each
   ticket allows exactly one guess.
3. Add durable per-account lockout (see F4) rather than only the 60-second
   sliding window, and narrow `valid_window` from 2 to 1 in `totp.py`.

---

## F4 — Weak credential management (High) — REAL

**Verified**, all four sub-claims:

1. **No lockout, no password history.** `_RateLimiter` (`app.py:609-625`) is a
   60-second sliding window; the bucket self-clears, with no persisted lockout
   state. No `password_history`/`previous_passwords` field exists anywhere in
   the tree; the forced-change flow rejects only the current password
   (`1986-1987`), self-service change checks policy/confirmation only
   (`2156-2162`), and admin reset checks policy only (`admin.py:1053-1068`).
2. **Admin MFA optional.** `admin.py:916` gates the second factor on
   `if user.get("totp_secret"):` — an `idpadmin` with no TOTP authenticates with
   a password alone and still receives a session cookie + stepup token
   (`957-968`).
3. **Passkey as single factor.** `webauthn_flows.py` uses
   `user_verification=PREFERRED` (`318`) and `require_user_verification=False`
   (`341`), so an assertion with no PIN/biometric satisfies admin login.
4. **LDAP empty-bind.** `adfs.py:154` binds as the user DN with the submitted
   password and no empty/whitespace guard; a directory permitting unauthenticated
   simple bind returns success for an empty password, and the caller treats it as
   authenticated.

**Remediation**
1. Persist lockout state on the user record: after N consecutive failures write
   `locked_until = now + 1800` and refuse auth until it elapses or an admin
   re-verifies. (Replaces the window-only limiter for lockout semantics.)
2. Store the last ≥4 bcrypt hashes per user and reject reuse in all three change
   paths (`app.py:1986-1987`, `2156-2162`, `admin.py:1053-1068`).
3. Make MFA mandatory for `idpadmin`: at `admin.py:916` require a verified
   second factor whenever the account holds `idpadmin`; direct un-enrolled
   admins to enrollment rather than skipping the block.
4. Set `require_user_verification=True` and `user_verification=REQUIRED` for the
   admin passkey flow so a passkey carries two factors.
5. Reject empty/whitespace-only passwords before the LDAP bind (`adfs.py:154`)
   and before `_check_password` on the local path.

---

## F5 — No server-side absolute session lifetime (Medium) — REAL

**Verified.** `_verify_session_cookie` (`app.py:1638-1647`) passes only
`SESSION_IDLE_MAX_AGE` (30 min) to `verify_token`. `SESSION_MAX_AGE` (12h) is
used only as the browser cookie `max_age` attribute — never enforced
server-side. The docstring claims it checks "both the idle and absolute limits,"
but the code checks idle only. The cookie is re-minted on each authenticated use
(`1186`, `1201`), restarting the only enforced clock, so a cookie replayed once
per 30 minutes is valid indefinitely. `verify_token` carries no revocation
state.

**Remediation**
1. Add an immutable `auth_time` to the signed session payload at issue time,
   preserve it across re-mints, and reject the session when
   `now - auth_time > SESSION_MAX_AGE`, forcing full re-authentication.
2. Reduce `SESSION_IDLE_MAX_AGE` to 15 minutes or document the risk acceptance
   for 30.
3. Require re-authentication before `GET /admin` issues a new stepup-admin token
   on cookie re-entry (`admin.py:693`).
4. Combine with the per-user `session_epoch` from F3 for server-side revocation.

---

## F6 — Audit-logging gaps (Medium) — REAL

**Verified.** `_audit_admin` (`admin.py:512-533`) is used for most mutations
(13 call sites) but is absent on the highest-impact ones:

- `upsert_sp` (`1179-1182`), `update_sp_duration` (`1240-1243`), `delete_sp`
  (`1260`), `save_backup_config` (`1650`) emit `logger.info` only. These decide
  where signed assertions are delivered (ACS URL) and where `idp.key` is shipped.
- Credential changes are unaudited: TOTP enroll (`app.py:1904`), TOTP disable
  (`1937`), self-service password change (`2185`), recovery-link reset (`2693`)
  — contrast passkey add/remove, which *do* call `audit.log`.
- The audit-log read (`admin.py:1372`) is not itself audited.

`docs/configuration.md` and `docs/security.md` assert these are audit-logged, so
the gap also breaks a documented control.

**Remediation**
1. Add `_audit_admin(admin_user, "upsert_sp"|"update_sp_duration"|"delete_sp",
   target)` at `admin.py:1177/1240/1258` and
   `_audit_admin(admin_user, "save_backup_config", config.server)` at `1650`.
2. Add `audit.log(..., reason="totp_enrolled"/"totp_removed"/"password_changed")`
   next to the writes at `app.py:1904`, `1937`, `2185`, `2693`.
3. Record audit-log reads at `admin.py:1372`.
4. Forward `data/audit.log` off-host as `docs/security.md` already prescribes.

---

## F8 — Enforcement decided per-handler (Medium) — REAL

**Verified** — four differentials, all reproduced:

1. Account-state gate present on credential paths, missing on the session-reuse
   path and on `_has_claim` (same root cause as F3).
2. `_audit_admin` applied selectively (same as F6).
3. SP path grammar diverges: `admin.py:1157` uses Unicode-aware `.isalnum()`
   while `services.py:17` uses ASCII `^[a-zA-Z0-9_-]+$`; `/admin/user/<u>`
   (`1736-1744`) applies no charset validation on the path segment.
4. Challenge ordering: on `POST /<sp>` the captcha runs *after* the password
   check and is skipped for TOTP accounts (`app.py:1452-1461`); on `POST /admin`
   the captcha runs *before* credentials (`admin.py:857-881`).

**Remediation**
1. Fold the account-state test into `_verify_session_cookie` and extend
   `_has_claim` (resolves differentials 1 and much of F3).
2. Route every admin mutation through a wrapper that calls `_audit_admin`
   (resolves differential 2 and F6).
3. Export one path grammar: import `services._PATH_RE` into `admin.py` and call
   `_validate_username` on `<target_username>`.
4. Evaluate the captcha before `_authenticate_user` and apply it regardless of
   `totp_secret`.

---

## F10 — Multi-worker voids per-process controls (Medium) — REAL

**Verified.** The rate limiter, both nonce stores, and the WebAuthn challenge
store are per-process dicts built in `create_app` (pre-fork). The shipped
defaults run more than one process: `run_gunicorn.py` defaults `--workers` to 2
and `examples/kubernetes/deployment.yaml` sets `replicas: 2` with no shared
store or session affinity. The `Dockerfile` correctly pins `--workers 1` with
the per-process rationale in a comment, and `scripts/deploy.py` + `docs/security.md`
also require a single worker — so the launcher and k8s example contradict the
project's own stated prerequisite. Effect: the 5/60s budget becomes 5×workers,
and single-use nonces/tickets are replayable once per worker.

**Remediation**
1. Change `run_gunicorn.py` `--workers` default to 1 and
   `deployment.yaml` `replicas` to 1, documenting that scaling out requires a
   shared store.
2. Add a startup check in `create_app` that warns (or refuses) when >1
   worker/replica is detected without a shared backend.
3. Longer term, move the four stores behind an interface with a shared
   implementation (Redis, or a SQLite file in the data dir).

---

## F7 — Backups unencrypted, unsigned, over possibly-unencrypted SMB (Medium) — REAL

**Verified.** `create_archive` (`backup.py:181-214`) writes a plain `tarfile`
`w:gz` with no encryption and no digest/signature. `BACKUP_FILES` includes
`idp.key`, `users.json`, `recovery_tokens.json`, `adfs_config.yaml`, and
`backup_config.json` (which itself holds the cleartext SMB password). A grep for
`encrypt|checksum|sha256|hashlib|gpg|seal|vers=|integrity` across both backup
modules returns no matches. The CIFS mount options (`backup_cli.py:63-66`) are
`rw,uid=0,gid=0,file_mode=0600,dir_mode=0700` with no `vers=3.x` minimum and no
`seal`, so transport encryption is left to negotiation. The restore path
validates only tar member paths/types — it cannot detect tampering because no
integrity value was ever produced.

Note: the report is honest that modern `mount.cifs` usually negotiates SMB3, so
unencrypted transport is *possible* rather than *certain*. The at-rest and
integrity gaps are certain.

**Remediation**
1. Wrap the tarball in authenticated encryption (age/GPG recipient or KMS
   envelope) with the key held outside the data dir, and write a detached
   SHA-256 / AEAD tag alongside it.
2. Verify that digest/signature in `restore_archive` before any extraction;
   refuse on mismatch.
3. Add `vers=3.1.1,seal` (or `vers=3.0,seal`) to the mount options and fail the
   backup rather than falling back to an unencrypted dialect.
4. Exclude `backup_config.json` from `BACKUP_FILES` so the share's own
   credentials are not stored on the share.

---

## F9 — Supply-chain integrity (Medium) — REAL

**Verified.** `Dockerfile:15` is `RUN pip install --no-cache-dir .` — no
`-c constraints.txt`, no `--require-hashes`, no lock file; the base image is
pinned by mutable tag (`python:3.13.7-slim`), with digest pinning only noted in a
comment. `pyproject.toml` has open-ended ranges (`cryptography>=42.0`,
`pillow>=10.0`). In CI, `pip-audit -c constraints.txt || true` discards the
audit result and the gitleaks secret scan is `continue-on-error: true`, so
neither can fail the build; there is no `permissions:` block. The CI *test*
install does honour `-c constraints.txt`, so the gap is specific to the image
build and the two non-blocking scanners — `docs/security.md:81-84` states the
opposite (secret scanning should be blocking).

**Remediation**
1. In the Dockerfile, `COPY constraints.txt ./` and
   `RUN pip install --no-cache-dir -c constraints.txt .`; move to a hash-pinned
   requirements file with `--require-hashes`.
2. Pin the base image by digest as the file's own comment recommends.
3. Remove `|| true` from the pip-audit step and `continue-on-error: true` from
   the gitleaks step.
4. Add a least-privilege `permissions: { contents: read }` block to the workflow.
5. Add Dependabot/Renovate and generate an SBOM during the image build.

---

## F2 — Passkey `/begin` enumeration (Low) — REAL

**Verified.** Both begin endpoints are anonymous and return 200 (with full
WebAuthn options) only for an existing, enabled, passkey-holding account, and
400 otherwise — so 200-vs-400 enumerates account state. `admin_passkey_begin`
(`admin.py:722-753`) additionally requires `idpadmin`, so it enumerates which
accounts are administrators. Neither begin handler calls `rate_limiter.record`
on the failure path (contrast the finish handlers), so the `is_limited` check at
the top never trips from probing begin. The 200 options embed `allowCredentials`
with stored credential IDs (`webauthn_flows.py:300-321`) — not secret per the
WebAuthn spec, but still disclosed to an anonymous caller.

**Remediation**
1. Make begin responses indistinguishable: return a syntactically valid options
   object built over a deterministic dummy credential set when the account is
   unknown/ineligible; keep the real failure for finish.
2. Call `rate_limiter.record(...)` on every non-success return in both begin
   handlers so the existing `is_limited` checks engage.
3. Prefer resident-key/discoverable-credential flows that do not require a
   username up front, removing the oracle entirely.

---

## F11 — `scripts/deploy.py` committed despite gitignore (Low) — REAL

**Verified, with a precise mechanism.** `.gitignore:35` lists `scripts/deploy.py`,
but `git ls-files` shows the file is tracked and `git check-ignore` returns
nothing — because a file already tracked by git is unaffected by a later ignore
rule. So the exclusion is not an effective control. The file discloses the
production host and root-SSH pattern (`HOST = "root@rpi4"`), the public hostname
(`IDP_URL = "https://idp.botthouse.net"`), install paths/service user, the full
systemd hardening profile, and the root sudoers policy (`SUDOERS_RULE`,
`123-130`). The rsync invocation (`202-213`) has no `--exclude='scripts/'`, so
the file and sudoers text are also synced onto the production host readable by
the service account. The historical committed `SECRET_KEY` has been removed (key
now generated on-host), which is why this is Low.

**Remediation**
1. `git rm --cached scripts/deploy.py` (and purge from history if the repo is or
   may become public), keeping it in an access-controlled operator location;
   parameterise host/hostname/paths via an uncommitted config.
2. Add `--exclude='scripts/'` to the rsync invocation.
3. Add a classification statement to `docs/security.md` covering deployment
   tooling, hardening profile, and sudoers policy as Confidential.
4. Add a CI check that fails the build if a path listed in `.gitignore` is
   tracked.

---

## F12 — No incident-response communication plan (Low) — REAL

**Verified.** The workload processes PII and federates into third-party relying
parties, so a compromise of `idp.key`/`users.json` is a breach affecting every
SP and data subject. Yet `ServiceProvider` (`services.py:20-70`) carries only
delivery metadata (path, url, protocol, duration, client_id, audience, scopes,
token_expiry) with no owner/contact field, and a grep for
`smtp|sendmail|sns|pagerduty|slack|webhook|twilio|opsgenie` across all `.py`/
`.yaml` (excluding tests) returns zero matches — there is no outbound
notification channel. `docs/security-remediation-plan.md` tells an operator to
rotate credentials but names no party to inform.

Fair counter-argument (also raised by the report): for a self-hosted
single-org IdP, the notification plan could legitimately live in an external
organisational runbook. But no such rationale is documented, and the missing SP
contact field means even an external plan would lack the data to execute. This
is a design/documentation gap with no claimed exploit path.

**Remediation**
1. Add a documented notification section under `docs/` (internal escalation
   targets, per-SP owners, AD/SMB/CDN operators, regulator/data-subject
   obligations) with timelines and message templates — or document the rationale
   for delegating it externally.
2. Add an `owner_contact` field to `ServiceProvider` and the services.yaml
   loader/admin writer.
3. Provide one configurable outbound channel (webhook/SMTP) invoked on backup
   failure and on `grant_idpadmin`/restore audit events.

---

## Suggested delivery grouping

- **PR 1 (High, auth):** F3 + F8-diff1 + F5 — session-cookie account-state gate,
  `session_epoch` revocation, server-side absolute lifetime. One cohesive change
  to the session/authorization layer.
- **PR 2 (High, auth):** F1 + F4 — rate-limit key fix, single-attempt MFA ticket,
  durable lockout, password history, mandatory admin MFA, passkey UV, LDAP
  empty-bind guard.
- **PR 3 (Medium, observability):** F6 + F8-diff2/3/4 — audit coverage, shared
  path grammar, captcha ordering.
- **PR 4 (Medium, ops):** F10 + F7 — single-worker defaults + startup guard;
  encrypted/signed backups + sealed SMB.
- **PR 5 (Medium, CI/supply chain):** F9 — Dockerfile pinning, blocking scanners,
  workflow permissions.
- **PR 6 (Low):** F2 (passkey begin), F11 (deploy.py untracking + rsync exclude +
  CI gitignore check), F12 (IR comms doc + SP contact field).

Each PR should also update the contradicted docs (`docs/security.md`,
`docs/configuration.md`) so the documentation and the code agree, and add/extend
tests (including `@pytest.mark.smoke` happy-path coverage) per the project's
testing standard.
