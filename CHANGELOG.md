# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security (code review idp-2026-10-06)

- **Harden backup restore against unverified/unsafe archives** (High, Finding 1):
  the admin portal restore guard now accepts only integrity-protected
  `.tar.gz.enc` archives (keeping the existing `/` and `..` rejection); the
  privileged restore CLI (`backup_cli.do_restore`) fails closed, with the legacy
  plaintext fallback removed, so any archive it cannot authenticate (detached
  SHA-256 digest + Fernet tag) is refused instead of silently extracted;
  `validate_archive` now rejects members whose mode carries setuid, setgid,
  sticky, group/other-write, or other-execute bits; and `restore_archive`
  extracts with the tarfile `data` filter. See review idp-2026-10-06, Finding 1.
- **Audit-log hash chain independently keyed and verified** (Medium, F4): the
  per-record hash chain is now keyed by a dedicated `IDP_AUDIT_CHAIN_KEY`
  (config `security.audit_chain_key`) or a stable, auto-created `0600`
  `data/audit_chain.key`, never `app.secret_key`, so the chain stays verifiable
  across restarts and secret rotation. A new `AuditChainKeyError` fails closed
  if no stable key can be established. `verify_chain` now runs at startup
  (firing a `critical` `audit_chain_invalid` notification on failure) and on
  every admin audit-log render (showing an in-page integrity banner on
  failure). The stdout AUDIT mirror is redacted — the User-Agent is replaced
  with a short sha256 digest and the username is truncated — while the on-disk
  record and hash chain are byte-for-byte unchanged. `docs/security.md` now
  states a concrete 12-month retention (3 months hot) and the operator's
  rotation/WORM responsibilities; `docs/configuration.md` documents
  `IDP_AUDIT_CHAIN_KEY`. The in-memory chain cursor remains per-process
  (single-worker topology); externalising chain state is out of scope.
- **Session cookie resurrection fixed** (Medium, F5): `add_user` now stamps a
  non-zero `session_epoch` floor and `delete_user` persists a
  `data/deleted_epochs.json` tombstone (owner-only `0600`) recording the deleted
  account's last epoch. `_user_session_epoch` returns the max of the live record
  epoch and the tombstone, so a stale cookie for a deleted-then-recreated
  username no longer re-authenticates as the new principal.
- **Bearer tokens kept out of logged URLs** (Medium, F2): the admin audit-log
  link is now a POST form carrying the step-up token in the request body, and
  `GET /admin/audit-log` returns 405, so the 1-hour token is no longer written
  to the gunicorn access log. The audit-log response now sets
  `Cache-Control: no-store, no-cache, must-revalidate, max-age=0`. The OAuth
  RS256 JWT is delivered via a URL fragment (`#token=`) instead of a query
  string at all four redirect sites (SSO short-circuit GET, MFA tail, password
  tail, passkey JSON), keeping it out of access logs and the Referer header.
  The SAML auto-POST delivery path is unchanged.

### Changed (code review idp-2026-10-06)

- **`IDP_TRUST_PROXY` now defaults to `false`** (F3): `create_app` /
  `IDP_TRUST_PROXY` (new `server.trust_proxy` config field, threaded through
  both entrypoints) no longer trusts proxy forwarding headers by default, so a
  direct deployment (e.g. the `docker-compose` file that publishes `:5000`)
  keeps the real socket peer address — closing the rate-limit bypass and audit
  source-IP forgery. **Set `IDP_TRUST_PROXY=true` only when running behind a
  single trusted reverse proxy/ingress**; the Kubernetes manifest sets it
  `true` because an Ingress fronts the pod. Documented in
  `docs/configuration.md`.
- **New recommended `IDP_AUDIT_CHAIN_KEY` setting** (F4): operators should set
  a stable `IDP_AUDIT_CHAIN_KEY` (config `security.audit_chain_key`) for a
  stable, verifiable audit chain across restarts and secret rotation. When
  unset, the IdP persists an auto-created `0600` `data/audit_chain.key` and
  fails closed (`AuditChainKeyError`) if no stable key can be established.
  Documented in `docs/configuration.md`.

### Security (code review idp-20261003)

All 11 findings from the second AWS Security Agent review were validated and
remediated. See `docs/security-review-20261003-response.md`.

- **Fail closed on a weak/placeholder `SECRET_KEY`** (Critical, F5): `create_app`
  now rejects a known placeholder or a key shorter than 32 chars; a random key is
  generated only when none is supplied. `docker-compose.yml` requires the var and
  the k8s Secret ships unset with out-of-band creation guidance.
- **Durable lockout applied uniformly** (High, F6): the per-account lockout now
  also gates `/user` login, `/recover`, and admin login, with an IP-independent
  per-account bucket on the admin path.
- **Second-factor mutation hardened** (F7): TOTP enrollment binds a server-issued
  secret (no client-supplied secret), enroll/disable require the current password
  (and disable requires a current code), and admin `remove_mfa` revokes sessions.
- **Bounded rate limiter** (F1): keys are no longer created on read, empty entries
  are evicted, the key count is LRU-capped, login usernames are charset/length
  validated before becoming keys, and `MAX_CONTENT_LENGTH` caps request bodies.
- **Sensitive files written `0600`** (F8): `users.json`, `recovery_tokens.json`,
  and `audit.log` use atomic owner-only writes; the data directory is `0700`.
- **Tamper-evident audit log** (F9): hash-chained records (`verify_chain`), an
  off-host stdout mirror, loud write-failure notifications, and a step-up token
  required to read `/admin/audit-log`.
- **Non-ASCII input no longer 500s** (F2): `safe_compare` byte-compares tokens and
  CSRF values; a catch-all error handler returns a bounded, audited 500.
- **Passkey finish throttled** (F3): the SP `/passkey/finish` failure branches
  record the buckets their gate reads, plus an account-scoped gate.
- **Anti-lockout on factor removal** (F4): `remove_passkey` and `disable` refuse
  to remove the last usable factor.
- **Account lifecycle** (F11): admin `disable_user`/`enable_user` (non-destructive
  suspension, session revocation, audited); a deleted account's cookie is rejected.
- **Vulnerability management** (F10): scheduled CI scan, Trivy image/OS scan, and a
  documented risk-ranking + remediation-SLA policy in `docs/security.md`.

### Added
- `docs/security-review-20261001-response.md`: validation and remediation plan
  for the AWS Security Agent code review (idp-20261001). All 12 findings were
  re-checked against the current source and confirmed real.
- `docs/incident-response.md`: stakeholder notification plan, per-relying-party
  contacts, and outbound-channel configuration (finding F12).
- Durable per-account lockout: after repeated failures an account is locked for
  30 minutes via a persisted `locked_until`, surviving the in-memory sliding
  window and process restarts (F1/F4).
- Password history: the last 5 password hashes are retained and reuse is
  rejected on every change path (self-service, forced rotation, recovery, admin
  reset) (F4).
- Server-side absolute session lifetime and revocation: session cookies now
  carry a signed `auth_time` (12-hour hard cap, enforced server-side) and a
  per-user `session_epoch`; disabling an account, resetting its password, or
  changing its claims bumps the epoch and immediately invalidates outstanding
  cookies (F3/F5).
- Encrypted, authenticated backups: archives are Fernet-encrypted with a key
  held outside the data directory and written with a detached SHA-256; restore
  verifies both before extraction. SMB mounts now require `vers=3.1.1,seal`
  (F7).
- `identity_provider_server/notify.py`: optional outbound webhook
  (`IDP_NOTIFY_WEBHOOK`) for backup-failure and idpadmin-grant events (F12).
- `ServiceProvider.owner_contact` and a shared `services.is_valid_sp_path`
  grammar used by both the admin writer and the loader (F8/F12).
- `.github/dependabot.yml` and a CI step that fails when a `.gitignore`-listed
  path is tracked (F9/F11).
- `verify-jwt` CLI (`identity_provider_server/verify_jwt.py`): decodes a JWT,
  prints its header and claims, and validates the RS256 signature against the
  IdP's RSA public key. The key is read from a local certificate/public-key PEM
  (`--cert`) or fetched from the SAML metadata endpoint (`--metadata-url`,
  default `https://idp.botthouse.net/metadata`) by extracting the embedded
  `X509Certificate`. Supports reading the token from stdin (`-`), decode-only
  mode (`--no-verify`), and machine-readable output (`--json`). Exits `0` for a
  valid signature, `2` for an invalid or expired token, and `1` for decode or
  fetch errors.

### Changed
- Admin login now requires a second factor for every `idpadmin` account; a
  password alone is refused and the admin is directed to enroll (F4).
- Admin passkey login now requires user verification (`require_uv`), so a
  passkey counts as two factors (F4).
- Passkey `begin` endpoints return indistinguishable options for unknown or
  ineligible accounts (and record a throttle hit), removing the account- and
  admin-enumeration oracle (F2).
- The login captcha is now evaluated before the password check and applied to
  every account, including those with TOTP (F8).
- Default worker/replica count is 1 (`run_gunicorn.py`, k8s example); `create_app`
  warns when `WEB_CONCURRENCY`/`GUNICORN_WORKERS` > 1 (F10).
- Dockerfile installs against `constraints.txt` and pins the base image by
  digest; CI dependency-audit and secret-scan steps are now blocking and the
  workflow runs with least-privilege `permissions` (F9).
- `users.json` hot-reload now updates the in-memory dict in place so the admin
  blueprint never reads a stale copy after an out-of-band edit.

### Security
- TOTP second factor is no longer brute-forceable: failed codes now count
  against the rate-limit buckets that are actually checked, the MFA ticket is
  consumed before verification (one guess per ticket), and `valid_window` is
  narrowed from 2 to 1 (F1).
- Disabling an account now revokes its live SSO and admin sessions instead of
  waiting out the idle window (F3).
- LDAP/ADFS authentication rejects empty or whitespace-only passwords before
  binding, closing the unauthenticated-simple-bind path (F4).
- Admin SP-registry and backup-destination mutations, credential changes, and
  audit-log reads are now written to the audit log (F6).
- SP-registry and backup credentials (`backup_config.json`) are no longer
  included in backup archives (F7).
- `scripts/deploy.py` (production topology + sudoers policy) is untracked and
  excluded from the deployment rsync (F11).

### Fixed
- The "Enable password-less sign-in" button stayed disabled right after
  registering a first passkey (the enroll page is reached via POST and is not
  reloaded). The `register/finish` response now reports `passwordless_eligible`
  and the client re-enables the toggle in place once the account meets the
  minimum-factor policy.
- Cache-bust `passkey.js`: shortened its cache to 5 minutes and appended a
  `?v=<version>` query to every script reference so a release is never masked
  by a stale CDN/browser copy of the client script.

## [1.8.0] - 2026-09-26

### Added
- Passkey (WebAuthn/FIDO2) support — Phase 1 (second factor). Users can register
  a passkey on the Account Settings page and use it as a second factor at login
  alongside TOTP. Implemented `identity_provider_server/webauthn_flows.py`
  (ceremony core, credential data model, single-use challenge store), a
  `WebAuthnConfig` (`webauthn.enabled` / `rp_id` / `rp_name` / `expected_origin`,
  with `IDP_WEBAUTHN_*` env overrides and startup validation), JSON registration
  endpoints (`POST /user/passkey/register/begin|finish`), a `remove_passkey`
  self-service action, username-first authentication endpoints
  (`POST /<sp>/passkey/begin|finish`) that funnel into the existing SAML/OAuth
  and SSO-session issuance path, and a static client script served under the
  strict `script-src 'self'` CSP. Sign-count monotonicity rejects cloned
  authenticators. Passkeys are available in local-user mode only.
- `docs/passkey-tasks.md`: the phased implementation task breakdown derived from
  the design doc.
- End-to-end passkey integration test (`tests/integration/test_passkey_e2e.py`)
  driving register → authenticate in a real browser via the Chrome DevTools
  Protocol virtual authenticator against a self-launched local IdP.
- Passkey support — Phase 2 (password-less). Accounts can opt into password-less
  sign-in (username → passkey, no password) from the Account Settings page. An
  anti-lockout guard requires a recovery path first — two passkeys, or one
  passkey plus a password or TOTP. `_user_can_login` now admits password-less
  accounts that hold a valid passkey; the no-MFA login path issues the SSO
  session cookie consistently; and forced password rotation is skipped for
  password-less accounts. The recovery-token flow remains the fallback.
- Passkey support — Phase 3 (admin). The `/admin` login page offers a "Use a
  passkey" option backed by a two-step `POST /admin/passkey/begin|finish`
  ceremony. It re-checks the `idpadmin` claim at finish, issues the same shared
  `idp_session` as the password + TOTP form, and is per-IP/per-account
  rate-limited. The existing password + TOTP admin login is unchanged.

### Changed
- `docs/configuration.md` and `docs/howto.md` document passkey configuration,
  enrollment/use, and the domain-binding caveat (changing the served domain
  invalidates enrolled passkeys).

## [1.7.0] - 2026-09-28

### Added
- `docs/passkey-design.md`: draft design for adding passkey (WebAuthn/FIDO2)
  authentication — phased plan (second-factor → passwordless → admin), data
  model, endpoints, CSP/JS approach, and test strategy. Design only; no code yet.
- `docs/security-remediation-plan.md`: a phased plan to remediate the 25 findings
  from the 2026-09-26 pentest code review, ordered by severity and grounded in
  verified source locations.
- `docs/security.md`: data inventory/classification, threat model, and
  operational controls (time-sync, log protection, key rotation, supply chain).
- `identity_provider_server/tokens.py`: purpose-scoped, per-purpose-keyed HMAC
  tokens plus a single-use `NonceStore`.
- Per-account lockout and rate limiting on every credential endpoint
  (`/admin`, `/user`, `/recover`, and SP login), keyed on IP and username.
- Security response headers via an `after_request` hook: HSTS, a nonce-based
  Content-Security-Policy, `X-Content-Type-Options`, `Referrer-Policy`, and
  `X-Frame-Options`. All cookies are now marked `Secure` by default.
- Session inactivity timeout (30 min idle; 12 h absolute cap) with a sliding
  window on authenticated use.
- Password complexity policy (min 12 chars, ≥3 character classes) and a
  first-use `must_set_password` marker for the seeded admin.
- Account lifecycle fields on user records: `enabled`, `created_at`, `last_login`.
- Forced password rotation: a `force_password_change` flag on a user record makes
  the next successful login require a new password before any SAML/JWT/session is
  issued (handled on SP login and `/user` via a dedicated change page).
- Audit records for all privileged admin mutations (user CRUD, password reset,
  MFA removal, claim/`idpadmin` grants, SP changes, recovery-link mint).
- CSRF protection on `POST /recover`.
- `constraints.txt` for pinned, reproducible dependency installs.
- Regression tests (`tests/test_security_hardening.py`) plus a whole-tree
  secret-scan and `scripts/` bandit gate in the security smoke tests.
- 100% line-coverage requirement, enforced by the coverage gate
  (`tests/test_coverage_gate.py` and `[tool.coverage.report] fail_under = 100`).
  Added `tests/test_app_full.py`, `tests/test_admin_full.py`,
  `tests/test_entrypoints.py`, `tests/test_coverage_fill.py`, and
  `tests/test_remaining_coverage.py` to exercise every reachable branch;
  genuinely-unreachable defensive lines are marked `# pragma: no cover` with a
  justification.

### Changed
- The TOTP login step now requires a signed, single-use "password-proven"
  ticket derived from a successful password check; a TOTP code plus a
  form-supplied username can no longer mint credentials.
- Session cookie, admin token, and `/user` step-up token are now distinct,
  purpose-tagged, and signed with per-purpose keys — they are no longer
  interchangeable.
- Password verification accepts only bcrypt hashes; plaintext (or any
  non-bcrypt value) is rejected, with constant-time behaviour preserved.
- The human-verification captcha is now signed, time-bound (5 min), and
  single-use (nonce-tracked) — a captured answer can no longer be replayed.
- Backup `subpath` is charset-validated and containment-checked against the
  mount at both the writer and the privileged runner (no path traversal).
- Destructive backup restore now requires a fresh TOTP code (the replayable
  captcha alternative was removed).
- `change_password` now requires the current password.
- The backup **Enabled** toggle is now enforced by the backup runner.
- The per-account login lockout now keys on the username alone (was IP+username,
  which failed to bound password-spraying of one account across many source
  IPs); failed logins also increment an IP-level counter.
- Deployment hardening: the web app runs as an unprivileged `idp` user under a
  sandboxed systemd unit bound to loopback; the signing key is read from an
  operator-managed EnvironmentFile (no longer committed); the restore sudoers
  rule is constrained to the archive-name pattern. The Dockerfile runs as a
  non-root user with a pinned base image and a single worker. Kubernetes
  `users.json` moved from a ConfigMap to a Secret with tightened pod security.

### Fixed
- Password recovery now verifies an already-enrolled user's MFA against their
  stored TOTP secret instead of a freshly generated one. Previously the
  `/recover` page always issued a new enrollment secret and checked the entered
  code against it, so an enrolled user entering their real authenticator code
  was always rejected with "Invalid MFA code. Try again." Enrolled users are
  now required to confirm their current code (and their secret is left
  unchanged); only users without MFA are offered optional enrollment.

### Security
- Closes the pentest findings: password-skip authentication bypass (critical),
  interchangeable tokens, plaintext-password acceptance and seeded default
  credential, unthrottled credential endpoints, replayable captcha, stored XSS
  in the admin panel, backup path traversal, missing `Secure`/security headers,
  unaudited admin mutations, missing session idle timeout, and the unenforced
  backup toggle.
- Removed committed production credentials from `tests/integration/conftest.py`
  (now required via environment, tests skip if unset) and the hardcoded
  `SECRET_KEY` from the deploy script. Rotate the exposed `topaz` credentials,
  TOTP seed, and signing key out of band — they must be treated as compromised.

## [1.6.0] - 2026-09-11

### Added
- SMB backup + restore for the IdP's critical state (signing key, users, services,
  claims, config). Configure the SMB server/share/credentials on the admin
  **Backups** page (`/admin/backups`).
- Nightly backup at 02:30 (server time) via a root `idp-backup.timer`, writing
  timestamped archives to `daily/` (and `weekly/` on Sundays) on the share, with
  30-daily / 52-weekly retention pruning.
- Portal-driven restore: pick an archive, confirm with MFA/captcha, and the
  service restores (after a local pre-restore snapshot) and restarts. All
  backup/restore events are recorded in the access audit log.
- Failure banner in the admin panel and Backups page when the last backup failed.
- `backup_cli` privileged runner and systemd units (`idp-backup.service`,
  `idp-backup.timer`, `idp-restore@.service`) provisioned by `scripts/deploy.py`,
  plus a narrow sudoers rule so the unprivileged web app can trigger them.
- The configured backup subpath (including nested paths) is created on the share
  automatically if it does not already exist.
- Backup detects a read-only SMB mount (server granted the user no write access)
  and reports a clear, actionable error instead of a raw "read-only file system"
  errno. The Test connection button surfaces this immediately.

### Fixed
- SMB mount used the invalid option `ro=false`, which `mount.cifs` interpreted as
  read-only — every backup failed to write. Use the correct `rw` flag instead.

## [1.5.0] - 2026-09-07

### Added
- Admin: inline token duration editing for service providers in the SP table.
- Access audit log: all authentication attempts (success, failure, session reuse) are recorded
  as structured JSON lines in `data/audit.log`.
- Admin panel: "Audit Log" page at `/admin/audit-log` shows 500 most recent access events.
- `get-jwt` CLI: authenticates against an IdP service URL (prompting for username, password,
  captcha, and MFA) and pretty-prints the decoded JWT payload like `jq`. Use `--raw` for the
  compact token string.

### Fixed
- User changes (add, MFA, password) now immediately stable across all gunicorn workers without restart.
- Hot-reload now tracks both mtime and file size to detect same-second writes.
- Deploy script no longer overwrites live data directory on the server.

## [1.4.0] - 2026-07-04

### Added
- `/admin` panel for user and claims management (requires `idpadmin` claim).
- Admin: add/delete users, reset passwords, remove MFA, manage claims per user.
- Admin: create, update, and delete service providers from the UI.
- Admin: token duration field for service providers (SAML session / OAuth JWT expiry).
- Claims-to-AWS-roles mapping via `claim_roles.yaml` — grant AWS access by assigning claims.
- Math captcha on all login pages (`/aws`, `/user`, `/admin`).
- 12-hour session cookie after MFA login — skips re-authentication across all pages.
- Session cookie shared between `/aws`, `/admin`, and service login routes.
- Password change functionality on `/user` settings page.
- `/user` requires MFA verification when MFA is enrolled (security-sensitive page).
- Claims input pre-fills with current values when selecting a user in admin panel.
- Playwright integration test suite (27 tests) covering login, session, user, and admin flows.
- Integration tests run automatically as part of `scripts/deploy.py`.
- `[integration]` optional dependency group (`playwright`, `pytest-playwright`, `pyotp`).
- `make test-integration` Makefile target.

### Changed
- Admin login is now a single page with username, password, MFA code, and captcha (no two-step flow).
- Default `make test` now excludes integration tests (use `make test-integration` separately).

### Fixed
- Entity ID uses `https://` scheme when port is 443.
- SAML provider name correctly passed through `services.yaml` routing.
- CSRF token validation fixed for multi-worker gunicorn deployments (shared `SECRET_KEY`).
- Session cookie set on `/admin` login (not just service routes).
- YAML parse errors in admin SP loader handled gracefully (no 500).

## [1.3.0] - 2026-06-25

### Added
- TOTP-based multi-factor authentication (MFA) support.
- `/user` page for MFA enrollment — scan QR code to set up an authenticator app.
- Users with MFA enabled are prompted for a 6-digit TOTP code after password verification.
- `identity_provider_server/totp.py` module with TOTP generation, verification, and QR code support.
- `pyotp`, `qrcode`, and `pillow` dependencies for TOTP functionality.
- Ability to disable MFA from the `/user` page.
- `gunicorn` added as a core dependency for production deployments.

### Fixed
- Entity ID now uses `https://` scheme when port is 443 (proper HTTPS metadata URL).
- SAML provider name correctly passed through `services.yaml` routing (was defaulting to `local-idp`).
- CSRF token validation fixed for multi-worker gunicorn deployments (shared `SECRET_KEY`).

## [1.2.0] - 2025-05-29

### Added
- Multi-service-provider routing via `services.yaml` — define multiple SAML and OAuth service providers with dynamic route registration.
- OAuth 2.0 JWT token issuance (RS256-signed) for OAuth-type service providers.
- `identity_provider_server/services.py` module for loading and validating `services.yaml`.
- `identity_provider_server/oauth_builder.py` module for building signed JWT tokens.
- `data/services.yaml.example` with annotated examples.
- `cryptography` dependency for RSA JWT signing.
- Hot-reload of `services.yaml` on file modification.
- `/metadata` now lists `SingleSignOnService` entries for all SAML service providers.

### Changed
- `build_saml_response()` now accepts `acs_url` and `audience` parameters for configurable SP targets (defaults to AWS values for backward compat).
- Login form title is now dynamic per service provider.
- App refactored to use shared authentication logic across all service provider routes.

## [1.1.0] - 2025-05-28

### Added
- ADFS/LDAP authentication mode via `--adfs-config` CLI argument — authenticates users against Active Directory and uses group memberships as SAML claims.
- `--skip-ldap-ssl-verify` CLI flag to disable TLS certificate verification for LDAP connections (for self-signed certs).
- `identity_provider_server/adfs.py` module with LDAP bind, user search, group extraction, and group-to-role mapping.
- `group_roles.yaml` mapping file to translate AD group names to AWS IAM roles.
- Interactive config file creation — if the ADFS config file doesn't exist, the user is prompted for connection details and the file is written automatically.
- `ldap3` optional dependency (`pip install identity-provider-server[adfs]`).
- Example files: `data/adfs_config.yaml.example` and `data/group_roles.yaml.example`.
- YAML config file support (`config.yaml`) — consolidates all settings in a single file for Kubernetes and container deployments.
- `--config` CLI argument to specify an explicit config file path.
- Environment variable overrides for all configuration values (`IDP_HOST`, `IDP_PORT`, `IDP_PROVIDER_NAME`, etc.).
- Layered configuration priority: CLI args > environment variables > config file > defaults.
- Configurable rate limiting via `security.rate_limit_max_attempts` and `security.rate_limit_window_seconds`.
- Configurable data file paths (`data.users_file`, `data.certificate_file`, `data.private_key_file`) — supports absolute paths or relative to data directory.
- Kubernetes deployment examples in `examples/kubernetes/` (Namespace, ConfigMap, Secret, Deployment, Service, Ingress, Kustomization).
- `pyyaml` dependency for config file parsing.
- `identity_provider_server/config.py` module with typed `AppConfig` dataclass.
- `pip-audit` and `bandit` added to dev dependencies for security scanning.
- Smoke tests enforcing 95% code coverage, ruff lint, bandit security, and pip-audit dependency checks.

### Changed
- `create_app()` now accepts `adfs_config` and `group_role_map` keyword arguments for ADFS mode.
- `create_app()` now accepts `secret_key`, `rate_limit_max_attempts`, `rate_limit_window_seconds`, `users_file`, `certificate_file`, and `private_key_file` keyword arguments.
- `--data-dir` now also serves as the default location for `config.yaml`.
- Documentation updated to reflect ADFS support, config file support, and Kubernetes deployment.

## [1.0.0] - 2025-05-08

### Added
- Bcrypt password hashing support — passwords starting with `$2b$` are verified with bcrypt, plaintext still supported for backward compatibility.
- `idp-hash-password` CLI command to generate bcrypt hashes for `users.json`.
- CSRF protection on the login form (cookie + hidden field).
- Rate limiting on login attempts (5 attempts per IP per 60 seconds).
- Hot-reload of `users.json` — file changes are picked up automatically without restart.
- `GET /health` endpoint returning `{"status": "healthy"}` for load balancers and Docker health checks.
- `--provider-name` CLI argument to configure the SAML provider name (default: `local-idp`).
- `--session-duration` CLI argument to set assertion validity in hours (1–12, default: 1).
- `-v` / `--verbose` flag for structured JSON logging (INFO/DEBUG levels).
- `idp_entity_id` is now derived from `--host` and `--port` instead of being hardcoded.
- `docker-compose.yml` for one-command local startup.
- `Makefile` with common targets: `install`, `dev`, `test`, `lint`, `format`, `docker`, `cert`, `clean`.
- Ruff linter and formatter configuration in `pyproject.toml`.
- Mypy strict type checking configuration.
- Type hints throughout the codebase.
- `Dockerfile` `HEALTHCHECK` instruction.
- `LICENSE` file (MIT).

### Changed
- `create_app()` now accepts `host`, `port`, `provider_name`, and `session_duration_hours` keyword arguments.
- `build_saml_response()` now accepts `provider_name` and `session_duration_hours` keyword arguments.
- Dependencies are now pinned to compatible version ranges in `pyproject.toml`.
- `InResponseTo="_dummy"` removed from SAML Response (was non-compliant for IdP-initiated flows).
- Plaintext password comparison now uses constant-time `hmac.compare_digest`.
- Metadata `SingleSignOnService Location` is now derived from the configured host/port.
- `bcrypt` is now a required dependency (previously optional).

### Removed
- Hardcoded `http://localhost:5000` entity ID — now dynamic based on CLI arguments.
- Hardcoded `local-idp` provider name in SAML assertions — now configurable.

## [0.1.0] - 2025-04-19

### Added
- Flask-based SAML 2.0 identity provider for AWS console federation
- Username/password authentication against a local `users.json` file
- RSA-SHA256 signed SAML assertions with configurable signing certificate
- Multi-account, multi-role mappings per user
- `/aws` login form and SAML POST endpoint
- `/metadata` endpoint serving IdP metadata XML for AWS IAM registration
- `--data-dir` CLI argument to separate data files from package code
- `--host`, `--port`, `--debug` CLI arguments
- `create_app` Flask application factory for programmatic use
- Unit tests for SAML builder, Flask routes, and CLI argument parsing
- Smoke tests that start a real server subprocess and validate over HTTP
- Documentation: spec, installation, configuration, how-to guides, FAQ
