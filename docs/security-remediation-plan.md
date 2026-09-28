# Security Remediation Plan

Derived from the pentest code review report *IdentityProvider* (dated 2026-09-26,
AWS Security Agent). That review reported **25 findings**: 1 critical, 4 high,
17 medium, 3 low.

Every finding below was re-verified against the current source in
`identity_provider_server/` before this plan was written — all are present as
reported; none has already been fixed. File/line references are the verified
current locations.

This IdP is internet-facing and mints AWS federation credentials. Treat the
critical and high findings as an active-incident checklist, not a backlog.

## Status (implementation)

Phases 1–4 have been implemented in code and documentation. The one item that
**cannot** be done in code and remains outstanding is Phase 0 — rotating the
credentials/keys that must be assumed compromised. The committed test
credentials and hardcoded `SECRET_KEY` have been removed from the tree, but the
`topaz` account password, its TOTP seed, and the SAML/JWT signing key must be
rotated on the production host out of band.

See `CHANGELOG.md` (`[Unreleased]`) for the full list of shipped changes and
`docs/security.md` for the resulting posture.

---

## Phase 0 — Immediate incident response (do first, out of band)

These involve credentials that must be assumed compromised. They cannot wait for
a code release.

1. **Rotate the leaked production credentials.** `tests/integration/conftest.py`
   commits a working production admin username, password, and TOTP seed for
   `topaz` against `https://idp.botthouse.net` (Finding 7). Anyone with repo read
   access holds a full MFA-satisfying admin credential.
   - Reset the `topaz` password and re-enroll its TOTP secret on the production
     host.
   - Rotate the `SECRET_KEY` committed in `scripts/deploy.py` (it signs every
     token, cookie, and captcha).
   - Review `data/audit.log` for use of that account and of `admin`.
2. **Rotate the SAML/JWT signing key** (`data/idp.key`) if the repo is public or
   the key ever left the host — nightly backups ship it to the configured SMB
   server (Findings 3, 5).
3. **Confirm no live deployment is running with the seeded `admin:changeme`**
   account (Finding 9). Delete or re-secure it now.

---

## Phase 1 — Critical & high severity (authentication integrity)

### 1.1 Close the password-skip authentication bypass — CRITICAL (Finding 6)
The `totp_step == "1"` branches mint credentials from a form-supplied username +
a TOTP code alone, never calling `_check_password`.
- SP login branch: `app.py:791-844` (issues SAML/JWT + session cookie).
- `/user` branch: `app.py:1146-1174` (issues the step-up `auth_token`).

**Fix.** Make the second factor unreachable without a proven first factor.
- When the password verifies and the user has a `totp_secret`, mint a signed,
  short-lived (≤120s), single-use "password-proven" ticket
  (`HMAC(secret, "mfa-pending:{username}:{ts}")`) and render *that* into
  `TOTP_FORM` instead of the plain username.
- In both `totp_step` branches, require and verify that ticket, derive the
  username from it, and reject any request that carries only `username`.
- Require the current password for `action=change_password` (`app.py:1508`+ user
  flow) so a step-up token alone cannot reset a password.

### 1.2 Separate token purposes and keys — HIGH (Finding 8)
The 12h session cookie, the 300s `/user` step-up token, and the 3600s `/admin`
token use byte-identical `HMAC(secret_key, "username:timestamp")` with one key
and no audience — so any one substitutes for the others.
- Issuers/verifiers: `admin.py:425-448`; `app.py:1037-1062`; `app.py:1066-1093`.
- `_verify_token` (`admin.py:429`) is the *only* admin authz check;
  `_has_claim` (`admin.py:449-453`) is the *only* authz predicate, hand-copied at
  eight sites.

**Fix.**
- Add a `purpose` tag to each payload (`"session"`, `"stepup-user"`,
  `"stepup-admin"`) and verify it in each verifier.
- Derive a distinct per-family signing key,
  e.g. `HMAC(secret_key, b"purpose:<tag>")`, so a token for one context can never
  sign for another.
- Replace the eight hand-copied `_has_claim(..., "idpadmin")` checks with one
  shared decorator/helper.
- Require re-authentication (and emit an audit event) before `idpadmin` can be
  granted (`admin.py:824`, `:754`, `:1492`); consider second-admin approval.

### 1.3 Remove the plaintext password path and the seeded default — HIGH (Finding 9)
`_check_password` (`app.py:412-424`) uses bcrypt only when the stored value
starts with `$2b$` and otherwise compares as cleartext. `init_project.py:238-252`
seeds `admin` / `changeme` with an AWS `AdminRole`.

**Fix.**
- Delete the `hmac.compare_digest(stored, provided)` fallback; treat any
  non-bcrypt stored value as unusable, log it, and fail authentication.
- Seed no usable password in `init_project.py` — use a `must_set_password` marker
  (or omit the field) and require `idp-hash-password`, or generate and print a
  random password once.
- Enforce a first-use password change keyed off that marker.
- Update `docs/configuration.md` to remove plaintext storage as an acceptable
  option, and move `users.json` from a Kubernetes ConfigMap to a Secret
  (`examples/kubernetes/`).
- Add complexity/history checks alongside the bare `len < 8` checks.

### 1.4 Throttle every credential endpoint and add account lockout — HIGH (Finding 1)
`_RateLimiter` (`app.py:427-443`) has one call site: `app.py:766` (SP login only).
`POST /admin` login, `POST /user` login, the `/user` `totp_step` branch, and
`POST /recover/<token>` are unthrottled, and no user record has a lockout field.

**Fix.**
- Pass `rate_limiter` into `register_admin_routes` (`app.py:1582`) and wrap the
  admin password/TOTP checks.
- Add `is_limited` / `record` to `user_page_post` (both the password check and
  the `totp_step` check) and to `recover_post`.
- Key the limiter on `(client_ip, username)` and add a per-account failed-attempt
  counter with a lock window on the user record.
- Move limiter state out of the per-process dict (shared store or single worker)
  and add `werkzeug.middleware.proxy_fix.ProxyFix` so `remote_addr` is the real
  client behind the nginx/ingress hop.

---

## Phase 2 — Medium severity (application hardening)

### 2.1 Make the captcha single-use and bound — (Finding 2)
`_generate_challenge` / `_verify_challenge` (`app.py:446-479`) are a stateless
HMAC of the answer — no nonce, expiry, or binding — so a captured pair replays
forever (~260 possible answers).
- Include a random nonce + issue timestamp in the signed material; reject pairs
  older than ~5 minutes; record consumed nonces in a short-lived server-side set.
- Bind the challenge to the CSRF token / session.
- For `restore_backup` (`admin.py:1413`+) drop the captcha alternative and
  require a fresh TOTP code (or second-admin approval) — it triggers a
  root-privileged overwrite of all auth state.

### 2.2 Contain the backup `subpath` path traversal — (Finding 3)
`subpath` is taken from the form (`admin.py:1378`) and joined onto the mount with
no containment check in `backup.py:291` and `backup_cli.py:188,228`. The existing
`_is_within` helper (`backup.py:343-348`) is applied only to tar members.
- Reject absolute or `..`-containing subpaths at the writer (`admin.py:1378`);
  accept only `^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`.
- On the root side, resolve and re-check with `_is_within(mount_dir, base)` in
  `run_backup`, restore, and test-connection.
- Narrow the `idp-restore@*.service` sudoers entry to a validated instance
  pattern (`scripts/deploy.py`).

### 2.3 Fix stored XSS in the admin panel — (Finding 4)
User-controlled values are interpolated into JS string literals inside inline
event handlers: `admin.py:154`, `:166`, `:207`, `:247`.
- Move values into HTML-escaped `data-` attributes and attach behavior from a
  single script block (no server value parsed as JS), or pass values through the
  `|tojson` filter.
- Add one shared charset validator for usernames (`^[A-Za-z0-9._@-]+$`) and
  claims (`^[a-z0-9_-]+$`) and apply it at all four writers (`add_user`,
  `set_claims`, `add_user_claim`, `add_claim`); reject nonconforming values in
  `_load_users`.
- Add a `Content-Security-Policy: default-src 'self'; script-src 'self'` header
  (depends on removing inline handlers).

### 2.4 Set the Secure flag and security headers — (Finding 10)
No `set_cookie` passes `secure=True`; there is no `after_request` hook.
- Set `SESSION_COOKIE_SECURE=True` in `create_app` and route all cookie writes
  through one helper; make it configurable off only for local dev.
- Add an `after_request` hook emitting `Strict-Transport-Security`,
  `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`.

### 2.5 Add session idle timeout and current-password proof — (Finding, session-idle)
The 12h session re-mints AWS credentials with no inactivity timeout, and password
change requires no current password.
- Track last-activity and expire idle sessions; require the current password (or
  fresh re-auth) for password change.

### 2.6 Audit privileged admin mutations — (Finding, audit-logging)
User CRUD, password reset, MFA removal, claim/`idpadmin` grants, SP changes, and
recovery-link minting emit no audit record. Add audit events to every mutating
admin action, reusing the existing `AuditLogger`.

### 2.7 Add CSRF to `POST /recover` and unify control application — (Finding, design-consistency)
`recover_post` has no CSRF check; controls are copy-pasted inconsistently.
Centralize CSRF, rate limiting, and input validation so every handler gets them
by construction rather than per-copy.

---

## Phase 3 — Low severity (correctness & lifecycle)

- **Enforce the backup "Enabled" toggle** (Finding 5): `config.enabled` is written
  (`admin.py:1379`) but never read. Add `if not config.enabled: return` at the top
  of `do_backup`/`test_connection`/`do_restore` in `backup_cli.py`.
- **Time synchronization** (Finding): document/require NTP; token expiry, TOTP,
  and audit ordering all trust the local clock.
- **Account lifecycle** (Finding): add `enabled`, `created_at`, `last_login`, and
  privilege-grant audit fields to user records so suspension/inactivity disabling
  becomes possible.

---

## Phase 4 — Governance, process & infrastructure (medium, non-code)

These are the remaining "Non-Compliant Requirement" findings. They are
organizational/process items and should be tracked as work items rather than code
diffs:

- **Least-privilege runtime** (privileged-access): stop running the web app as
  root; add `User=idp`, systemd hardening, and drop the wildcard NOPASSWD sudoers
  rule.
- **Supply-chain integrity**: pin dependencies, pin/verify the base image, produce
  an SBOM, and run vulnerability scanning in CI (not opt-in).
- **SDLC / CI gate**: add a pre-deployment security gate (lint + bandit over the
  whole tree, secret scanning); the deployer currently goes live before validating
  and validates against production.
- **Log protection & centralization**: rotate, retain, and centralize
  `audit.log`; add tamper-evidence and alerting.
- **Network protection**: add NetworkPolicy/host firewall, WAF, and traffic
  monitoring; don't publish the admin portal + root bridge on the public ingress.
- **Cryptographic agility**: add signing-key rotation, certificate renewal, and a
  crypto inventory; stop keying everything off one non-rotatable secret.
- **Data inventory & threat model**: produce a data inventory/classification, flow
  and retention docs, a threat model, and a risk register for the workload.
- **Anti-malware / integrity monitoring**: add file-integrity monitoring; fix the
  swallowed config-drift exception and validate hot-reload.

---

## Suggested sequencing

| Order | Scope | Findings |
|-------|-------|----------|
| 0 | Rotate leaked creds & signing key (out of band) | 7, 9, (3/5) |
| 1 | Auth integrity code fixes | 6, 8, 9, 1 |
| 2 | App hardening | 2, 3(XSS), 4, 10, session, audit, CSRF |
| 3 | Correctness & lifecycle | 5, time-sync, lifecycle |
| 4 | Governance / infra / CI | privileged-access, supply-chain, SDLC, network, crypto, data, anti-malware |

Each code fix should ship with a regression test (the report notes tests exist
but that `bandit` is scoped only to `identity_provider_server/`). Add a
whole-tree secret-scanning and bandit gate as part of Phase 4 so a fix in one
phase can't be undone silently later.
