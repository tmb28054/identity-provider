# Passkey Implementation — Task Breakdown

Derived from [`docs/passkey-design.md`](./passkey-design.md). Tasks are grouped
by the design's three phases and ordered by dependency. Each task lists its
intent, the concrete code seams it touches (from the design's architecture map),
and its acceptance criteria. The project's **100% coverage gate** applies to
every task that adds code — tests are part of the task, not a follow-up.

## Decisions that gate the work (design §14)

These must be answered before Phase 1 coding starts; the recommended defaults
are assumed by the task list below. If a decision changes, the affected tasks
change with it.

- **D1. Phase 1 scope = second factor only.** (Recommended.) Assumed by P1.*.
- **D2. Client JS delivery = static file** served under `script-src 'self'`.
  (Recommended.) Drives task P1.2.
- **D3. Passwordless (Phase 2) wanted?** If no, P2.* is dropped.
- **D4. Passwordless lockout policy** — require a second passkey or a retained
  password/TOTP. Drives P2.4.
- **D5. Library = `py_webauthn`.** (Recommended.) Drives P1.1.

---

## Phase 0 — Groundwork (shared by all phases)

### P0.1 — Add the WebAuthn dependency
- Add `webauthn` (py_webauthn) to `pyproject.toml` runtime deps; pin an exact
  version in `constraints.txt`. Add `soft-webauthn` to the `dev`/`integration`
  extras for tests.
- Acceptance: `pip install -e ".[dev]" -c constraints.txt` succeeds; `pip-audit`
  clean; the import works in a smoke import test.

### P0.2 — RP configuration
- Add `rp_id`, `rp_name`, `expected_origin` to `create_app(...)` params and to
  `config.yaml` (+ `config.py` `SecurityConfig` or a new `WebAuthnConfig`),
  derived from the existing domain config so operators set it once.
- Validate at startup that `expected_origin` scheme/host is consistent with
  `rp_id`.
- Acceptance: config round-trips; unit tests cover default, file, and env
  precedence; missing/mismatched values raise a clear error.

### P0.3 — Data model helpers
- Define the `webauthn_credentials` record shape (design §4) and small helpers
  to read/append/remove/update a credential on a user dict, writing through
  `_save_users_and_update_mtime` so hot-reload stays consistent.
- `sign_count` update + monotonicity check helper.
- Acceptance: unit tests for add/remove/update, sign-count regression rejection,
  and that a user with no `webauthn_credentials` is unaffected.

### P0.4 — Challenge store
- Add a short-lived, single-use challenge store backed by the existing
  `NonceStore` pattern (design §5): `{handle -> (challenge, username, purpose)}`
  with ~120s TTL, consumed on `finish`.
- Acceptance: unit tests for issue/consume, replay rejection, expiry.

---

## Phase 1 — Passkey as a second factor (D1)

### P1.1 — WebAuthn ceremony core (server)
- A module (e.g. `webauthn_flows.py`) wrapping py_webauthn:
  `begin_registration`, `finish_registration`, `begin_authentication`,
  `finish_authentication`, using P0.2 config and P0.4 challenge store.
- Acceptance: unit tests with `soft-webauthn` covering success, wrong
  origin/RP, replayed/expired challenge, sign-count regression, unknown
  credential, malformed input.

### P1.2 — Static JS + serving + CSP
- Add static-file serving (new for this app) and ship `passkey.js` implementing
  the `navigator.credentials.create()/get()` ceremonies against the endpoints.
- Confirm it loads under the existing `script-src 'self'` CSP with no relaxation.
- Acceptance: the static route serves the file with the right content-type and
  cache headers; a test asserts CSP is unchanged and the script is `'self'`.

### P1.3 — Registration endpoints (`/user`)
- `POST /user/passkey/register/begin` and `.../finish`, gated by the existing
  `PURPOSE_USER` step-up token (same gate as TOTP `enroll`); append to
  `webauthn_credentials` on success. Add a `remove_passkey` action.
- Reuse the CSRF double-submit pattern; JSON request/response.
- Acceptance: register + remove round-trip tests; unauthorized (no step-up
  token) rejected; audit events emitted; rate limiting applied.

### P1.4 — Authentication endpoints (SP flow)
- `POST /<sp>/passkey/begin` and `.../finish` (username-first). `finish`
  verifies the assertion, updates `sign_count`/`last_used`, then funnels into
  the **existing** issuance path: `_record_login` → forced-rotation gate →
  `build_saml_response`/`build_oauth_token` → `_set_session_cookie`.
- Wire as a second-factor option after the password step (design §7 Phase 1):
  a user with `webauthn_credentials` is offered "use a passkey"; TOTP remains
  the fallback.
- Acceptance: full password→passkey login issues SAML and OAuth identically to
  password→TOTP; sign-count regression rejected; rate limiting on `finish`;
  audit events.

### P1.5 — Templates / UI
- `USER_PAGE_ENROLL`: "Register a passkey" button + list of registered passkeys
  with remove buttons, beside the TOTP section.
- `LOGIN_FORM` / `TOTP_FORM`: "Use a passkey" affordance as a second-factor
  option. All forms reuse the CSRF pattern.
- Acceptance: rendered pages include the controls; CSRF present; no inline JS
  that violates CSP.

### P1.6 — Docs + changelog
- Update `docs/configuration.md` (RP config, enabling passkeys) and
  `docs/howto.md` (enroll/use a passkey); mark passkey-design Phase 1 done in the
  changelog `[Unreleased]`.
- Acceptance: docs describe setup and the domain-binding caveat (changing the
  domain invalidates passkeys).

### P1.7 — Integration test (Playwright virtual authenticator)
- Use CDP `WebAuthn.addVirtualAuthenticator` to drive register→authenticate
  end-to-end against the live server in the integration suite.
- Acceptance: green in the integration suite (network-gated, like the others).

---

## Phase 2 — Passwordless login (D3, D4)

### P2.1 — Account policy model
- Per-account "required vs offered" factor policy (design §7/§10 downgrade
  protection). Define where it lives on the user record and how admin sets it.
- Acceptance: policy read/write + tests; default preserves current behaviour.

### P2.2 — `_user_can_login` for password-less accounts
- Allow login when the account has a valid passkey but no `password`, without
  weakening the existing `enabled`/`must_set_password` gates for others.
- Acceptance: tests for password-less-with-passkey allowed, disabled blocked,
  password accounts unchanged.

### P2.3 — Session-cookie issuance consistency
- Fix the no-MFA terminal path in `_handle_login_post` to set the session cookie
  (the code-review inconsistency), so passwordless issuance establishes SSO.
- Make the `force_password_change` gate passkey-aware (meaningless without a
  password).
- Acceptance: passwordless login sets `idp_session`; forced-rotation no longer
  applies to password-less accounts; existing flows unchanged.

### P2.4 — Passwordless entry point + lockout guard (D4)
- Username→passkey login entry point; enforce the minimum-factor policy (require
  a second passkey or retained password/TOTP) before an account can go
  passwordless, so a single lost device can't permanently lock a user out.
- Keep the recovery-token flow as fallback.
- Acceptance: lockout guard tested; recovery still works; audit events.

---

## Phase 3 — Admin passkeys

### P3.1 — Admin two-step ceremony
- Rework `admin_post` login from single-form password+TOTP+idpadmin to support
  the two-step WebAuthn begin/finish, preserving the `idpadmin` authorization
  check and the shared `idp_session` issuance.
- Acceptance: admin passkey login works; password+TOTP still works; `idpadmin`
  still enforced; sensitive ops (e.g. backup restore) re-verification preserved.

---

## Cross-cutting (applies to every code task)
- **Coverage:** 100% line coverage maintained; unreachable defensive lines carry
  a justified `# pragma: no cover`.
- **Lint/security:** ruff clean; bandit (medium+) clean on package and scripts.
- **Audit:** register / authenticate / remove events logged via `AuditLogger`,
  mirroring TOTP events.
- **Rate limiting:** existing per-IP / per-account limiter applied to `finish`
  endpoints.
- **No regressions:** existing password/TOTP/SAML/OAuth/admin flows unchanged for
  users who don't opt into passkeys.

## Suggested sequencing
P0.1 → P0.2 → P0.3 → P0.4 → P1.1 → P1.2 → P1.3 → P1.4 → P1.5 → P1.6 → P1.7,
then (if D3=yes) P2.1 → P2.2 → P2.3 → P2.4, then P3.1.

Ship Phase 1 as its own release; it is self-contained and changes nothing for
users who don't enroll a passkey.
