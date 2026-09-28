# Design: Passkey (WebAuthn/FIDO2) Support

Status: **Draft for review** — no code written yet. This document proposes how
to add passkey authentication to the identity provider, grounded in the current
codebase (`identity_provider_server/app.py`, `admin.py`, `tokens.py`, `totp.py`).

## 1. Goals and non-goals

### Goals
- Let users register one or more **passkeys** (WebAuthn credentials) and use them
  to authenticate.
- Support passkeys as a **second factor** (alongside/instead of TOTP) in phase 1.
- Support **passwordless** login (username → passkey, no password) as an opt-in
  phase 2.
- Preserve every existing security property: purpose-scoped tokens, single-use
  challenges, rate limiting, forced rotation, audit logging, the CSP, and the
  100% coverage gate.

### Non-goals (initially)
- Removing TOTP or passwords. Passkeys are additive; existing factors keep working.
- Cross-device passkey sync management (that's the platform/authenticator's job).
- Usernameless/discoverable-credential "just tap" login (resident keys) — deferred
  to a later phase; phase 1 uses username-first (non-discoverable) flows.

## 2. Background: what a passkey needs

WebAuthn is a challenge-response protocol between the browser and an authenticator
(Touch ID, Windows Hello, a phone, a hardware key). Two ceremonies:

- **Registration** (`navigator.credentials.create()`): server issues a random
  challenge + RP info; the authenticator generates a keypair, returns the public
  key + a credential ID; the server stores them.
- **Authentication** (`navigator.credentials.get()`): server issues a challenge;
  the authenticator signs it with the stored private key; the server verifies the
  signature against the stored public key and checks the signature counter.

Server-side requirements this imposes on us:
- A **Relying Party ID** (`rp_id`) — our domain, `idp.botthouse.net` — and an
  **expected origin** (`https://idp.botthouse.net`). Credentials are bound to
  these; they must match exactly or every passkey breaks.
- Per-credential storage of `credential_id`, `public_key`, and `sign_count`.
- A **single-use, time-bound challenge** per ceremony — which maps directly onto
  our existing `NonceStore` primitive (`tokens.py`).
- **Client-side JavaScript** — WebAuthn has no form-only fallback.

## 3. Dependency choice

Add [`webauthn`](https://pypi.org/project/webauthn/) (the `py_webauthn` library)
to `pyproject.toml`. Rationale:
- It wraps `cryptography` (already a dependency) and handles attestation/assertion
  verification, CBOR/COSE parsing, and challenge validation — the parts that are
  dangerous to hand-roll.
- Actively maintained, widely used, ships test vectors.

Pin it in `constraints.txt` like the other deps. A software authenticator
(e.g. `soft-webauthn`) goes in the `dev`/`integration` extras for testing.

## 4. Data model

Add a `webauthn_credentials` field to the user record in `users.json`, parallel
to `totp_secret`:

```json
{
  "username": "topaz",
  "password": "$2b$12$...",
  "totp_secret": "…",                // unchanged; MFA via TOTP still works
  "webauthn_credentials": [
    {
      "credential_id": "<base64url>",
      "public_key": "<base64url COSE key>",
      "sign_count": 42,
      "transports": ["internal", "hybrid"],
      "label": "MacBook Touch ID",
      "created_at": "2026-09-28T12:00:00+00:00",
      "last_used": "2026-09-28T13:00:00+00:00"
    }
  ]
}
```

- **Presence of a non-empty `webauthn_credentials` gates the passkey path**, exactly
  as `totp_secret` gates the TOTP path today.
- All writes go through `_save_users_and_update_mtime(...)` so the content-digest
  hot-reload stays consistent.
- `sign_count` MUST be updated on every successful authentication and rejected if
  it goes backward (clone detection) — the library surfaces this.

The RP config (`rp_id`, `expected_origin`, `rp_name`) is added to `create_app`
parameters and `config.yaml`, derived from the existing domain configuration so
operators set it in one place.

## 5. Challenge handling

Reuse the existing `NonceStore` pattern. Introduce a short-lived server-side
challenge store keyed by a random handle:

- On `.../begin`: generate the WebAuthn challenge, store
  `{challenge, username, purpose}` in a `NonceStore`-backed dict with a ~120s TTL,
  and return the ceremony options as JSON (plus a handle the client echoes back).
- On `.../finish`: look up and **consume** the challenge (single-use), then verify
  the authenticator response against it.

This mirrors how the MFA ticket + `mfa_nonces` already work, so it fits the
codebase's established shape rather than introducing a new session mechanism.

## 6. Endpoints

Registered in `create_app` alongside the existing dynamic routes; all reuse the
existing CSRF double-submit pattern. Requests/responses are JSON (the ceremony
data is binary-ish, unsuited to form fields).

### Registration (self-service, on `/user`)
Gated by the existing `PURPOSE_USER` step-up token (the same gate as the TOTP
`enroll` action), so a user must have just authenticated to add a passkey.

- `POST /user/passkey/register/begin` → returns `PublicKeyCredentialCreationOptions`.
- `POST /user/passkey/register/finish` → verifies attestation, appends to
  `webauthn_credentials`, persists. Also add a `remove_passkey` action to delete one.

### Authentication (per service provider)
- `POST /<sp>/passkey/begin` → returns `PublicKeyCredentialRequestOptions` for the
  named user (username-first).
- `POST /<sp>/passkey/finish` → verifies the assertion, updates `sign_count` /
  `last_used`, then terminates in the **existing** issuance path:
  `_record_login` → forced-rotation gate → `build_saml_response` /
  `build_oauth_token` → `_set_session_cookie`.

The finish handler funnels into the same credential-issuance code the password/TOTP
flow uses, so SAML/OAuth/session behaviour is identical regardless of how the user
authenticated.

## 7. Policy model (the key decisions to confirm)

### Phase 1 — passkey as a second factor (recommended first)
Flow: `password → (passkey OR TOTP)`. Minimal disruption; passkey simply becomes
another second factor. A user with `webauthn_credentials` is offered "use a
passkey" on the second-factor step; TOTP remains as fallback.

### Phase 2 — passwordless (opt-in)
Flow: `username → passkey`, no password. This is the real UX win but interacts with
existing logic that needs care:
- `_user_can_login` gates on `must_set_password` / `enabled` / having a `password`.
  A passwordless account may have **no password** — that gate must allow login when
  a valid passkey exists.
- The no-MFA terminal path in `_handle_login_post` currently does **not** set a
  session cookie (an inconsistency the code review noted); passwordless issuance
  must set it so SSO works.
- `force_password_change` is meaningless for a passwordless account — the forced
  rotation gate needs a passkey-aware branch.

### Admin panel
`admin_post` today verifies password + single-shot TOTP + `idpadmin` in **one form
submit**. WebAuthn is inherently two-step (begin/finish), so admin passkey login
needs the two-step ceremony rather than the single-form pattern. Recommended:
keep admin on password+TOTP for phase 1, add admin passkey in a later phase to
avoid reworking the admin login contract up front.

**Decision needed before coding:** confirm phase 1 = second-factor only, phases 2/3
(passwordless, admin) as follow-ups.

## 8. CSP and client-side JavaScript

WebAuthn requires JS, and the current CSP is `script-src 'self' 'nonce-<nonce>'`
(no `unsafe-inline`). The app ships **no static assets today** — everything is
inline templates. Two viable approaches:

- **(Recommended) Static file:** add a small static-file route (or Flask static
  folder) serving `passkey.js` under `script-src 'self'`. Cleaner CSP story, cacheable,
  easier to test in isolation. Requires adding static serving (new for this app).
- **Nonce'd inline script:** thread `csp_nonce=g.csp_nonce` into the relevant
  `render_template_string` calls and use `<script nonce="{{ csp_nonce }}">`. No new
  serving mechanism, but couples JS into templates.

`connect-src`/`form-action` already resolve to `'self'`, so same-origin ceremony
posts are allowed. `img-src` already allows `data:`. No CSP relaxation of
`script-src` is needed for either approach.

## 9. Template changes
- `USER_PAGE_ENROLL`: add a "Register a passkey" button + list of registered
  passkeys with remove buttons, beside the existing TOTP section.
- `LOGIN_FORM` / `TOTP_FORM`: add a "Use a passkey" affordance (phase 1 as a
  second-factor option; phase 2 as a passwordless entry point).
- All new forms reuse the CSRF hidden-field + cookie pattern.

## 10. Security considerations
- **RP ID / origin binding:** must exactly match the public domain. Document that
  changing the domain invalidates enrolled passkeys.
- **Challenge single-use + TTL:** enforced via `NonceStore`; never accept a reused
  or expired challenge.
- **Sign-count regression:** reject assertions whose counter did not increase
  (cloned-authenticator signal), where the authenticator provides one.
- **Rate limiting:** apply the existing per-IP / per-account limiter to the
  `.../finish` endpoints.
- **Audit:** log passkey register / authenticate / remove events through the
  existing `AuditLogger`, mirroring TOTP events.
- **Account recovery:** passkeys can be lost with the device. Keep the existing
  recovery-token flow as the fallback, and require at least one non-passkey factor
  (password or TOTP) OR multiple passkeys before allowing a passwordless account,
  so a single lost device doesn't permanently lock the user out.
- **Downgrade protection:** don't let an attacker who has a password (but not the
  passkey) bypass a user's intended passkey requirement — the policy model above
  must define, per account, which factors are *required* vs *offered*.

## 11. Testing strategy (100% coverage gate applies)
- **Unit:** use a software authenticator (`soft-webauthn` or py_webauthn's test
  vectors) to drive begin/finish for both ceremonies — success, replayed challenge,
  expired challenge, wrong origin/RP, sign-count regression, unknown credential,
  malformed input. Cover the data-model read/write and the issuance funnel.
- **Smoke:** a fast in-process test of register→authenticate round-trip.
- **Integration (Playwright):** use the CDP virtual authenticator
  (`WebAuthn.addVirtualAuthenticator`) to exercise the real browser ceremony
  end-to-end against the live server.
- Every new line must be covered or carry a justified `# pragma: no cover`.

## 12. Rollout plan
1. **Phase 1 — second factor.** Dependency + data model + challenge store +
   register/authenticate endpoints (SP flow) + `/user` enrollment UI + JS + tests.
   Passkey becomes an optional second factor; nothing existing changes for users
   who don't opt in.
2. **Phase 2 — passwordless.** Adjust `_user_can_login`, the session-cookie issuance
   consistency, and the forced-rotation gate for password-less accounts; add the
   passwordless login entry point; define per-account required-factor policy.
3. **Phase 3 — admin passkeys.** Rework admin login to a two-step ceremony.

## 13. Effort estimate
- Phase 1: a few focused days. The crypto is handled by `py_webauthn`; the effort
  is the challenge store, the JS + CSP/static plumbing (new for this app), the
  enrollment/auth UI, and reaching 100% coverage (the largest single chunk).
- Phases 2 and 3: smaller, but each carries a policy/redesign decision.

## 14. Open questions for review
1. Phase 1 scope confirmed as **second-factor only**? (Recommended.)
2. Client JS as a **static file** (recommended) or **nonce'd inline**?
3. Passwordless (phase 2) desired at all, or is second-factor sufficient?
4. Minimum-factor policy for passwordless accounts (require a second passkey or a
   retained password/TOTP) to avoid lockout?
5. Any preference on `py_webauthn` vs another library?
