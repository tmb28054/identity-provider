# Implementation Plan — Security review idp-2026-10-06, Medium findings F2–F5

Worktree: `/Users/topazb/repos/identity-provider/.worktrees/sec-f2-f5-medium`
Branch: `security/20261006-f2-f5-medium`
Environment: run `source /Users/topazb/python/py314/bin/activate` before any python/pytest/ruff/bandit.

## Hard boundary
A separate workflow owns Finding 1 (backup restore integrity) in a different worktree. DO NOT touch: the admin restore guard, `backup_cli.py` restore branch, or `backup.py` `restore_archive`/`validate_archive`/`tar.extract`. `audit.py` and the audit-chain wiring in `app.py` are in scope (Finding 4).

## Baseline (verified during exploration)
- `ruff check identity_provider_server/` → clean.
- `bandit -r identity_provider_server/` → 0 medium/high.
- `pytest` → 657 passed, 28 skipped (~76s), after copying the two gitignored fixtures `data/idp.key` and `data/users.json` from the main repo into the worktree `data/` dir (required for the test suite; they are gitignored so they will not be committed).
- Coverage gate: `pyproject.toml` sets `fail_under = 100`. Every new line needs a covering test.

## Design decisions (made here, grounded in the code)
- **F5 tombstone**: a JSON sidecar `deleted_epochs.json` in the data dir mapping `username -> last_epoch+1`. `_user_session_epoch` (app.py) returns `max(record_epoch, tombstone_value)`. `delete_user` (admin.py) bumps the epoch then writes the tombstone. Rationale: matches the existing `users.json` persisted-file pattern; survives restart; makes a recreate of a deleted username start above the deleted account's last epoch, so stale cookies (epoch 0) never re-auth. Chosen over an in-record scheme because a deleted record no longer exists to hold the value.
- **F2(c) OAuth token delivery**: use the URL **fragment** (`#token=...`) for the three 302 redirect sites and the passkey JSON `redirect`. Rationale: an auto-submitting cross-origin POST to arbitrary OAuth relying-party callback URLs is not generally viable (RP callbacks are written to read `?token`/`#token`, not to accept a POSTed form); the fragment is never sent to servers and never appears in access logs, which fixes the logged-credential problem with minimal RP-compatibility risk. Caveat documented: an RP that reads the token from the query string must switch to reading `location.hash`. The SAML POST path is unchanged.
- **F3 default**: flip `create_app(trust_proxy=...)` default to `False`; wire `IDP_TRUST_PROXY` (default False) through config and both entrypoints. Rationale: the shipped docker-compose exposes :5000 directly with no proxy, so XFF is attacker-controlled unless explicitly opted in.
- **F4 chain key**: dedicated `IDP_AUDIT_CHAIN_KEY`; if auditing is enabled and no stable key resolves, fail closed at startup (mirror `WeakSecretKeyError`). Never reuse `app.secret_key`. Verify the chain at startup and on each audit-log render; redact the stdout mirror. Retention guidance is docs-only.

---

## Finding 5 — Session cookie resurrection

- [ ] 1. Add the deletion-tombstone helpers and wire the epoch read to consult them.
      In `app.py` `_user_session_epoch` (~line 2018), read `deleted_epochs.json` from the data dir and return `max(int(user.get("session_epoch", 0)), tombstone.get(username, 0))`. Add a small module/closure helper `_load_deleted_epochs()` that reads the sidecar (returns `{}` on missing/corrupt). The function already closes over `data` (the data_dir `Path`); use `data / "deleted_epochs.json"`.
      Files: `identity_provider_server/app.py`
      Verify: `source .../activate && pytest tests/test_security_remediation_20261003.py -q` passes (existing F11 deleted-cookie test still green).

- [ ] 2. In `admin.py` `add_user` (~line 1200), set `"session_epoch": int(time.time())` on `new_user` so a recreated username never starts at 0. (`time` is already imported.)
      Files: `identity_provider_server/admin.py`
      Verify: `pytest tests/test_admin_full.py -q` passes.

- [ ] 3. In `admin.py` `delete_user` (~line 1221), call `_bump_session_epoch(target)` BEFORE `del users[target]`, then write/update the tombstone sidecar: `deleted_epochs[target] = max(existing, user_epoch_after_bump)`. Thread the data dir via the existing `data_dir` arg already passed to `register_admin_routes` (admin.py captures `data_dir: Path | None`). Add a `_write_deleted_epoch(target, epoch)` helper in admin.py that reads/merges/writes `deleted_epochs.json` 0600, following the `save_users_fn` persistence pattern. Guard on `data_dir is not None`.
      Files: `identity_provider_server/admin.py`
      Verify: `pytest tests/test_admin_full.py -q` passes.

- [ ] 4. Add tests: in `tests/test_security_remediation.py` (or a new `tests/test_security_remediation_20261006.py`) assert (a) `add_user` creates a record with a non-zero `session_epoch`; (b) delete→recreate of the same username writes `deleted_epochs.json` and a cookie minted at epoch 0 for the recreated user is rejected by `_verify_session_cookie`. Add one `@pytest.mark.smoke` test covering the delete-then-recreate happy path.
      Files: `tests/test_security_remediation_20261006.py` (new) or extend `tests/test_security_remediation.py`
      Verify: `pytest tests/test_security_remediation_20261006.py -q` passes; `pytest -m smoke -q` includes the new smoke test.

---

## Finding 2 — Bearer credentials in URL query strings

- [ ] 5. Convert the audit-log link to a POST form. In the `ADMIN_PANEL` template (admin.py ~line 149) replace the `<a href="/admin/audit-log?auth_token={{ auth_token }}">Audit Log</a>` with a `method="post" action="/admin/audit-log"` form carrying hidden `csrf_token` and `auth_token` inputs plus a submit styled as the link (mirror the existing inline action forms).
      Files: `identity_provider_server/admin.py`
      Verify: `pytest tests/test_admin_full.py -q` (after step 6/7) passes.

- [ ] 6. Change the handler `admin_audit_log_get` (admin.py ~line 1596) from `@app.get("/admin/audit-log")` to `@app.post("/admin/audit-log")`, rename appropriately, read the token from `request.form.get("auth_token", "")` (keep the `_require_admin` step-up gate), and wrap the render in `app.make_response(...)` so a header can be set. Add `resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"` (matches admin.py lines 798/827/1517/1821).
      Files: `identity_provider_server/admin.py`
      Verify: `pytest tests/test_admin_full.py -q` passes.

- [ ] 7. Update the existing audit-log tests that use GET. In `tests/test_admin_full.py` the test at ~line 837 does `client.get(f"/admin/audit-log?auth_token={auth}")` — change to a POST with `csrf_token` + `auth_token` in the body; keep the no-session / no-step-up redirect tests but switch them to POST. Add a test asserting a GET to `/admin/audit-log` now returns 405.
      Files: `tests/test_admin_full.py`
      Verify: `pytest tests/test_admin_full.py -q` passes.

- [ ] 8. Move the OAuth JWT out of the query string at all four sites in `app.py`. Replace `f"{sp.url}{separator}token={token}"` with a fragment form `f"{sp.url}#token={token}"` at: the SSO short-circuit GET (~1512), the MFA tail (~1715), the password tail (~1930), and the passkey tail JSON `redirect` (~2878). Drop the now-unused `separator` locals at those sites. Leave the SAML POST paths untouched.
      Files: `identity_provider_server/app.py`
      Verify: `pytest tests/test_app_full.py tests/test_multisp_functional.py -q` passes.

- [ ] 9. Update `static/passkey.js` for the fragment delivery. The login handler does `window.location.href = result.redirect` (~line near `wireLoginButton`); the server now returns a URL already containing `#token=...`, so assigning it to `location.href` still works. Confirm no JS change is required beyond a comment; if the server instead returns the token separately, adjust. (Design: server returns the full fragment URL, so passkey.js is unchanged except a clarifying comment.)
      Files: `identity_provider_server/static/passkey.js`
      Verify: `pytest tests/test_passkey_endpoints.py tests/test_admin_passkey.py -q` passes.

- [ ] 10. Add tests asserting the OAuth token is no longer in the query string. For each of the four flows, assert the 302 `Location` (or passkey JSON `redirect`) contains `#token=` and NOT `?token=`/`&token=`. Follow the OAuth-SP fixtures already in `tests/test_app_full.py` / `tests/test_multisp_functional.py`. Add a `@pytest.mark.smoke` test for the primary OAuth login → fragment redirect happy path.
      Files: `tests/test_app_full.py` (extend) and/or `tests/test_security_remediation_20261006.py`
      Verify: `pytest -q` for the touched test files passes; `pytest -m smoke -q` includes the new smoke test.

---

## Finding 3 — X-Forwarded-For trusted unconditionally

- [ ] 11. Add the config setting + env override. In `config.py` `_DEFAULTS["server"]` add `"trust_proxy": False`; add a `ServerConfig.trust_proxy: bool = False` field; add `"IDP_TRUST_PROXY": ("server", "trust_proxy")` to the `env_map` (~line 175). The loader already bool-coerces from the default's type.
      Files: `identity_provider_server/config.py`
      Verify: `pytest tests/test_config.py -q` passes.

- [ ] 12. Flip the `create_app` default. In `app.py` (~line 989) change `trust_proxy: bool = True` to `trust_proxy: bool = False` and update the docstring line (~1014) to say it defaults to False / opt-in behind a trusted proxy.
      Files: `identity_provider_server/app.py`
      Verify: `pytest tests/test_app_full.py tests/test_security_remediation_20261003.py -q` passes (these set `trust_proxy=False` explicitly, so unaffected).

- [ ] 13. Thread the resolved value through both entrypoints. In `__main__.py` and `run_gunicorn.py` add `trust_proxy=config.server.trust_proxy` to the `create_app(...)` call (next to `secure_cookies`/host/port threading).
      Files: `identity_provider_server/__main__.py`, `identity_provider_server/run_gunicorn.py`
      Verify: `pytest tests/test_entrypoints.py tests/test_cli.py tests/test_cli_extended.py -q` passes.

- [ ] 14. Docs + deployment. In `docker-compose.yml` add a comment that `IDP_TRUST_PROXY` must stay false unless a trusted reverse proxy fronts the service. In `examples/kubernetes/configmap.yaml` set `server.trust_proxy: true` (an ingress fronts it) OR add `IDP_TRUST_PROXY=true` to the deployment env in `examples/kubernetes/deployment.yaml` — pick the env form to match the Secret-injection convention; document the choice. Add the `IDP_TRUST_PROXY` row to the env-var table in `docs/configuration.md`.
      Files: `docker-compose.yml`, `examples/kubernetes/configmap.yaml` or `examples/kubernetes/deployment.yaml`, `docs/configuration.md`
      Verify: `yamllint`/manual read; `pytest -q` unaffected.

- [ ] 15. Add a config-resolution test: `trust_proxy` is False by default and True when `IDP_TRUST_PROXY=true` (monkeypatch env). Follow `tests/test_config.py` style. Add a `@pytest.mark.smoke` test if the config happy path lacks one.
      Files: `tests/test_config.py`
      Verify: `pytest tests/test_config.py -q` passes.

---

## Finding 4 — Audit log integrity / retention

- [ ] 16. Add `IDP_AUDIT_CHAIN_KEY` config/env. In `config.py` add `security.audit_chain_key: ""` default, a `SecurityConfig.audit_chain_key: str = ""` field, and `"IDP_AUDIT_CHAIN_KEY": ("security", "audit_chain_key")` in the env map.
      Files: `identity_provider_server/config.py`
      Verify: `pytest tests/test_config.py -q` passes.

- [ ] 17. Key the audit chain with a dedicated value and fail closed. In `app.py` where `AuditLogger(data_dir, chain_key=app.secret_key, ...)` is built (~line 1246): resolve the chain key from an `audit_chain_key` param threaded into `create_app` (default `""`, env `IDP_AUDIT_CHAIN_KEY`). If empty, derive a STABLE per-deployment key that does NOT reuse `app.secret_key` (e.g. read/create a `data/audit_chain.key` 0600 random file); if a stable key cannot be established while auditing is enabled, raise a clear startup error mirroring `WeakSecretKeyError` (add `AuditChainKeyError` or reuse the pattern). Add the `audit_chain_key` kwarg to `create_app` and thread it from both entrypoints (config.security.audit_chain_key).
      Files: `identity_provider_server/app.py`, `identity_provider_server/__main__.py`, `identity_provider_server/run_gunicorn.py`
      Verify: `pytest tests/test_app_full.py tests/test_security_remediation_20261003.py -q` passes.

- [ ] 18. Invoke `verify_chain`. At startup after constructing the `AuditLogger`, call `audit.verify_chain()`; on failure log an error and fire `notify.notify(...)` (reuse the `_audit_write_failed` notify wiring, ~lines 1240–1251). In the audit-log render handler (admin.py, after F2 moves it to POST) call `audit_logger.verify_chain()` and surface an integrity warning banner in `ADMIN_AUDIT_LOG` when it fails (pass a flag to the template). Note the multi-worker `_seq/_last_hash` caveat in a comment (out of scope; single-worker topology).
      Files: `identity_provider_server/app.py`, `identity_provider_server/admin.py`
      Verify: `pytest tests/test_admin_full.py -q` passes.

- [ ] 19. Redact/truncate the stdout mirror in `audit.py` (~lines 180–187). Keep the on-disk JSON record full-fidelity; for the `sys.stdout.write("AUDIT " + ...)` mirror, emit a line with the User-Agent hashed (sha256, short hex) or omitted and the username truncated (e.g. first 3 chars + length). Do not change the structured on-disk payload or the hash chain.
      Files: `identity_provider_server/audit.py`
      Verify: `pytest tests/test_security_remediation_20261003.py tests/test_remaining_coverage.py -q` passes.

- [ ] 20. Retention docs. In `docs/security.md` replace the "Per retention policy" placeholder (~line 17, audit log row) with concrete guidance: 12 months retained, 3 months immediately queryable; note rotation + external append-only forwarding is the operator's responsibility. Add `IDP_AUDIT_CHAIN_KEY` to the `docs/configuration.md` env-var table.
      Files: `docs/security.md`, `docs/configuration.md`
      Verify: manual read.

- [ ] 21. Add audit-integrity tests in a new `tests/test_audit_integrity.py`: (a) a configured `IDP_AUDIT_CHAIN_KEY` is used as the chain key and is independent of `app.secret_key`; (b) startup with a tampered `audit.log` triggers the notify callback / logs an error; (c) the audit-log admin render shows the integrity banner when the chain is broken; (d) the stdout mirror does not contain the full User-Agent or full username while the on-disk record does. Add a `@pytest.mark.smoke` test for the chain-key resolution + a clean `verify_chain()` happy path.
      Files: `tests/test_audit_integrity.py` (new)
      Verify: `pytest tests/test_audit_integrity.py -q` passes; `pytest -m smoke -q` includes the new smoke test.

---

## Finding 2–5 — Changelog & final gate

- [ ] 22. Update `CHANGELOG.md` under `## [Unreleased]`: `### Security` entries for F2 (token out of URLs + audit-log cache suppression + POST), F4 (dedicated audit chain key, startup+render verification, stdout redaction), F5 (session resurrection fix). `### Changed` entries for the `trust_proxy` default flip (F3, deployment-impacting) and the new required/recommended `IDP_AUDIT_CHAIN_KEY` (deployment-impacting). Reference review `idp-2026-10-06`. Do NOT create the overall security-review response doc.
      Files: `CHANGELOG.md`
      Verify: manual read.

- [ ] 23. Full project gate. Run the complete suite and linters.
      Verify: `source /Users/topazb/python/py314/bin/activate && cd <worktree> && ruff check identity_provider_server/ && bandit -r identity_provider_server/ -q && pytest --cov=identity_provider_server --cov-report=term-missing -q` — ruff clean, bandit 0 medium+, all tests pass, coverage 100% (`fail_under=100`). (Ensure `data/idp.key` and `data/users.json` are present in the worktree `data/` from the main repo; they are gitignored and must not be committed.)
