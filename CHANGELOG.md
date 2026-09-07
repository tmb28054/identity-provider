# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
