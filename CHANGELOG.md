# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
