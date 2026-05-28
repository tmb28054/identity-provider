# identity-provider-server — Project Specification

## Purpose

A lightweight, self-hosted SAML 2.0 identity provider that federates browser-based logins into the AWS Management Console. Credentials and role mappings are stored in a local JSON file. The server signs SAML assertions with an RSA key so that AWS IAM can verify them without any external dependency.

Intended use cases: local development, CI/CD test environments, and small internal teams that need AWS console access without a full enterprise IdP.

---

## Scope and non-goals

In scope:
- Username/password authentication against a local JSON store
- ADFS/LDAP authentication with AD group-based role mapping
- Bcrypt password hashing (optional, with plaintext fallback)
- SAML 2.0 HTTP-POST binding to `https://signin.aws.amazon.com/saml`
- RSA-SHA256 signed assertions accepted by AWS IAM
- Multi-account, multi-role mappings per user
- SAML IdP metadata endpoint for AWS IAM registration
- YAML config file with layered configuration (CLI > env vars > config file > defaults)
- Configurable data directory, host, port, provider name, and session duration
- CSRF protection, rate limiting, and hot-reload of user data
- Health check endpoint for container orchestration
- Kubernetes deployment support

Out of scope:
- MFA / second factors
- SAML SP-initiated flows (AWS always initiates via the login form here)
- OAuth or OIDC backends
- User management API (users are managed by editing `users.json` directly)
- High availability or horizontal scaling

---

## Architecture

```
identity-provider-server/
├── identity_provider_server/
│   ├── __init__.py        # public API: exposes create_app and __version__
│   ├── __main__.py        # CLI entry point with structured logging
│   ├── _version.py        # parses version from CHANGELOG.md (single source of truth)
│   ├── adfs.py            # ADFS/LDAP authentication backend
│   ├── app.py             # Flask application factory (CSRF, rate limiting, hot-reload)
│   ├── config.py          # YAML config loader with layered priority
│   ├── hash_password.py   # CLI utility for bcrypt password hashing
│   └── saml_builder.py    # pure SAML assertion builder
├── data/                  # default data directory (not committed)
│   ├── config.yaml        # application configuration
│   ├── users.json         # user credentials and role mappings (local auth)
│   ├── group_roles.yaml   # AD group to AWS role mapping (ADFS auth)
│   ├── idp.crt
│   └── idp.key
├── examples/
│   └── kubernetes/        # complete K8s deployment manifests
├── docs/
│   ├── spec.md
│   ├── installation.md
│   ├── configuration.md
│   ├── howto.md
│   └── faq.md
├── tests/
│   ├── test_saml_builder.py  # unit tests — pure SAML builder function
│   ├── test_app.py           # unit tests — HTTP routes via Flask test client
│   ├── test_cli.py           # unit tests — CLI argument parsing
│   └── test_smoke.py         # smoke tests — live subprocess over HTTP
├── .gitignore
├── CHANGELOG.md           # single source of truth for version number
├── Dockerfile             # container image with HEALTHCHECK
├── docker-compose.yml     # one-command local deployment
├── LICENSE                # MIT license
├── Makefile               # common development targets
├── README.md
└── pyproject.toml         # build config, deps, entry points, ruff/mypy config
```

### Module responsibilities

**`app.py` — `create_app(data_dir, *, host, port, provider_name, session_duration_hours, ...)`**
- Reads `idp.crt` and `idp.key` from `data_dir` at startup
- In local mode: reads `users.json` and hot-reloads on each request if modified
- In ADFS mode: authenticates via LDAP and maps AD groups to AWS roles
- Implements CSRF protection (cookie + hidden form field)
- Implements per-IP rate limiting (configurable attempts per window)
- Supports bcrypt password hashes (with plaintext fallback)
- Derives `idp_entity_id` from `host` and `port` arguments
- Registers four HTTP routes (`/aws` GET/POST, `/metadata`, `/health`)
- Returns a configured Flask application instance

**`adfs.py` — `authenticate_adfs(...)`, `load_adfs_config(...)`, `load_group_role_map(...)`**
- Authenticates users against Active Directory via LDAP (ldap3 library)
- Searches for users by sAMAccountName, verifies password via user bind
- Extracts group memberships from the `memberOf` attribute
- Maps AD group CNs to AWS IAM roles via `group_roles.yaml`
- Supports TLS with optional certificate verification skip
- Prompts interactively for config values if the ADFS config file doesn't exist

**`config.py` — `load_config(data_dir, config_path)`**
- Loads YAML config file from the data directory
- Applies environment variable overrides
- Returns a typed `AppConfig` dataclass
- Supports layered priority: CLI args > env vars > config file > defaults

**`saml_builder.py` — `build_saml_response(...)`**
- Pure function: takes username, roles, cert PEM, key PEM, IdP entity ID, provider name, and session duration
- Builds and signs a SAML 2.0 Response containing a signed Assertion
- Returns a base64-encoded string ready for the `SAMLResponse` form field
- No file I/O, no Flask dependency

**`hash_password.py` — `main()`**
- CLI utility registered as `idp-hash-password`
- Generates bcrypt hashes for use in `users.json`
- Supports interactive (secure prompt) and inline modes

**`_version.py` — `__version__`**
- Parses the first `## [x.y.z]` heading from `CHANGELOG.md` at import time
- Exposes `__version__` as a string
- Used by `pyproject.toml` (`dynamic = ["version"]`) and the CLI `--version` flag
- No third-party dependencies, so setuptools can import it during build without installing Flask/lxml

**`__main__.py` — `main()`**
- Parses CLI arguments (including `--version`, `--provider-name`, `--session-duration`, `-v`)
- Configures structured JSON logging
- Calls `create_app` with all resolved arguments
- Starts the Flask development server

---

## HTTP endpoints

### `GET /health`

Returns a JSON health check response. Used by Docker HEALTHCHECK, load balancers, and monitoring.

Response: `200 OK`, `application/json`

```json
{"status": "healthy"}
```

### `GET /aws`

Returns an HTML login form with `username`, `password`, and `csrf_token` fields. Sets a `csrf_token` cookie for validation on POST.

Response: `200 OK`, `text/html`

### `POST /aws`

Authenticates the submitted credentials and, on success, returns an auto-submitting HTML form that POSTs the SAML assertion to AWS.

Request body (form-encoded):

| Field | Type | Description |
|-------|------|-------------|
| `username` | string | Must match a key in the loaded users dict |
| `password` | string | Verified against stored value (bcrypt or plaintext) |
| `csrf_token` | string | Must match the token in the `csrf_token` cookie |

Responses:

| Status | Condition |
|--------|-----------|
| `200 OK` | Credentials valid — returns HTML form that auto-POSTs to AWS ACS |
| `401 Unauthorized` | Credentials invalid — returns login form with error message |
| `403 Forbidden` | CSRF token missing or invalid |
| `429 Too Many Requests` | Rate limit exceeded (5 attempts per IP per 60s) |

On success the response body is an HTML page with:
```html
<form method="post" action="https://signin.aws.amazon.com/saml">
  <input type="hidden" name="SAMLResponse" value="<base64>">
  <input type="hidden" name="RelayState" value="">
</form>
```
The page's `onload` handler submits the form immediately.

### `GET /metadata`

Returns the SAML IdP metadata XML. Used once during AWS IAM SAML provider registration.

Response: `200 OK`, `application/xml`

The document contains:
- `EntityDescriptor` with the IdP entity ID (`http://<host>:<port>/metadata`)
- `IDPSSODescriptor` with the signing certificate
- `SingleSignOnService` pointing to `http://<host>:<port>/aws`

---

## SAML assertion structure

Every successful login produces a SAML 2.0 Response wrapping a signed Assertion. The Assertion contains:

| Element | Value |
|---------|-------|
| `Issuer` | IdP entity ID (`http://<host>:<port>/metadata`) |
| `NameID` format | `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` |
| `NameID` value | Authenticated username |
| `SubjectConfirmationData.NotOnOrAfter` | Now + session duration (default 1 hour) |
| `SubjectConfirmationData.Recipient` | `https://signin.aws.amazon.com/saml` |
| `Conditions.NotBefore` | Now (UTC) |
| `Conditions.NotOnOrAfter` | Now + session duration |
| `Audience` | `urn:amazon:webservices` |
| `AuthnContextClassRef` | `PasswordProtectedTransport` |
| `Role` attribute | One value per role: `arn:aws:iam::<account>:role/<role>,arn:aws:iam::<account>:saml-provider/<provider-name>` |
| `RoleSessionName` attribute | Authenticated username |

Signing:
- Algorithm: RSA-SHA256
- Digest: SHA-256
- Canonicalization: Exclusive C14N (`http://www.w3.org/2001/10/xml-exc-c14n#`)
- The Assertion element is signed (not the Response wrapper)
- The certificate is embedded in the `KeyInfo` of the signature

---

## Data model

### `users.json`

```json
[
  {
    "username": "string",
    "password": "string (plaintext or bcrypt hash starting with $2b$)",
    "roles": [
      {
        "account_id": "string (12-digit AWS account ID)",
        "role": "string (IAM role name)"
      }
    ]
  }
]
```

- Top-level array; zero or more user objects
- `username` must be unique within the file (first match wins if duplicated)
- `password` can be plaintext (backward compatible) or a bcrypt hash (recommended)
- `roles` may be empty (user can authenticate but AWS will reject the assertion)
- `roles` may contain entries across multiple AWS accounts
- File is hot-reloaded on each request if modified (no restart needed)

### `idp.crt` / `idp.key`

PEM-encoded RSA-2048 (minimum) X.509 certificate and private key pair. Generated with OpenSSL. The certificate is embedded in `/metadata` and must be registered in AWS IAM before logins will succeed.

---

## Configuration

Runtime configuration is loaded from a YAML config file (`config.yaml`), environment variables, and CLI arguments, merged with the following priority (highest wins):

1. CLI arguments
2. Environment variables
3. Config file (`config.yaml` in the data directory)
4. Built-in defaults

| Argument | Default | Description |
|----------|---------|-------------|
| `--version` | — | Print version (sourced from `CHANGELOG.md`) and exit |
| `--data-dir` | `<package_root>/../data` | Path to directory containing config and data files |
| `--config` | `<data-dir>/config.yaml` | Explicit path to config file |
| `--host` | `127.0.0.1` | Bind address (also used to derive IdP entity ID) |
| `--port` | `5000` | TCP port (also used to derive IdP entity ID) |
| `--debug` | `False` | Flask debug mode (auto-reload, detailed error pages) |
| `--provider-name` | `local-idp` | SAML provider name in AWS IAM |
| `--session-duration` | `1` | Assertion validity in hours (1–12) |
| `-v, --verbose` | off | Structured logging verbosity (`-v` = INFO, `-vv` = DEBUG) |
| `--adfs-config` | — | Path to ADFS config YAML. Enables ADFS/LDAP auth mode. |
| `--skip-ldap-ssl-verify` | `False` | Disable TLS certificate verification for LDAP |

Environment variables:

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Flask secret key for CSRF tokens. Auto-generated if not set. |
| `IDP_HOST` | Bind address |
| `IDP_PORT` | TCP port |
| `IDP_PROVIDER_NAME` | SAML provider name |
| `IDP_SESSION_DURATION_HOURS` | Assertion validity |
| `IDP_LOG_LEVEL` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `IDP_RATE_LIMIT_MAX_ATTEMPTS` | Rate limit threshold |
| `IDP_RATE_LIMIT_WINDOW_SECONDS` | Rate limit window |

The `idp_entity_id` and `Location` in the metadata are derived from `--host` and `--port` automatically.

---

## Dependencies

| Package | Role |
|---------|------|
| `flask` >=3.0,<4.0 | HTTP server and routing |
| `lxml` >=5.0,<6.0 | XML construction for SAML documents |
| `signxml` >=4.0,<5.0 | XML digital signature (xmldsig) |
| `bcrypt` >=4.0,<6.0 | Password hashing and verification |
| `pyyaml` >=6.0,<7.0 | YAML config file parsing |

Optional dependencies:

| Package | Extra | Role |
|---------|-------|------|
| `ldap3` >=2.9,<3.0 | `[adfs]` | LDAP communication for ADFS authentication |

Dev dependencies (installed via `pip install -e ".[dev]"`): `pytest`, `pytest-cov`, `ruff`, `mypy`

Runtime requirement: Python 3.10+

Build requirement: `setuptools>=42`

---

## Security considerations

- Passwords can be stored as bcrypt hashes (recommended) or plaintext (for quick local dev). Plaintext comparison uses constant-time `hmac.compare_digest`.
- CSRF protection prevents cross-site request forgery against the login form.
- Rate limiting (5 attempts per IP per 60 seconds) provides basic brute-force protection.
- `idp.key` must be kept secret. Anyone with the private key can issue valid SAML assertions for any user and role registered in AWS IAM.
- The server binds to `127.0.0.1` by default. Exposing it on `0.0.0.0` without TLS sends credentials over plaintext HTTP.
- SAML assertion validity is configurable (default 1 hour, max 12 hours). AWS caps SAML-federated sessions at 12 hours via `MaxSessionDuration` on the IAM role.
- `data/idp.key` and `data/users.json` should be excluded from version control (`.gitignore` provided).
- There is no account lockout (rate limiting resets after the window expires).

---

## Testing

### Test suite

Tests live in `tests/` and are run with pytest. The suite has four files split across two categories:

**Unit tests** — fast, in-process, no network:

| File | Layer | Tests |
|------|-------|-------|
| `tests/test_saml_builder.py` | `saml_builder.py` — pure function | 22 |
| `tests/test_app.py` | `app.py` — HTTP routes via Flask test client | 21 |
| `tests/test_cli.py` | `__main__.py` — CLI argument parsing | 4 |

**Smoke tests** — spawn a real subprocess, hit it over HTTP:

| File | Layer | Tests |
|------|-------|-------|
| `tests/test_smoke.py` | Fully assembled server on port 15001 | 11 |

| | **Total** | **58** |

### Running the tests

```bash
# Install dev dependencies
pip install -e ".[all]"

# Run all tests (unit + smoke)
make test

# Run only unit tests
make test-unit

# Run only smoke tests
make test-smoke

# Run with coverage report
python3 -m pytest --cov=identity_provider_server --cov-report=term-missing

# Lint
make lint
```

### What each test file covers

**`test_saml_builder.py`** — calls `build_saml_response` directly and parses the decoded XML:
- Response wrapper: tag, SAML version, `Destination`, `StatusCode`, `Issuer`
- Assertion: presence, SAML version, `NameID` value and format
- Subject: `SubjectConfirmationData.Recipient`
- Conditions: `Audience` value
- `AuthnContextClassRef` value
- Attributes: `RoleSessionName` value, role count, role ARN format, provider ARN format, correct account IDs
- Custom provider name and session duration
- Signature: element present, `SignatureValue` non-empty, certificate embedded in `KeyInfo`
- Output: result is valid base64 that decodes to an XML declaration
- No `InResponseTo` attribute on Response

**`test_app.py`** — uses Flask's test client against a real `create_app(data_dir)` instance:
- `GET /health`: status 200, JSON response with `status: healthy`
- `GET /aws`: status 200, form contains `username`, `password`, and `csrf_token` fields
- `POST /aws` (invalid): wrong password → 401, unknown user → 401, error message in response body
- `POST /aws` (missing CSRF): returns 403
- `POST /aws` (valid): status 200, `SAMLResponse` hidden field present, action points to AWS ACS URL, SAMLResponse decodes to valid XML, contains username and role
- `GET /metadata`: status 200, content-type contains `xml`, parses as valid XML, root tag is `EntityDescriptor`, contains `X509Certificate`, contains `/aws` SSO location, entity ID matches configured host/port

**`test_cli.py`** — patches `create_app` and `sys.argv`, then calls `main()` directly:
- Default invocation passes correct defaults to `create_app` and `app.run`
- `--host 0.0.0.0 --port 8080 --debug` passes the correct values through
- `--data-dir <path>` is forwarded as the first positional argument to `create_app`
- `--provider-name` and `--session-duration` are forwarded correctly

**`test_smoke.py`** — spawns `python3 -m identity_provider_server` as a subprocess on port 15001, waits for it to accept connections, then makes real HTTP requests using `urllib`:
- Process is still running after startup
- `GET /health` returns 200
- `GET /aws` returns 200 with `text/html` content-type
- `POST /aws` with bad credentials returns the error page (with CSRF flow)
- `POST /aws` with valid credentials returns a form posting to the AWS ACS URL with a `SAMLResponse` field that decodes to valid XML (with CSRF flow)
- `GET /metadata` returns 200 with `application/xml` content-type, body contains `EntityDescriptor` and `X509Certificate`

---

## Known limitations and future work

| Limitation | Notes |
|------------|-------|
| No TLS | Intended to run behind a reverse proxy for any non-localhost deployment |
| No SP-initiated flow | `InResponseTo` is omitted since there is no `AuthnRequest` to reference |
| No account lockout | Rate limiting resets after the 60-second window |
| In-memory rate limiter | Resets on server restart; not shared across processes |
| No user management API | Users are managed by editing `users.json` directly |
