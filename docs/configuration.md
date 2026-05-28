# Configuration

The server reads configuration from three sources, merged in this priority order (highest wins):

1. **CLI arguments** — override everything
2. **Environment variables** — override config file values
3. **Config file** (`config.yaml`) — base configuration
4. **Built-in defaults** — fallback for any unset value

This layered approach works well for Kubernetes: store base config in a ConfigMap, inject secrets via environment variables, and use CLI args for one-off overrides.

---

## Config file (`config.yaml`)

Place a `config.yaml` in the data directory (or specify its path with `--config`). The server reads it at startup.

### Full schema

```yaml
# Server settings
server:
  host: "0.0.0.0"          # Bind address
  port: 5000               # TCP port
  debug: false             # Flask debug mode

# SAML settings
saml:
  provider_name: "local-idp"       # SAML provider name in AWS IAM
  session_duration_hours: 1        # Assertion validity (1–12 hours)

# Paths to data files (relative to config file directory, or absolute)
data:
  users_file: "users.json"         # User credentials and role mappings
  certificate_file: "idp.crt"     # PEM signing certificate
  private_key_file: "idp.key"     # PEM private key

# Logging
logging:
  level: "WARNING"                 # DEBUG, INFO, WARNING, ERROR

# Security
security:
  secret_key: ""                   # Flask CSRF secret. Empty = auto-generate.
  rate_limit_max_attempts: 5       # Failed logins before rate limiting
  rate_limit_window_seconds: 60    # Rate limit window
```

All fields are optional — omitted fields use built-in defaults.

### Minimal example

```yaml
saml:
  provider_name: "my-corp-idp"
  session_duration_hours: 4

logging:
  level: "INFO"
```

---

## Environment variables

Environment variables override config file values. Useful for injecting secrets in container environments.

| Variable | Config equivalent | Description |
|----------|-------------------|-------------|
| `IDP_HOST` | `server.host` | Bind address |
| `IDP_PORT` | `server.port` | TCP port |
| `IDP_DEBUG` | `server.debug` | `true`/`false` |
| `IDP_PROVIDER_NAME` | `saml.provider_name` | SAML provider name |
| `IDP_SESSION_DURATION_HOURS` | `saml.session_duration_hours` | Assertion validity |
| `IDP_USERS_FILE` | `data.users_file` | Path to users JSON |
| `IDP_CERTIFICATE_FILE` | `data.certificate_file` | Path to certificate |
| `IDP_PRIVATE_KEY_FILE` | `data.private_key_file` | Path to private key |
| `IDP_LOG_LEVEL` | `logging.level` | Log level |
| `SECRET_KEY` | `security.secret_key` | Flask CSRF secret key |
| `IDP_RATE_LIMIT_MAX_ATTEMPTS` | `security.rate_limit_max_attempts` | Rate limit threshold |
| `IDP_RATE_LIMIT_WINDOW_SECONDS` | `security.rate_limit_window_seconds` | Rate limit window |

---

## CLI arguments

CLI arguments have the highest priority and override both config file and environment variables.

```
identity-provider-server [OPTIONS]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `--version` | — | Print version and exit |
| `--data-dir PATH` | `./data` | Directory containing config.yaml and data files |
| `--config PATH` | `<data-dir>/config.yaml` | Explicit path to config file |
| `--host HOST` | `127.0.0.1` | Interface to bind to |
| `--port PORT` | `5000` | TCP port |
| `--debug` | off | Enable Flask debug mode |
| `--provider-name NAME` | `local-idp` | SAML provider name in AWS IAM |
| `--session-duration HOURS` | `1` | SAML assertion validity (1–12) |
| `-v, --verbose` | off | Increase log verbosity (`-v` = INFO, `-vv` = DEBUG) |
| `--adfs-config PATH` | — | Path to ADFS config YAML. Enables ADFS/LDAP auth mode. Prompts if file missing. |
| `--skip-ldap-ssl-verify` | off | Disable TLS certificate verification for LDAP connections |

### Examples

```bash
# Default — reads config.yaml from ./data/
identity-provider-server

# Custom data directory
identity-provider-server --data-dir /etc/idp/

# Explicit config file path
identity-provider-server --config /etc/idp/config.yaml --data-dir /etc/idp/

# Override host and port from CLI
identity-provider-server --host 0.0.0.0 --port 8080

# Development mode
identity-provider-server --debug -vv
```

---

## users.json

The user credentials and role mappings file. Referenced by `data.users_file` in the config.

### Schema

```json
[
  {
    "username": "<string>",
    "password": "<string — plaintext or bcrypt hash>",
    "roles": [
      {
        "account_id": "<12-digit AWS account ID>",
        "role": "<IAM role name>"
      }
    ]
  }
]
```

- Top-level JSON array — multiple users supported.
- `roles` is an array — a user can access roles across multiple accounts.
- Changes are picked up automatically (hot-reload on next request).
- Passwords can be plaintext (dev only) or bcrypt hashes (recommended).

### Password hashing

```bash
# Interactive
idp-hash-password

# Inline
idp-hash-password "mysecretpassword"

# Custom cost factor
idp-hash-password --rounds 14
```

### Example

```json
[
  {
    "username": "admin",
    "password": "$2b$12$LJ3m4sMKfXzKg1ZZfJGOXe...",
    "roles": [
      {
        "account_id": "123456789012",
        "role": "AdminRole"
      }
    ]
  },
  {
    "username": "developer",
    "password": "hunter2",
    "roles": [
      {
        "account_id": "123456789012",
        "role": "DeveloperRole"
      },
      {
        "account_id": "987654321098",
        "role": "ReadOnlyRole"
      }
    ]
  }
]
```

---

## Data directory layout

All data files live in a single directory (default: `./data`, configurable via `--data-dir`):

| File | Description |
|------|-------------|
| `config.yaml` | Application configuration (optional) |
| `users.json` | User credentials and role mappings (local auth mode) |
| `group_roles.yaml` | AD group to AWS role mapping (ADFS auth mode) |
| `adfs_config.yaml` | ADFS/LDAP connection settings (ADFS auth mode) |
| `idp.crt` | PEM-encoded X.509 signing certificate (public) |
| `idp.key` | PEM-encoded RSA private key — keep secret |

File paths in `config.yaml` can be relative (resolved against the data directory) or absolute.

---

## Kubernetes deployment

For Kubernetes, the recommended approach is:

1. **ConfigMap** — stores `config.yaml` and `users.json`
2. **Secret** — stores `idp.crt`, `idp.key`, and `SECRET_KEY`
3. **Volume mounts** — mount both into `/data` in the container

See `examples/kubernetes/` for complete manifests.

### Quick start

```bash
# Customize the examples
cp -r examples/kubernetes/ my-deployment/
# Edit configmap.yaml with your users and settings
# Edit secret.yaml with your certificates and secret key

# Deploy
kubectl apply -k my-deployment/
```

### Configuration priority in Kubernetes

```
CLI args (Dockerfile CMD)  →  highest priority
    ↓
Environment variables (from Secret)
    ↓
config.yaml (from ConfigMap)
    ↓
Built-in defaults  →  lowest priority
```

---

## SAML assertion details

The assertion issued on successful login contains:

| SAML Attribute | Value |
|----------------|-------|
| `https://aws.amazon.com/SAML/Attributes/Role` | `arn:aws:iam::<account>:role/<role>,arn:aws:iam::<account>:saml-provider/<provider-name>` |
| `https://aws.amazon.com/SAML/Attributes/RoleSessionName` | The authenticated username |
| `NameID` | The authenticated username (persistent format) |

Session duration is configurable via `saml.session_duration_hours` (default: 1 hour). AWS caps SAML-federated sessions at 12 hours via `MaxSessionDuration` on the IAM role.

---

## Security features

| Feature | Description |
|---------|-------------|
| CSRF protection | Login form includes a CSRF token validated on POST |
| Rate limiting | Configurable failed login attempts per IP (default: 5 per 60s) |
| Bcrypt passwords | Optional bcrypt hashing for stored passwords |
| Constant-time comparison | Plaintext passwords use `hmac.compare_digest` |
| Structured logging | JSON-formatted logs with request context |
| Read-only filesystem | Kubernetes deployment supports `readOnlyRootFilesystem` |

---

## ADFS authentication mode

Instead of authenticating against a local `users.json`, the server can authenticate users against Active Directory via LDAP. AD group memberships are used as claims to determine which AWS roles the user can assume.

### Enable ADFS mode

```bash
identity-provider-server --adfs-config /path/to/adfs_config.yaml
```

If the file doesn't exist, you'll be prompted interactively for the connection details and the file will be created.

### Install the ADFS dependency

```bash
pip install identity-provider-server[adfs]
```

This installs the `ldap3` library for LDAP communication.

### ADFS config file schema

```yaml
# LDAP server hostname or IP (use ldaps:// prefix for TLS)
host: "ldaps://dc01.corp.example.com"

# Service account for LDAP bind (used to search for users)
username: "CN=svc-idp,OU=Service Accounts,DC=corp,DC=example,DC=com"

# Base DN for user searches
base_dn: "DC=corp,DC=example,DC=com"

# Service account password
password: "your-service-account-password"
```

All four keys are required. If any are missing, the server exits with an error.

### Group-to-role mapping (`group_roles.yaml`)

Place a `group_roles.yaml` file in the data directory. This maps AD group CNs to AWS IAM roles:

```yaml
# AD group CN → list of AWS roles
AWS-Admins:
  - account_id: "123456789012"
    role: "AdminRole"

AWS-Developers:
  - account_id: "123456789012"
    role: "DeveloperRole"
  - account_id: "987654321098"
    role: "DeveloperRole"

AWS-ReadOnly:
  - account_id: "123456789012"
    role: "ReadOnlyRole"
```

When a user authenticates:
1. The server binds to AD with the service account to look up the user's DN and group memberships.
2. The server re-binds as the user to verify their password.
3. Group CNs are extracted from the user's `memberOf` attribute.
4. Groups are mapped to AWS roles via `group_roles.yaml`.
5. A SAML assertion is issued with all matched roles.

If a user authenticates successfully but has no matching group-to-role mappings, they receive a 403 error.

### How it works

```
Browser → POST /aws (username + password)
    → LDAP bind with service account
    → Search for user by sAMAccountName
    → LDAP bind as user (password verification)
    → Extract memberOf groups
    → Map groups → AWS roles via group_roles.yaml
    → Build signed SAML assertion with matched roles
    → Auto-POST to https://signin.aws.amazon.com/saml
```

### Example: full ADFS setup

```bash
# 1. Install with ADFS support
pip install -e ".[adfs]"

# 2. Create the ADFS config (interactive — prompts for values)
identity-provider-server --adfs-config data/adfs_config.yaml
# Or copy and edit the example:
cp data/adfs_config.yaml.example data/adfs_config.yaml

# 3. Create the group-to-role mapping
cp data/group_roles.yaml.example data/group_roles.yaml
# Edit with your AD groups and AWS roles

# 4. Run
identity-provider-server --adfs-config data/adfs_config.yaml
```

### Notes

- In ADFS mode, `users.json` is not required and not loaded.
- The signing certificate (`idp.crt` / `idp.key`) is still required for SAML assertion signing.
- The ADFS config file contains a password — keep it secure (restrict file permissions, use Kubernetes Secrets in production).
- Use `ldaps://` for the host to encrypt LDAP traffic with TLS.
- The user search uses `sAMAccountName` — users log in with their AD username (not email or UPN).
- Use `--skip-ldap-ssl-verify` to disable TLS certificate verification (e.g. for self-signed certs on the AD server). Not recommended for production.

### Skipping LDAP SSL verification

If your AD server uses a self-signed or internal CA certificate that isn't in the system trust store:

```bash
identity-provider-server --adfs-config data/adfs_config.yaml --skip-ldap-ssl-verify
```

This disables certificate validation on the LDAP connection. Only takes effect when the host uses `ldaps://`. Use this for development or when you cannot install the CA certificate on the server.
