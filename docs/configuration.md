# Configuration

## users.json

The single source of truth for authentication and authorization. Pass its parent directory to the server via `--data-dir`.

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

- The top level is a JSON array — multiple users are supported.
- `roles` is an array — a user can have access to roles across multiple accounts.
- Changes to `users.json` are picked up automatically (hot-reload on next request).
- Passwords can be plaintext (for development) or bcrypt hashes (recommended).

### Password hashing

Use the `idp-hash-password` command to generate bcrypt hashes:

```bash
# Interactive (prompts for password)
idp-hash-password

# Inline
idp-hash-password "mysecretpassword"

# Custom cost factor
idp-hash-password --rounds 14
```

Then use the output in `users.json`:

```json
{
  "username": "alice",
  "password": "$2b$12$LJ3m4sMKfXzKg1ZZfJGOXe...",
  "roles": [...]
}
```

Bcrypt is installed automatically with the server.

Plaintext passwords are still supported for backward compatibility but are not recommended for any shared environment.

### Example

```json
[
  {
    "username": "topaztest",
    "password": "$2b$12$LJ3m4sMKfXzKg1ZZfJGOXeRZqkfM3JxN...",
    "roles": [
      {
        "account_id": "711387107691",
        "role": "topaztestrole"
      }
    ]
  },
  {
    "username": "alice",
    "password": "hunter2",
    "roles": [
      {
        "account_id": "711387107691",
        "role": "ReadOnlyRole"
      },
      {
        "account_id": "222233334444",
        "role": "DevRole"
      }
    ]
  }
]
```

When a user has more than one role, AWS presents a role-selection screen after login.

## Data directory files

All three files must exist in the same directory:

| File | Description |
|------|-------------|
| `users.json` | User credentials and role mappings |
| `idp.crt` | PEM-encoded X.509 signing certificate (public) |
| `idp.key` | PEM-encoded RSA private key — keep secret |

## CLI arguments

```
identity-provider-server [OPTIONS]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `--version` | — | Print version and exit |
| `--data-dir PATH` | `./data` | Directory containing `users.json`, `idp.crt`, `idp.key` |
| `--host HOST` | `127.0.0.1` | Interface to bind to. Use `0.0.0.0` to listen on all interfaces |
| `--port PORT` | `5000` | TCP port |
| `--debug` | off | Enable Flask debug mode (auto-reload, verbose errors) |
| `--provider-name NAME` | `local-idp` | SAML provider name registered in AWS IAM |
| `--session-duration HOURS` | `1` | SAML assertion validity in hours (1–12) |
| `-v, --verbose` | off | Increase log verbosity (`-v` = INFO, `-vv` = DEBUG) |

### Examples

```bash
# Default — localhost only, port 5000
identity-provider-server

# Custom data directory
identity-provider-server --data-dir /etc/idp/

# Listen on all interfaces, port 8080
identity-provider-server --host 0.0.0.0 --port 8080

# Development mode with auto-reload and verbose logging
identity-provider-server --debug -vv

# Custom provider name and extended session
identity-provider-server --provider-name my-corp-idp --session-duration 8
```

## Environment variables

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Flask secret key for CSRF tokens. Auto-generated if not set. Set this in production for consistent behavior across restarts. |

## SAML assertion details

The assertion issued on successful login contains:

| SAML Attribute | Value |
|----------------|-------|
| `https://aws.amazon.com/SAML/Attributes/Role` | `arn:aws:iam::<account>:role/<role>,arn:aws:iam::<account>:saml-provider/<provider-name>` |
| `https://aws.amazon.com/SAML/Attributes/RoleSessionName` | The authenticated username |
| `NameID` | The authenticated username (persistent format) |

Session duration is configurable via `--session-duration` (default: 1 hour). AWS caps SAML-federated sessions at 12 hours via `MaxSessionDuration` on the IAM role.

## Security features

| Feature | Description |
|---------|-------------|
| CSRF protection | Login form includes a CSRF token validated on POST |
| Rate limiting | 5 failed login attempts per IP per 60 seconds |
| Bcrypt passwords | Optional bcrypt hashing for stored passwords |
| Constant-time comparison | Plaintext passwords use `hmac.compare_digest` |
| Structured logging | JSON-formatted logs with request context |
