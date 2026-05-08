# identity-provider-server

A lightweight local SAML identity provider for AWS console access. Reads users and role mappings from a JSON file and issues signed SAML assertions that AWS IAM trusts.

Intended for development, testing, and small internal teams — not a replacement for a production IdP.

## How it works

```
Browser → GET /aws → login form
        → POST /aws (username + password)
             → validates against users.json
             → builds signed SAML assertion
             → auto-POSTs to https://signin.aws.amazon.com/saml
             → AWS redirects to console
```

## Quick start

```bash
# 1. Install
pip install -e .

# 2. Generate a signing certificate (one-time)
make cert
# or manually:
# openssl req -x509 -newkey rsa:2048 -keyout data/idp.key -out data/idp.crt \
#   -days 3650 -nodes -subj "/CN=local-idp"

# 3. Edit data/users.json with your users and role mappings

# 4. Register the IdP in AWS IAM (see docs/installation.md)

# 5. Run
identity-provider-server --debug
# → http://localhost:5000/aws
```

## Documentation

| Doc | Contents |
|-----|----------|
| [Specification](docs/spec.md) | Architecture, data model, SAML structure, security considerations |
| [Installation](docs/installation.md) | Full install, cert generation, AWS IAM setup |
| [Configuration](docs/configuration.md) | `users.json` schema, CLI arguments |
| [How-to guides](docs/howto.md) | Adding users, multiple accounts, custom ports, running as a service |
| [FAQ](docs/faq.md) | Troubleshooting and common questions |
| [Changelog](CHANGELOG.md) | Version history and release notes |

## Running tests

```bash
pip install -e ".[dev]"

# All tests (unit + smoke)
make test

# Unit tests only (fast, no network)
make test-unit

# With coverage
python3 -m pytest --cov=identity_provider_server --cov-report=term-missing

# Lint
make lint
```

## Docker

```bash
# Build and run directly
docker build -t identity-provider-server .
docker run -v /path/to/data:/data -p 5000:5000 identity-provider-server

# Or use docker-compose
docker compose up
```

The container expects a `/data` volume containing `users.json`, `idp.crt`, and `idp.key`.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/aws` | GET | Login form |
| `/aws` | POST | Authenticate and redirect to AWS console |
| `/metadata` | GET | SAML IdP metadata XML (needed for AWS IAM registration) |
| `/health` | GET | Health check (returns `{"status": "healthy"}`) |

## License

MIT — see [LICENSE](LICENSE).
