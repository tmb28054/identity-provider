# identity-provider-server

A lightweight, self-hosted identity provider that federates browser-based logins into multiple service providers. Supports SAML 2.0 (e.g. AWS Console, GitLab) and OAuth 2.0 (e.g. internal docs, wikis) via a single login portal.

Intended for development, testing, and small internal teams — not a replacement for a production IdP.

## How it works

```
Browser → GET /<service> → login form
        → POST /<service> (username + password)
             → validates against users.json (or ADFS/LDAP)
             → SAML: builds signed assertion, auto-POSTs to SP
             → OAuth: issues signed JWT, redirects to SP
```

Routes are defined in `data/services.yaml`:

```yaml
saml:
  aws: https://signin.aws.amazon.com/saml
  gitlab: https://gitlab.corp.com/users/auth/saml/callback

oauth:
  docs: https://docs.botthouse.net/
```

If `services.yaml` doesn't exist, the server falls back to a single `/aws` route (backward compatible).

## Quick start

```bash
# 1. Install
pip install -e .

# 2. Initialize (generates certs, config, and example files)
identity-provider-server --init

# 3. Edit data/users.json with your users and role mappings

# 4. Register the IdP in AWS IAM (see docs/installation.md)

# 5. Run (production)
gunicorn "identity_provider_server:create_app('data')" -b 0.0.0.0:5000

# Or run in development mode (auto-reload, verbose errors)
identity-provider-server --debug
```

## ADFS mode

Authenticate against Active Directory instead of a local users file. AD group memberships are used as claims to determine AWS roles.

```bash
# Install with ADFS support
pip install -e ".[adfs]"

# Run with ADFS (prompts for config if file doesn't exist)
identity-provider-server --adfs-config data/adfs_config.yaml

# Skip LDAP TLS verification (for self-signed certs)
identity-provider-server --adfs-config data/adfs_config.yaml --skip-ldap-ssl-verify
```

See [Configuration — ADFS](docs/configuration.md#adfs-authentication-mode) for the full setup guide.

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

The container runs gunicorn with 2 workers by default. It expects a `/data` volume containing `config.yaml`, `services.yaml`, `users.json`, `idp.crt`, and `idp.key`.

## Kubernetes

Complete Kubernetes manifests are provided in `examples/kubernetes/`. The deployment uses:

- **ConfigMap** for `config.yaml` and `users.json`
- **Secret** for certificates and the Flask secret key
- **Deployment** with health checks, resource limits, and security context
- **Service** + **Ingress** for external access

```bash
# Customize and deploy
cp -r examples/kubernetes/ my-deployment/
# Edit configmap.yaml and secret.yaml with your values
kubectl apply -k my-deployment/
```

See [Configuration](docs/configuration.md) for the full config file schema and environment variable reference.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/<service>` | GET | Login form for the service (defined in `services.yaml`) |
| `/<service>` | POST | Authenticate and redirect to the service provider |
| `/metadata` | GET | SAML IdP metadata XML (lists all SAML SP paths) |
| `/health` | GET | Health check (returns `{"status": "healthy"}`) |

Without `services.yaml`, the default route is `/aws`.

## License

MIT — see [LICENSE](LICENSE).
