"""Interactive project initialization.

Generates signing certificates, config files, and example data for a new
identity-provider-server deployment.
"""

from __future__ import annotations

import subprocess  # nosec B404
import sys
from pathlib import Path


def _extract_cn_from_cert(cert_path: Path) -> str:
    """Extract the CN from an existing certificate, falling back to 'local-idp'."""
    try:
        result = subprocess.run(  # nosec B603 B607
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-subject"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            subject = result.stdout.strip()
            # Formats: "subject=CN = value" or "subject= /CN=value"
            if "CN=" in subject or "CN =" in subject:
                # Handle "CN = value" format
                part = subject.split("CN")[-1]
                # Strip leading '=' or ' = '
                cn = part.lstrip(" =").strip()
                # Handle cases like "CN=value/O=org" — take only CN part
                if "/" in cn:
                    cn = cn.split("/")[0].strip()
                if cn:
                    return cn
    except OSError:
        pass
    return "local-idp"


def run_init(data_dir: str) -> None:
    """Run the interactive init process.

    Creates:
      - idp.crt / idp.key (signing certificate)
      - config.yaml (server configuration with commented examples)
      - services.yaml (service provider routing with AWS defined)
      - users.json (example user)

    Args:
        data_dir: Path to the data directory to initialize.
    """
    data = Path(data_dir)
    data.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("  identity-provider-server — Project Initialization")
    print("=" * 60)
    print()

    # --- Generate signing certificate ---
    cert_path = data / "idp.crt"
    key_path = data / "idp.key"

    if cert_path.exists() and key_path.exists():
        print(f"✓ Signing certificate already exists: {cert_path}")
        # Try to extract CN from existing cert for use as provider_name
        cn = _extract_cn_from_cert(cert_path)
    else:
        cn = input("  Certificate CN (e.g. local-idp, my-corp-idp): ").strip()
        if not cn:
            cn = "local-idp"
            print(f"    Using default: {cn}")

        print(f"  Generating RSA-2048 certificate with CN={cn}...")
        result = subprocess.run(  # nosec B603 B607
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path),
                "-out", str(cert_path),
                "-days", "3650",
                "-nodes",
                "-subj", f"/CN={cn}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            print(f"  ERROR: openssl failed:\n{result.stderr}", file=sys.stderr)
            sys.exit(1)
        print(f"  ✓ Created: {cert_path}")
        print(f"  ✓ Created: {key_path}")

    print()

    # --- Create config.yaml ---
    config_path = data / "config.yaml"
    if config_path.exists():
        print(f"✓ Config file already exists: {config_path}")
    else:
        config_path.write_text(_CONFIG_TEMPLATE.format(provider_name=cn))
        print(f"  ✓ Created: {config_path}")

    print()

    # --- Create services.yaml ---
    services_path = data / "services.yaml"
    if services_path.exists():
        print(f"✓ Services file already exists: {services_path}")
    else:
        services_path.write_text(_SERVICES_TEMPLATE.format(provider_name=cn))
        print(f"  ✓ Created: {services_path}")

    print()

    # --- Create users.json ---
    users_path = data / "users.json"
    if users_path.exists():
        print(f"✓ Users file already exists: {users_path}")
    else:
        # Seed the credential store 0600 (not world-readable) — it will hold
        # bcrypt hashes and TOTP secrets (finding idp-20261003 F8).
        from .app import _atomic_write_private
        _atomic_write_private(users_path, _USERS_TEMPLATE)
        print(f"  ✓ Created: {users_path}")

    print()

    # --- Done ---
    print("=" * 60)
    print("  Initialization complete!")
    print("=" * 60)
    print()
    print("  Next steps:")
    print()
    print(f"  1. Edit {services_path}")
    print("     Define your service providers (AWS is pre-configured).")
    print()
    print(f"  2. Edit {users_path}")
    print("     Add your users and role mappings.")
    print("     Hash passwords with: idp-hash-password")
    print()
    print("  3. Register the IdP in AWS IAM:")
    print("     identity-provider-server")
    print("     curl http://localhost:5000/metadata -o metadata.xml")
    print(f"     aws iam create-saml-provider --name {cn} \\")
    print("       --saml-metadata-document file://metadata.xml")
    print()
    print("  4. Start the server:")
    print()
    print(f"     gunicorn \"identity_provider_server:create_app('{data}')\" -b 0.0.0.0:5000")
    print()
    print("     Or for development (auto-reload):")
    print(f"     identity-provider-server --data-dir {data} --debug")
    print()


_CONFIG_TEMPLATE = """\
# identity-provider-server configuration
# Documentation: docs/configuration.md

# Server settings
server:
  host: "127.0.0.1"      # Use "0.0.0.0" to listen on all interfaces
  port: 5000
  debug: false

# SAML defaults (applied to all SAML SPs unless overridden in services.yaml)
saml:
  provider_name: "{provider_name}"
  session_duration_hours: 1

# Paths to data files (relative to this directory, or absolute)
data:
  users_file: "users.json"
  certificate_file: "idp.crt"
  private_key_file: "idp.key"

# Logging
logging:
  level: "INFO"            # DEBUG, INFO, WARNING, ERROR

# Security
security:
  # Signing key for session cookies, admin/step-up tokens, and captcha HMACs.
  # Leave empty to auto-generate a per-process key (fine for single-worker dev;
  # in production set a strong, secret value so tokens survive restarts/workers).
  # Treat this like a private key: never commit it, and rotate it if exposed.
  secret_key: ""
  rate_limit_max_attempts: 5
  rate_limit_window_seconds: 60

# --- ADFS/LDAP authentication (uncomment to enable) ---
# To use ADFS instead of local users.json, create an adfs_config.yaml:
#
#   host: "ldaps://dc01.corp.example.com"
#   username: "CN=svc-idp,OU=Service Accounts,DC=corp,DC=example,DC=com"
#   base_dn: "DC=corp,DC=example,DC=com"
#   password: "your-service-account-password"
#
# Then start with: identity-provider-server --adfs-config data/adfs_config.yaml
#
# Map AD groups to AWS roles in group_roles.yaml:
#
#   AWS-Admins:
#     - account_id: "123456789012"
#       role: "AdminRole"
#
#   AWS-Developers:
#     - account_id: "123456789012"
#       role: "DeveloperRole"
"""

_SERVICES_TEMPLATE = """\
# Service provider routing
# Maps URI paths to service providers with their authentication protocol.
#
# Format:
#   <protocol>:
#     <path>: <url>
#
# Protocols: saml, oauth
# Paths become routes on the IdP (e.g. "aws" -> GET/POST /aws)
#
# Documentation: docs/configuration.md#service-provider-routing-servicesyaml

saml:
  # AWS Console — issues SAML assertion, auto-POSTs to AWS signin
  aws: https://signin.aws.amazon.com/saml

  # Add more SAML service providers here:
  # gitlab: https://gitlab.corp.com/users/auth/saml/callback
  # jenkins: https://jenkins.corp.com/securityRealm/finishLogin

# oauth:
  # OAuth service providers — issues JWT, redirects with ?token=<jwt>
  # docs: https://docs.corp.com/
  # wiki: https://wiki.corp.com/oauth/callback

# Extended format with per-SP overrides:
# saml:
#   aws:
#     url: https://signin.aws.amazon.com/saml
#     provider_name: {provider_name}
#     session_duration_hours: 4
#     audience: urn:amazon:webservices
#
# oauth:
#   docs:
#     url: https://docs.corp.com/
#     client_id: docs-app
#     scopes: ["openid", "profile", "email"]
#     token_expiry_minutes: 60
"""

_USERS_TEMPLATE = """\
[
  {
    "username": "admin",
    "must_set_password": true,
    "claims": ["idpadmin"],
    "roles": []
  }
]
"""
# NOTE: The seeded admin has NO usable password. Set one before first login with:
#     idp-hash-password
# then paste the resulting bcrypt hash into the "password" field (and remove the
# "must_set_password" marker). The account is disabled for login until then, so
# the IdP cannot ship with a working default credential.
