"""ADFS/LDAP authentication backend.

Authenticates users against Active Directory via LDAP and uses group
memberships as claims for SAML assertion role mappings.

The ADFS config file is a YAML file with keys:
    host: LDAP server hostname or IP
    username: Bind DN or user (e.g. CN=svc-idp,OU=Service,DC=corp,DC=com)
    base_dn: Base DN for user searches (e.g. DC=corp,DC=com)
    password: Bind password

If the config file does not exist, the user is prompted for the values
and the file is written automatically.
"""

from __future__ import annotations

import getpass
import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _prompt_and_write_config(config_path: Path) -> dict[str, str]:
    """Prompt the user for ADFS config values and write the file.

    Args:
        config_path: Path where the config file will be written.

    Returns:
        Dict with host, username, base_dn, password keys.
    """
    print(f"ADFS config file not found: {config_path}")
    print("Please provide the ADFS/LDAP connection details:\n")

    host = input("  LDAP host (e.g. ldap.corp.com): ").strip()
    username = input("  Bind username/DN (e.g. CN=svc-idp,OU=Service,DC=corp,DC=com): ").strip()
    base_dn = input("  Base DN (e.g. DC=corp,DC=com): ").strip()
    password = getpass.getpass("  Bind password: ")

    if not all([host, username, base_dn, password]):
        print("Error: All fields are required.", file=sys.stderr)
        sys.exit(1)

    config = {
        "host": host,
        "username": username,
        "base_dn": base_dn,
        "password": password,
    }

    import yaml

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(yaml.dump(config, default_flow_style=False))
    print(f"\nConfig written to: {config_path}")
    print("You can edit this file directly in the future.\n")

    return config


def load_adfs_config(config_path: str | Path) -> dict[str, str]:
    """Load ADFS config from a YAML file, prompting if it doesn't exist.

    Args:
        config_path: Path to the ADFS config YAML file.

    Returns:
        Dict with keys: host, username, base_dn, password.
    """
    import yaml

    path = Path(config_path)

    if not path.is_file():
        return _prompt_and_write_config(path)

    config = yaml.safe_load(path.read_text()) or {}

    required_keys = ["host", "username", "base_dn", "password"]
    missing = [k for k in required_keys if not config.get(k)]
    if missing:
        logger.error("ADFS config %s is missing keys: %s", path, missing)
        print(f"Error: ADFS config {path} is missing required keys: {missing}", file=sys.stderr)
        sys.exit(1)

    return config


def authenticate_adfs(
    username: str,
    password: str,
    adfs_config: dict[str, str],
    *,
    skip_ssl_verify: bool = False,
) -> list[str] | None:
    """Authenticate a user against AD via LDAP and return their group memberships.

    Args:
        username: The username to authenticate (sAMAccountName).
        password: The user's password.
        adfs_config: Dict with host, username (bind DN), base_dn, password (bind password).
        skip_ssl_verify: If True, disable TLS certificate verification for LDAP connections.

    Returns:
        List of group CNs the user belongs to, or None if authentication failed.
    """
    import ssl

    from ldap3 import ALL, Connection, Server, Tls
    from ldap3.core.exceptions import LDAPBindError, LDAPException

    # Reject empty or whitespace-only passwords before any bind. A directory
    # that permits an unauthenticated simple bind (RFC 4513) returns success
    # for a DN with an empty password; without this guard that success would be
    # read as a valid authentication.
    if not password or not password.strip():
        logger.info("ADFS auth: rejected empty password for user %s", username)
        return None

    host = adfs_config["host"]
    bind_user = adfs_config["username"]
    bind_password = adfs_config["password"]
    base_dn = adfs_config["base_dn"]

    use_ssl = host.startswith("ldaps://")

    # Configure TLS settings
    tls = None
    if use_ssl and skip_ssl_verify:
        tls = Tls(validate=ssl.CERT_NONE)
        logger.debug("LDAP SSL certificate verification disabled")

    # First, bind with the service account to look up the user's DN
    try:
        server = Server(host, get_info=ALL, use_ssl=use_ssl, tls=tls)
        conn = Connection(server, user=bind_user, password=bind_password, auto_bind=True)
    except (LDAPBindError, LDAPException) as e:
        logger.error("Failed to bind to LDAP server %s: %s", host, e)
        return None

    # Search for the user by sAMAccountName
    search_filter = f"(&(objectClass=user)(sAMAccountName={_ldap_escape(username)}))"
    conn.search(
        search_base=base_dn,
        search_filter=search_filter,
        attributes=["distinguishedName", "memberOf"],
    )

    if not conn.entries:
        logger.info("ADFS auth: user %s not found in directory", username)
        conn.unbind()
        return None

    user_entry = conn.entries[0]
    user_dn = str(user_entry.distinguishedName)
    conn.unbind()

    # Now bind as the user to verify their password
    try:
        user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        user_conn.unbind()
    except (LDAPBindError, LDAPException):
        logger.info("ADFS auth: invalid password for user %s", username)
        return None

    # Extract group CNs from memberOf
    groups = []
    if hasattr(user_entry, "memberOf") and user_entry.memberOf:
        for group_dn in user_entry.memberOf:
            # Extract CN from the DN (e.g. "CN=AWS-Admin,OU=Groups,DC=corp,DC=com" -> "AWS-Admin")
            cn = _extract_cn(str(group_dn))
            if cn:
                groups.append(cn)

    logger.info("ADFS auth: user %s authenticated, groups=%s", username, groups)
    return groups


def groups_to_roles(
    groups: list[str],
    group_role_map: dict[str, list[dict[str, str]]],
) -> list[dict[str, str]]:
    """Map AD group names to AWS IAM roles.

    Args:
        groups: List of AD group CNs the user belongs to.
        group_role_map: Mapping of group name -> list of role dicts
                        (each with 'account_id' and 'role' keys).

    Returns:
        Deduplicated list of role dicts for the SAML assertion.
    """
    roles: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for group in groups:
        if group in group_role_map:
            for role in group_role_map[group]:
                key = (role["account_id"], role["role"])
                if key not in seen:
                    seen.add(key)
                    roles.append(role)

    return roles


def _ldap_escape(value: str) -> str:
    """Escape special characters for LDAP search filters (RFC 4515)."""
    replacements = {
        "\\": "\\5c",
        "*": "\\2a",
        "(": "\\28",
        ")": "\\29",
        "\x00": "\\00",
    }
    for char, escaped in replacements.items():
        value = value.replace(char, escaped)
    return value


def _extract_cn(dn: str) -> str | None:
    """Extract the CN value from a distinguished name string."""
    for part in dn.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:]
    return None


def load_group_role_map(data_dir: str | Path, filename: str = "group_roles.yaml") -> dict[str, Any]:
    """Load the group-to-role mapping file.

    Args:
        data_dir: Data directory path.
        filename: Name of the group roles mapping file.

    Returns:
        Dict mapping group names to lists of role dicts.
    """
    import yaml

    path = Path(data_dir) / filename
    if not path.is_file():
        logger.warning("Group role mapping file not found: %s", path)
        return {}

    data = yaml.safe_load(path.read_text()) or {}
    return data
