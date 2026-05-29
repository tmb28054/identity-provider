"""Service provider routing loader.

Parses services.yaml to define which service providers the IdP serves,
mapping URI paths to protocols (saml/oauth) and target URLs.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SERVICES_FILENAME = "services.yaml"
_PATH_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


@dataclass
class ServiceProvider:
    """A single service provider configuration."""

    path: str
    protocol: str  # "saml" or "oauth"
    url: str
    # SAML-specific
    provider_name: str = "local-idp"
    session_duration_hours: int = 1
    audience: str = ""
    # OAuth-specific
    client_id: str = ""
    scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email"])
    token_expiry_minutes: int = 60


def _parse_sp_entry(
    path: str,
    protocol: str,
    value: str | dict[str, Any],
    defaults: dict[str, Any],
) -> ServiceProvider:
    """Parse a single service provider entry (short or extended form)."""
    if isinstance(value, str):
        # Short form: path: url
        url = value
        extra: dict[str, Any] = {}
    elif isinstance(value, dict):
        # Extended form: path: {url: ..., provider_name: ..., ...}
        url = value.get("url", "")
        extra = {k: v for k, v in value.items() if k != "url"}
    else:
        raise ValueError(f"Invalid service provider entry for path '{path}': {value}")

    if not url:
        raise ValueError(f"Service provider '{path}' has no URL")

    sp = ServiceProvider(
        path=path,
        protocol=protocol,
        url=url,
        provider_name=extra.get("provider_name", defaults.get("provider_name", "local-idp")),
        session_duration_hours=extra.get(
            "session_duration_hours", defaults.get("session_duration_hours", 1)
        ),
        audience=extra.get("audience", ""),
        client_id=extra.get("client_id", path),
        scopes=extra.get("scopes", ["openid", "profile", "email"]),
        token_expiry_minutes=extra.get("token_expiry_minutes", 60),
    )
    return sp


def load_services(
    data_dir: str | Path,
    *,
    default_provider_name: str = "local-idp",
    default_session_duration_hours: int = 1,
) -> list[ServiceProvider] | None:
    """Load service provider routing from services.yaml.

    Args:
        data_dir: Path to the data directory.
        default_provider_name: Default SAML provider name for SPs that don't specify one.
        default_session_duration_hours: Default session duration for SAML SPs.

    Returns:
        List of ServiceProvider objects, or None if services.yaml doesn't exist.

    Raises:
        ValueError: If the file has validation errors.
    """
    import yaml

    path = Path(data_dir) / SERVICES_FILENAME
    if not path.is_file():
        return None

    data = yaml.safe_load(path.read_text())
    if not data:
        return None

    defaults = {
        "provider_name": default_provider_name,
        "session_duration_hours": default_session_duration_hours,
    }

    services: list[ServiceProvider] = []
    seen_paths: set[str] = set()

    for protocol in ("saml", "oauth"):
        entries = data.get(protocol, {})
        if not isinstance(entries, dict):
            continue

        for sp_path, value in entries.items():
            sp_path = str(sp_path)

            # Validate path
            if not _PATH_RE.match(sp_path):
                raise ValueError(
                    f"Invalid path '{sp_path}': must be alphanumeric, hyphens, or underscores"
                )
            if sp_path in seen_paths:
                raise ValueError(f"Duplicate path '{sp_path}' across service providers")
            seen_paths.add(sp_path)

            sp = _parse_sp_entry(sp_path, protocol, value, defaults)
            services.append(sp)

    logger.info("Loaded %d service providers from %s", len(services), path)
    return services if services else None
