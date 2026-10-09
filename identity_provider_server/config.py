"""Configuration loader for identity-provider-server.

Reads a YAML config file from the data directory and merges with
CLI arguments and environment variables. Priority (highest wins):

    CLI arguments > Environment variables > Config file > Defaults
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULTS: dict[str, Any] = {
    "server": {
        "host": "127.0.0.1",
        "port": 5000,
        "debug": False,
        "trust_proxy": False,
    },
    "saml": {
        "provider_name": "local-idp",
        "session_duration_hours": 1,
    },
    "data": {
        "users_file": "users.json",
        "certificate_file": "idp.crt",
        "private_key_file": "idp.key",
    },
    "logging": {
        "level": "WARNING",
    },
    "security": {
        "secret_key": "",  # nosec B105
        "audit_chain_key": "",  # nosec B105
        "rate_limit_max_attempts": 5,
        "rate_limit_window_seconds": 60,
    },
    "webauthn": {
        "enabled": False,
        "rp_id": "",
        "rp_name": "Identity Provider",
        "expected_origin": "",
    },
}

CONFIG_FILENAME = "config.yaml"

# Single source of truth mapping each supported environment variable to the
# (section, key) it overrides in the config dict. ``_apply_env_overrides``
# iterates this, and ``app.create_app``'s unconsumed-config guard imports it so
# the loader and the guard can never drift out of sync.
ENV_OVERRIDE_MAP: dict[str, tuple[str, str]] = {
    "IDP_HOST": ("server", "host"),
    "IDP_PORT": ("server", "port"),
    "IDP_DEBUG": ("server", "debug"),
    "IDP_TRUST_PROXY": ("server", "trust_proxy"),
    "IDP_PROVIDER_NAME": ("saml", "provider_name"),
    "IDP_SESSION_DURATION_HOURS": ("saml", "session_duration_hours"),
    "IDP_USERS_FILE": ("data", "users_file"),
    "IDP_CERTIFICATE_FILE": ("data", "certificate_file"),
    "IDP_PRIVATE_KEY_FILE": ("data", "private_key_file"),
    "IDP_LOG_LEVEL": ("logging", "level"),
    "SECRET_KEY": ("security", "secret_key"),
    "IDP_AUDIT_CHAIN_KEY": ("security", "audit_chain_key"),
    "IDP_RATE_LIMIT_MAX_ATTEMPTS": ("security", "rate_limit_max_attempts"),
    "IDP_RATE_LIMIT_WINDOW_SECONDS": ("security", "rate_limit_window_seconds"),
    "IDP_WEBAUTHN_ENABLED": ("webauthn", "enabled"),
    "IDP_WEBAUTHN_RP_ID": ("webauthn", "rp_id"),
    "IDP_WEBAUTHN_RP_NAME": ("webauthn", "rp_name"),
    "IDP_WEBAUTHN_EXPECTED_ORIGIN": ("webauthn", "expected_origin"),
}


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 5000
    debug: bool = False
    trust_proxy: bool = False


@dataclass
class SamlConfig:
    provider_name: str = "local-idp"
    session_duration_hours: int = 1


@dataclass
class DataConfig:
    users_file: str = "users.json"
    certificate_file: str = "idp.crt"
    private_key_file: str = "idp.key"


@dataclass
class LoggingConfig:
    level: str = "WARNING"


@dataclass
class SecurityConfig:
    secret_key: str = ""
    audit_chain_key: str = ""
    rate_limit_max_attempts: int = 5
    rate_limit_window_seconds: int = 60


@dataclass
class WebAuthnConfig:
    """Passkey (WebAuthn/FIDO2) relying-party configuration.

    ``rp_id`` is the effective domain credentials are bound to (e.g.
    ``idp.botthouse.net``). ``expected_origin`` is the full https origin the
    browser reports (e.g. ``https://idp.botthouse.net``). Both must match the
    domain users actually visit, or enrolled passkeys stop validating.
    """

    enabled: bool = False
    rp_id: str = ""
    rp_name: str = "Identity Provider"
    expected_origin: str = ""

    def validate(self) -> None:
        """Raise ValueError if enabled but misconfigured or inconsistent."""
        if not self.enabled:
            return
        if not self.rp_id:
            raise ValueError("webauthn.rp_id is required when webauthn.enabled is true")
        if not self.expected_origin:
            raise ValueError(
                "webauthn.expected_origin is required when webauthn.enabled is true"
            )
        origin = self.expected_origin
        if not origin.startswith("https://") and not origin.startswith("http://"):
            raise ValueError("webauthn.expected_origin must be an http(s) URL")
        # The origin host must equal rp_id or be a subdomain of it.
        host = origin.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        if host != self.rp_id and not host.endswith("." + self.rp_id):
            raise ValueError(
                f"webauthn.expected_origin host ({host}) is not rp_id "
                f"({self.rp_id}) or a subdomain of it"
            )


@dataclass
class AppConfig:
    """Complete application configuration."""

    server: ServerConfig = field(default_factory=ServerConfig)
    saml: SamlConfig = field(default_factory=SamlConfig)
    data: DataConfig = field(default_factory=DataConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    webauthn: WebAuthnConfig = field(default_factory=WebAuthnConfig)
    data_dir: str = ""

    def resolve_path(self, relative_path: str) -> Path:
        """Resolve a path relative to the data directory."""
        p = Path(relative_path)
        if p.is_absolute():
            return p
        return Path(self.data_dir) / p

    @property
    def users_path(self) -> Path:
        return self.resolve_path(self.data.users_file)

    @property
    def certificate_path(self) -> Path:
        return self.resolve_path(self.data.certificate_file)

    @property
    def private_key_path(self) -> Path:
        return self.resolve_path(self.data.private_key_file)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, returning a new dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _apply_env_overrides(config: dict) -> dict:
    """Apply environment variable overrides.

    Supported environment variables:
        IDP_HOST, IDP_PORT, IDP_DEBUG, IDP_TRUST_PROXY,
        IDP_PROVIDER_NAME, IDP_SESSION_DURATION_HOURS,
        IDP_USERS_FILE, IDP_CERTIFICATE_FILE, IDP_PRIVATE_KEY_FILE,
        IDP_LOG_LEVEL,
        SECRET_KEY, IDP_AUDIT_CHAIN_KEY,
        IDP_RATE_LIMIT_MAX_ATTEMPTS, IDP_RATE_LIMIT_WINDOW_SECONDS,
        IDP_WEBAUTHN_ENABLED, IDP_WEBAUTHN_RP_ID, IDP_WEBAUTHN_RP_NAME,
        IDP_WEBAUTHN_EXPECTED_ORIGIN

    The variable-to-field mapping lives in the module-level
    ``ENV_OVERRIDE_MAP`` so the loader and the app's unconsumed-config guard
    share a single source of truth.
    """
    for env_var, (section, key) in ENV_OVERRIDE_MAP.items():
        value = os.environ.get(env_var)
        if value is not None:
            # Type coercion based on defaults
            default_value = _DEFAULTS[section][key]
            if isinstance(default_value, bool):
                value = value.lower() in ("true", "1", "yes")
            elif isinstance(default_value, int):
                value = int(value)

            if section not in config:
                config[section] = {}
            config[section][key] = value

    return config


def load_config(data_dir: str, config_path: str | None = None) -> AppConfig:
    """Load configuration from file, environment, and defaults.

    Args:
        data_dir: Path to the data directory.
        config_path: Optional explicit path to config file. If not provided,
                     looks for config.yaml in the data directory.

    Returns:
        Fully resolved AppConfig instance.
    """
    data_path = Path(data_dir)

    # Start with defaults
    config = _DEFAULTS.copy()
    config = {k: v.copy() if isinstance(v, dict) else v for k, v in config.items()}

    # Load config file if it exists
    cfg_file = Path(config_path) if config_path else data_path / CONFIG_FILENAME

    if cfg_file.is_file():
        try:
            import yaml

            file_config = yaml.safe_load(cfg_file.read_text()) or {}
            config = _deep_merge(config, file_config)
            logger.info("Loaded configuration from %s", cfg_file)
        except ImportError:  # pragma: no cover - PyYAML is a hard dependency
            logger.warning(
                "PyYAML not installed — cannot read config file %s. "
                "Install with: pip install pyyaml",
                cfg_file,
            )
        except Exception as e:  # noqa: BLE001 - config load must never crash startup
            logger.warning("Failed to read config file %s: %s", cfg_file, e)
    else:
        logger.debug("No config file found at %s, using defaults", cfg_file)

    # Apply environment variable overrides
    config = _apply_env_overrides(config)

    # Build the AppConfig dataclass
    return AppConfig(
        server=ServerConfig(**config.get("server", {})),
        saml=SamlConfig(**config.get("saml", {})),
        data=DataConfig(**config.get("data", {})),
        logging=LoggingConfig(**config.get("logging", {})),
        security=SecurityConfig(**config.get("security", {})),
        webauthn=WebAuthnConfig(**config.get("webauthn", {})),
        data_dir=str(data_path),
    )
