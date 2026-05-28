"""Tests for the configuration loader module."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import yaml

from identity_provider_server.config import (
    AppConfig,
    _apply_env_overrides,
    _deep_merge,
    load_config,
)


# --- _deep_merge ---


def test_deep_merge_simple():
    base = {"a": 1, "b": 2}
    override = {"b": 3, "c": 4}
    result = _deep_merge(base, override)
    assert result == {"a": 1, "b": 3, "c": 4}


def test_deep_merge_nested():
    base = {"server": {"host": "127.0.0.1", "port": 5000}}
    override = {"server": {"port": 8080}}
    result = _deep_merge(base, override)
    assert result == {"server": {"host": "127.0.0.1", "port": 8080}}


def test_deep_merge_does_not_mutate_base():
    base = {"a": {"x": 1}}
    override = {"a": {"y": 2}}
    _deep_merge(base, override)
    assert base == {"a": {"x": 1}}


# --- _apply_env_overrides ---


def test_env_override_string():
    config = {"server": {"host": "127.0.0.1"}}
    with patch.dict(os.environ, {"IDP_HOST": "0.0.0.0"}):
        result = _apply_env_overrides(config)
    assert result["server"]["host"] == "0.0.0.0"


def test_env_override_int():
    config = {"server": {"port": 5000}}
    with patch.dict(os.environ, {"IDP_PORT": "8080"}):
        result = _apply_env_overrides(config)
    assert result["server"]["port"] == 8080


def test_env_override_bool_true():
    config = {"server": {"debug": False}}
    with patch.dict(os.environ, {"IDP_DEBUG": "true"}):
        result = _apply_env_overrides(config)
    assert result["server"]["debug"] is True


def test_env_override_bool_false():
    config = {"server": {"debug": False}}
    with patch.dict(os.environ, {"IDP_DEBUG": "no"}):
        result = _apply_env_overrides(config)
    assert result["server"]["debug"] is False


def test_env_override_creates_section():
    config = {}
    with patch.dict(os.environ, {"IDP_HOST": "10.0.0.1"}):
        result = _apply_env_overrides(config)
    assert result["server"]["host"] == "10.0.0.1"


def test_env_override_secret_key():
    config = {"security": {"secret_key": ""}}
    with patch.dict(os.environ, {"SECRET_KEY": "my-secret"}):
        result = _apply_env_overrides(config)
    assert result["security"]["secret_key"] == "my-secret"


# --- load_config ---


def test_load_config_defaults(tmp_path):
    """When no config file exists, defaults are used."""
    config = load_config(str(tmp_path))
    assert config.server.host == "127.0.0.1"
    assert config.server.port == 5000
    assert config.server.debug is False
    assert config.saml.provider_name == "local-idp"
    assert config.saml.session_duration_hours == 1
    assert config.data.users_file == "users.json"
    assert config.logging.level == "WARNING"
    assert config.security.rate_limit_max_attempts == 5


def test_load_config_from_file(tmp_path):
    """Config file values override defaults."""
    cfg = {
        "server": {"host": "0.0.0.0", "port": 8080},
        "saml": {"provider_name": "my-idp"},
    }
    (tmp_path / "config.yaml").write_text(yaml.dump(cfg))

    config = load_config(str(tmp_path))
    assert config.server.host == "0.0.0.0"
    assert config.server.port == 8080
    assert config.saml.provider_name == "my-idp"
    # Defaults still apply for unset values
    assert config.saml.session_duration_hours == 1


def test_load_config_explicit_path(tmp_path):
    """Explicit config_path is used instead of data_dir/config.yaml."""
    cfg = {"saml": {"session_duration_hours": 8}}
    custom_path = tmp_path / "custom.yaml"
    custom_path.write_text(yaml.dump(cfg))

    config = load_config(str(tmp_path), config_path=str(custom_path))
    assert config.saml.session_duration_hours == 8


def test_load_config_env_overrides_file(tmp_path):
    """Environment variables override config file values."""
    cfg = {"server": {"port": 3000}}
    (tmp_path / "config.yaml").write_text(yaml.dump(cfg))

    with patch.dict(os.environ, {"IDP_PORT": "9999"}):
        config = load_config(str(tmp_path))
    assert config.server.port == 9999


def test_load_config_invalid_yaml(tmp_path):
    """Invalid YAML is handled gracefully (falls back to defaults)."""
    (tmp_path / "config.yaml").write_text(": invalid: yaml: [")

    config = load_config(str(tmp_path))
    # Should still return defaults without crashing
    assert config.server.host == "127.0.0.1"


def test_load_config_empty_yaml(tmp_path):
    """Empty YAML file is handled gracefully."""
    (tmp_path / "config.yaml").write_text("")

    config = load_config(str(tmp_path))
    assert config.server.host == "127.0.0.1"


# --- AppConfig methods ---


def test_app_config_resolve_path_relative():
    config = AppConfig(data_dir="/data")
    assert config.resolve_path("users.json") == Path("/data/users.json")


def test_app_config_resolve_path_absolute():
    config = AppConfig(data_dir="/data")
    assert config.resolve_path("/etc/users.json") == Path("/etc/users.json")


def test_app_config_properties():
    config = AppConfig(data_dir="/data")
    assert config.users_path == Path("/data/users.json")
    assert config.certificate_path == Path("/data/idp.crt")
    assert config.private_key_path == Path("/data/idp.key")
