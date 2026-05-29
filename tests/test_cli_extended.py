"""Extended CLI tests covering ADFS loading and logging configuration."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

from identity_provider_server.__main__ import _configure_logging, main

_PATCH_CREATE = "identity_provider_server.__main__.create_app"


def test_configure_logging_verbosity_2():
    """Verbosity 2 sets DEBUG level regardless of config."""
    import logging

    _configure_logging("WARNING", 2)
    logger = logging.getLogger("identity_provider_server")
    assert logger.level == logging.DEBUG
    # Clean up handlers
    logger.handlers.clear()


def test_configure_logging_verbosity_1():
    """Verbosity 1 sets INFO level."""
    import logging

    _configure_logging("WARNING", 1)
    logger = logging.getLogger("identity_provider_server")
    assert logger.level == logging.INFO
    logger.handlers.clear()


def test_configure_logging_from_config_level():
    """When verbosity is 0, config level string is used."""
    import logging

    _configure_logging("ERROR", 0)
    logger = logging.getLogger("identity_provider_server")
    assert logger.level == logging.ERROR
    logger.handlers.clear()


def test_configure_logging_invalid_level_defaults_to_warning():
    """Invalid level string falls back to WARNING."""
    import logging

    _configure_logging("INVALID_LEVEL", 0)
    logger = logging.getLogger("identity_provider_server")
    assert logger.level == logging.WARNING
    logger.handlers.clear()


def test_main_with_adfs_config(tmp_path):
    """--adfs-config loads ADFS config and group role map."""
    data = Path(__file__).parent.parent / "data"
    shutil.copy(data / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(data / "idp.key", tmp_path / "idp.key")
    (tmp_path / "users.json").write_text(json.dumps([]))

    adfs_cfg = {
        "host": "ldaps://dc.corp.com",
        "username": "CN=svc,DC=corp",
        "base_dn": "DC=corp,DC=com",
        "password": "secret",
    }
    adfs_file = tmp_path / "adfs.yaml"
    adfs_file.write_text(yaml.dump(adfs_cfg))

    group_map = {"AWS-Admin": [{"account_id": "111", "role": "Admin"}]}
    (tmp_path / "group_roles.yaml").write_text(yaml.dump(group_map))

    mock_app = MagicMock()
    with (
        patch(_PATCH_CREATE, return_value=mock_app) as mock_create,
        patch(
            "sys.argv",
            [
                "identity-provider-server",
                "--data-dir",
                str(tmp_path),
                "--adfs-config",
                str(adfs_file),
            ],
        ),
    ):
        main()

    call_kwargs = mock_create.call_args.kwargs
    assert call_kwargs["adfs_config"] == adfs_cfg
    assert call_kwargs["group_role_map"] == group_map
    assert call_kwargs["skip_ldap_ssl_verify"] is False


def test_main_with_skip_ldap_ssl_verify(tmp_path):
    """--skip-ldap-ssl-verify is passed through to create_app."""
    data = Path(__file__).parent.parent / "data"
    shutil.copy(data / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(data / "idp.key", tmp_path / "idp.key")
    (tmp_path / "users.json").write_text(json.dumps([]))

    adfs_cfg = {
        "host": "ldaps://dc.corp.com",
        "username": "CN=svc,DC=corp",
        "base_dn": "DC=corp,DC=com",
        "password": "secret",
    }
    adfs_file = tmp_path / "adfs.yaml"
    adfs_file.write_text(yaml.dump(adfs_cfg))

    (tmp_path / "group_roles.yaml").write_text(yaml.dump({}))

    mock_app = MagicMock()
    with (
        patch(_PATCH_CREATE, return_value=mock_app) as mock_create,
        patch(
            "sys.argv",
            [
                "identity-provider-server",
                "--data-dir",
                str(tmp_path),
                "--adfs-config",
                str(adfs_file),
                "--skip-ldap-ssl-verify",
            ],
        ),
    ):
        main()

    assert mock_create.call_args.kwargs["skip_ldap_ssl_verify"] is True


def test_main_with_config_file(tmp_path):
    """--config loads from explicit config file path."""
    data = Path(__file__).parent.parent / "data"
    shutil.copy(data / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(data / "idp.key", tmp_path / "idp.key")
    (tmp_path / "users.json").write_text(json.dumps([]))

    cfg = {"saml": {"provider_name": "custom-idp"}}
    cfg_file = tmp_path / "my-config.yaml"
    cfg_file.write_text(yaml.dump(cfg))

    mock_app = MagicMock()
    with (
        patch(_PATCH_CREATE, return_value=mock_app) as mock_create,
        patch(
            "sys.argv",
            [
                "identity-provider-server",
                "--data-dir",
                str(tmp_path),
                "--config",
                str(cfg_file),
            ],
        ),
    ):
        main()

    assert mock_create.call_args.kwargs["provider_name"] == "custom-idp"
