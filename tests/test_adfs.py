"""Tests for the ADFS/LDAP authentication module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from identity_provider_server.adfs import (
    _extract_cn,
    _ldap_escape,
    authenticate_adfs,
    groups_to_roles,
    load_adfs_config,
    load_group_role_map,
)


# --- _ldap_escape ---


def test_ldap_escape_no_special_chars():
    assert _ldap_escape("alice") == "alice"


def test_ldap_escape_backslash():
    assert _ldap_escape("a\\b") == "a\\5cb"


def test_ldap_escape_asterisk():
    assert _ldap_escape("a*b") == "a\\2ab"


def test_ldap_escape_parentheses():
    assert _ldap_escape("(test)") == "\\28test\\29"


def test_ldap_escape_null():
    assert _ldap_escape("a\x00b") == "a\\00b"


def test_ldap_escape_multiple():
    assert _ldap_escape("a*(b)") == "a\\2a\\28b\\29"


# --- _extract_cn ---


def test_extract_cn_simple():
    assert _extract_cn("CN=AWS-Admin,OU=Groups,DC=corp,DC=com") == "AWS-Admin"


def test_extract_cn_with_spaces():
    assert _extract_cn("CN=My Group, OU=Groups, DC=corp, DC=com") == "My Group"


def test_extract_cn_lowercase():
    assert _extract_cn("cn=lower,DC=corp") == "lower"


def test_extract_cn_no_cn():
    assert _extract_cn("OU=Groups,DC=corp,DC=com") is None


def test_extract_cn_empty():
    assert _extract_cn("") is None


# --- groups_to_roles ---


def test_groups_to_roles_basic():
    mapping = {
        "AWS-Admins": [{"account_id": "111", "role": "Admin"}],
        "AWS-Dev": [{"account_id": "222", "role": "Dev"}],
    }
    result = groups_to_roles(["AWS-Admins"], mapping)
    assert result == [{"account_id": "111", "role": "Admin"}]


def test_groups_to_roles_multiple_groups():
    mapping = {
        "AWS-Admins": [{"account_id": "111", "role": "Admin"}],
        "AWS-Dev": [{"account_id": "222", "role": "Dev"}],
    }
    result = groups_to_roles(["AWS-Admins", "AWS-Dev"], mapping)
    assert len(result) == 2


def test_groups_to_roles_deduplication():
    mapping = {
        "GroupA": [{"account_id": "111", "role": "Admin"}],
        "GroupB": [{"account_id": "111", "role": "Admin"}],
    }
    result = groups_to_roles(["GroupA", "GroupB"], mapping)
    assert len(result) == 1


def test_groups_to_roles_no_match():
    mapping = {"AWS-Admins": [{"account_id": "111", "role": "Admin"}]}
    result = groups_to_roles(["UnknownGroup"], mapping)
    assert result == []


def test_groups_to_roles_empty_groups():
    mapping = {"AWS-Admins": [{"account_id": "111", "role": "Admin"}]}
    result = groups_to_roles([], mapping)
    assert result == []


def test_groups_to_roles_multi_role_per_group():
    mapping = {
        "AWS-Dev": [
            {"account_id": "111", "role": "Dev"},
            {"account_id": "222", "role": "Dev"},
        ],
    }
    result = groups_to_roles(["AWS-Dev"], mapping)
    assert len(result) == 2


# --- load_adfs_config ---


def test_load_adfs_config_from_file(tmp_path):
    import yaml

    config = {
        "host": "ldaps://dc.corp.com",
        "username": "CN=svc,DC=corp",
        "base_dn": "DC=corp,DC=com",
        "password": "secret",
    }
    cfg_file = tmp_path / "adfs.yaml"
    cfg_file.write_text(yaml.dump(config))

    result = load_adfs_config(str(cfg_file))
    assert result == config


def test_load_adfs_config_missing_keys(tmp_path):
    import yaml

    config = {"host": "ldaps://dc.corp.com"}
    cfg_file = tmp_path / "adfs.yaml"
    cfg_file.write_text(yaml.dump(config))

    with pytest.raises(SystemExit):
        load_adfs_config(str(cfg_file))


def test_load_adfs_config_prompts_when_missing(tmp_path):
    cfg_file = tmp_path / "subdir" / "adfs.yaml"

    with patch("builtins.input", side_effect=["ldaps://host", "CN=user", "DC=corp"]):
        with patch("getpass.getpass", return_value="pass123"):
            result = load_adfs_config(str(cfg_file))

    assert result["host"] == "ldaps://host"
    assert result["username"] == "CN=user"
    assert result["base_dn"] == "DC=corp"
    assert result["password"] == "pass123"
    assert cfg_file.is_file()


def test_load_adfs_config_prompts_exits_on_empty(tmp_path):
    cfg_file = tmp_path / "adfs.yaml"

    with patch("builtins.input", side_effect=["", "", ""]):
        with patch("getpass.getpass", return_value=""):
            with pytest.raises(SystemExit):
                load_adfs_config(str(cfg_file))


# --- load_group_role_map ---


def test_load_group_role_map_exists(tmp_path):
    import yaml

    mapping = {"AWS-Admin": [{"account_id": "111", "role": "Admin"}]}
    (tmp_path / "group_roles.yaml").write_text(yaml.dump(mapping))

    result = load_group_role_map(str(tmp_path))
    assert result == mapping


def test_load_group_role_map_missing(tmp_path):
    result = load_group_role_map(str(tmp_path))
    assert result == {}


def test_load_group_role_map_custom_filename(tmp_path):
    import yaml

    mapping = {"G1": [{"account_id": "222", "role": "R1"}]}
    (tmp_path / "custom.yaml").write_text(yaml.dump(mapping))

    result = load_group_role_map(str(tmp_path), filename="custom.yaml")
    assert result == mapping


# --- authenticate_adfs ---


@pytest.fixture
def adfs_cfg():
    return {
        "host": "ldaps://dc.corp.com",
        "username": "CN=svc,DC=corp",
        "base_dn": "DC=corp,DC=com",
        "password": "svc-pass",
    }


def test_authenticate_adfs_success(adfs_cfg):
    mock_entry = MagicMock()
    mock_entry.distinguishedName = "CN=alice,OU=Users,DC=corp,DC=com"
    mock_entry.memberOf = [
        "CN=AWS-Admins,OU=Groups,DC=corp,DC=com",
        "CN=AWS-Dev,OU=Groups,DC=corp,DC=com",
    ]

    mock_conn = MagicMock()
    mock_conn.entries = [mock_entry]

    mock_user_conn = MagicMock()

    with patch("ldap3.Server") as MockServer:
        with patch("ldap3.Connection") as MockConn:
            MockConn.side_effect = [mock_conn, mock_user_conn]
            result = authenticate_adfs("alice", "password123", adfs_cfg)

    assert result == ["AWS-Admins", "AWS-Dev"]
    mock_conn.unbind.assert_called_once()
    mock_user_conn.unbind.assert_called_once()


def test_authenticate_adfs_user_not_found(adfs_cfg):
    mock_conn = MagicMock()
    mock_conn.entries = []

    with patch("ldap3.Server"):
        with patch("ldap3.Connection", return_value=mock_conn):
            result = authenticate_adfs("unknown", "pass", adfs_cfg)

    assert result is None
    mock_conn.unbind.assert_called_once()


def test_authenticate_adfs_bad_password(adfs_cfg):
    from ldap3.core.exceptions import LDAPBindError

    mock_entry = MagicMock()
    mock_entry.distinguishedName = "CN=alice,OU=Users,DC=corp,DC=com"
    mock_entry.memberOf = ["CN=AWS-Admins,OU=Groups,DC=corp,DC=com"]

    mock_conn = MagicMock()
    mock_conn.entries = [mock_entry]

    with patch("ldap3.Server"):
        with patch("ldap3.Connection") as MockConn:
            MockConn.side_effect = [mock_conn, LDAPBindError("bad password")]
            result = authenticate_adfs("alice", "wrong", adfs_cfg)

    assert result is None


def test_authenticate_adfs_bind_failure(adfs_cfg):
    from ldap3.core.exceptions import LDAPBindError

    with patch("ldap3.Server"):
        with patch(
            "ldap3.Connection",
            side_effect=LDAPBindError("connection refused"),
        ):
            result = authenticate_adfs("alice", "pass", adfs_cfg)

    assert result is None


def test_authenticate_adfs_no_groups(adfs_cfg):
    mock_entry = MagicMock()
    mock_entry.distinguishedName = "CN=alice,OU=Users,DC=corp,DC=com"
    mock_entry.memberOf = None

    mock_conn = MagicMock()
    mock_conn.entries = [mock_entry]

    mock_user_conn = MagicMock()

    with patch("ldap3.Server"):
        with patch("ldap3.Connection") as MockConn:
            MockConn.side_effect = [mock_conn, mock_user_conn]
            # memberOf is None, so hasattr check should handle it
            result = authenticate_adfs("alice", "pass", adfs_cfg)

    assert result == []


def test_authenticate_adfs_skip_ssl_verify(adfs_cfg):
    mock_entry = MagicMock()
    mock_entry.distinguishedName = "CN=alice,OU=Users,DC=corp,DC=com"
    mock_entry.memberOf = ["CN=G1,DC=corp"]

    mock_conn = MagicMock()
    mock_conn.entries = [mock_entry]
    mock_user_conn = MagicMock()

    with patch("ldap3.Server") as MockServer:
        with patch("ldap3.Connection") as MockConn:
            with patch("ldap3.Tls") as MockTls:
                MockConn.side_effect = [mock_conn, mock_user_conn]
                result = authenticate_adfs(
                    "alice", "pass", adfs_cfg, skip_ssl_verify=True
                )

    # Tls should have been called since host starts with ldaps://
    MockTls.assert_called_once()
    assert result == ["G1"]


def test_authenticate_adfs_no_ssl_no_tls():
    """When host doesn't use ldaps://, TLS object should not be created."""
    cfg = {
        "host": "ldap://dc.corp.com",
        "username": "CN=svc,DC=corp",
        "base_dn": "DC=corp,DC=com",
        "password": "svc-pass",
    }
    mock_entry = MagicMock()
    mock_entry.distinguishedName = "CN=alice,DC=corp"
    mock_entry.memberOf = ["CN=G1,DC=corp"]

    mock_conn = MagicMock()
    mock_conn.entries = [mock_entry]
    mock_user_conn = MagicMock()

    with patch("ldap3.Server") as MockServer:
        with patch("ldap3.Connection") as MockConn:
            with patch("ldap3.Tls") as MockTls:
                MockConn.side_effect = [mock_conn, mock_user_conn]
                result = authenticate_adfs(
                    "alice", "pass", cfg, skip_ssl_verify=True
                )

    # Tls should NOT be called since host is not ldaps://
    MockTls.assert_not_called()
    MockServer.assert_called_once()
    # use_ssl should be False
    call_kwargs = MockServer.call_args
    assert call_kwargs.kwargs.get("use_ssl") is False or call_kwargs[1].get("use_ssl") is False


# --- empty-password guard (security review F4) ---

def test_authenticate_adfs_rejects_empty_password():
    """An empty password is refused before any bind (unauthenticated simple
    bind defence). No LDAP connection should be attempted."""
    cfg = {
        "host": "ldaps://ldap.example.com",
        "username": "cn=svc,dc=example,dc=com",
        "password": "svcpass",
        "base_dn": "dc=example,dc=com",
    }
    with patch("ldap3.Connection") as conn:
        assert authenticate_adfs("alice", "", cfg) is None
        assert authenticate_adfs("alice", "   ", cfg) is None
        conn.assert_not_called()
