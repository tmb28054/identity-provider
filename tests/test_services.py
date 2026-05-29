"""Tests for the service provider routing loader."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from identity_provider_server.services import ServiceProvider, load_services


def test_load_services_file_not_found(tmp_path):
    """Returns None when services.yaml doesn't exist."""
    result = load_services(str(tmp_path))
    assert result is None


def test_load_services_empty_file(tmp_path):
    """Returns None for an empty YAML file."""
    (tmp_path / "services.yaml").write_text("")
    result = load_services(str(tmp_path))
    assert result is None


def test_load_services_saml_short_form(tmp_path):
    """Parses short-form SAML entries."""
    (tmp_path / "services.yaml").write_text(yaml.dump({
        "saml": {"aws": "https://signin.aws.amazon.com/saml"},
    }))
    result = load_services(str(tmp_path))
    assert result is not None
    assert len(result) == 1
    assert result[0].path == "aws"
    assert result[0].protocol == "saml"
    assert result[0].url == "https://signin.aws.amazon.com/saml"


def test_load_services_oauth_short_form(tmp_path):
    """Parses short-form OAuth entries."""
    (tmp_path / "services.yaml").write_text(yaml.dump({
        "oauth": {"docs": "https://docs.example.com/"},
    }))
    result = load_services(str(tmp_path))
    assert result is not None
    assert len(result) == 1
    assert result[0].path == "docs"
    assert result[0].protocol == "oauth"
    assert result[0].url == "https://docs.example.com/"


def test_load_services_extended_form(tmp_path):
    """Parses extended-form entries with per-SP overrides."""
    (tmp_path / "services.yaml").write_text(yaml.dump({
        "saml": {
            "gitlab": {
                "url": "https://gitlab.com/saml",
                "provider_name": "gitlab-idp",
                "session_duration_hours": 8,
                "audience": "https://gitlab.com",
            },
        },
        "oauth": {
            "wiki": {
                "url": "https://wiki.example.com/callback",
                "client_id": "wiki-app",
                "scopes": ["openid", "profile"],
                "token_expiry_minutes": 120,
            },
        },
    }))
    result = load_services(str(tmp_path))
    assert result is not None
    assert len(result) == 2

    gitlab = next(sp for sp in result if sp.path == "gitlab")
    assert gitlab.provider_name == "gitlab-idp"
    assert gitlab.session_duration_hours == 8
    assert gitlab.audience == "https://gitlab.com"

    wiki = next(sp for sp in result if sp.path == "wiki")
    assert wiki.client_id == "wiki-app"
    assert wiki.scopes == ["openid", "profile"]
    assert wiki.token_expiry_minutes == 120


def test_load_services_duplicate_path_raises(tmp_path):
    """Duplicate paths across protocols raise ValueError."""
    (tmp_path / "services.yaml").write_text(yaml.dump({
        "saml": {"app": "https://a.com/saml"},
        "oauth": {"app": "https://b.com/"},
    }))
    with pytest.raises(ValueError, match="Duplicate path"):
        load_services(str(tmp_path))


def test_load_services_invalid_path_raises(tmp_path):
    """Invalid path characters raise ValueError."""
    (tmp_path / "services.yaml").write_text(yaml.dump({
        "saml": {"my/path": "https://a.com/saml"},
    }))
    with pytest.raises(ValueError, match="Invalid path"):
        load_services(str(tmp_path))


def test_load_services_no_url_raises(tmp_path):
    """Extended form without url raises ValueError."""
    (tmp_path / "services.yaml").write_text(yaml.dump({
        "saml": {"app": {"provider_name": "test"}},
    }))
    with pytest.raises(ValueError, match="has no URL"):
        load_services(str(tmp_path))


def test_load_services_uses_defaults(tmp_path):
    """Default provider_name and session_duration are applied."""
    (tmp_path / "services.yaml").write_text(yaml.dump({
        "saml": {"aws": "https://signin.aws.amazon.com/saml"},
    }))
    result = load_services(
        str(tmp_path),
        default_provider_name="my-corp-idp",
        default_session_duration_hours=4,
    )
    assert result is not None
    assert result[0].provider_name == "my-corp-idp"
    assert result[0].session_duration_hours == 4


def test_load_services_mixed_protocols(tmp_path):
    """Both SAML and OAuth entries are loaded."""
    (tmp_path / "services.yaml").write_text(yaml.dump({
        "saml": {"aws": "https://aws.com/saml", "gitlab": "https://gl.com/saml"},
        "oauth": {"docs": "https://docs.com/", "wiki": "https://wiki.com/"},
    }))
    result = load_services(str(tmp_path))
    assert result is not None
    assert len(result) == 4
    saml_sps = [sp for sp in result if sp.protocol == "saml"]
    oauth_sps = [sp for sp in result if sp.protocol == "oauth"]
    assert len(saml_sps) == 2
    assert len(oauth_sps) == 2


def test_load_services_invalid_entry_type(tmp_path):
    """Non-string, non-dict entry raises ValueError."""
    (tmp_path / "services.yaml").write_text(yaml.dump({
        "saml": {"aws": 12345},
    }))
    with pytest.raises(ValueError, match="Invalid service provider entry"):
        load_services(str(tmp_path))
