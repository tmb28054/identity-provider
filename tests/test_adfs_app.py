"""Tests for ADFS authentication mode in the Flask app."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def data_dir(tmp_path):
    """Create a minimal data directory with certs."""
    src = Path(__file__).parent.parent / "data"
    (tmp_path / "idp.crt").write_text((src / "idp.crt").read_text())
    (tmp_path / "idp.key").write_text((src / "idp.key").read_text())
    return tmp_path


@pytest.fixture
def adfs_config():
    return {
        "host": "ldaps://dc.corp.com",
        "username": "CN=svc,DC=corp",
        "base_dn": "DC=corp,DC=com",
        "password": "svc-pass",
    }


@pytest.fixture
def group_role_map():
    return {
        "AWS-Admins": [{"account_id": "111122223333", "role": "AdminRole"}],
        "AWS-Dev": [{"account_id": "111122223333", "role": "DevRole"}],
    }


def _get_csrf_and_challenge(client):
    """Get a CSRF token and solve the challenge from the login form."""
    resp = client.get("/aws")
    html = resp.data.decode()

    # Extract csrf_token
    import re

    csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    csrf_token = csrf_match.group(1) if csrf_match else ""

    # Extract challenge_hash
    hash_match = re.search(r'name="challenge_hash" value="([^"]+)"', html)
    challenge_hash = hash_match.group(1) if hash_match else ""

    # Get the cookie
    cookie = resp.headers.get("Set-Cookie", "")

    return csrf_token, challenge_hash, resp


def test_adfs_mode_successful_login(data_dir, adfs_config, group_role_map):
    """ADFS mode: successful auth returns SAML response."""
    from identity_provider_server.app import create_app

    app = create_app(
        str(data_dir),
        adfs_config=adfs_config,
        group_role_map=group_role_map,
    )
    app.config["TESTING"] = True
    client = app.test_client()

    # Get CSRF token
    get_resp = client.get("/aws")
    html = get_resp.data.decode()

    import re

    csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    csrf_token = csrf_match.group(1)
    hash_match = re.search(r'name="challenge_hash" value="([^"]+)"', html)
    challenge_hash = hash_match.group(1)

    # Compute the correct challenge answer by brute-forcing small math
    # Instead, mock authenticate_adfs to return groups
    with patch(
        "identity_provider_server.adfs.authenticate_adfs",
        return_value=["AWS-Admins"],
    ):
        with patch(
            "identity_provider_server.app._verify_challenge",
            return_value=True,
        ):
            resp = client.post(
                "/aws",
                data={
                    "username": "alice",
                    "password": "pass",
                    "csrf_token": csrf_token,
                    "challenge_answer": "42",
                    "challenge_hash": challenge_hash,
                },
            )

    assert resp.status_code == 200
    assert b"SAMLResponse" in resp.data


def test_adfs_mode_auth_failure(data_dir, adfs_config, group_role_map):
    """ADFS mode: failed auth returns 401."""
    from identity_provider_server.app import create_app

    app = create_app(
        str(data_dir),
        adfs_config=adfs_config,
        group_role_map=group_role_map,
    )
    app.config["TESTING"] = True
    client = app.test_client()

    get_resp = client.get("/aws")
    html = get_resp.data.decode()

    import re

    csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    csrf_token = csrf_match.group(1)
    hash_match = re.search(r'name="challenge_hash" value="([^"]+)"', html)
    challenge_hash = hash_match.group(1)

    with patch(
        "identity_provider_server.adfs.authenticate_adfs",
        return_value=None,
    ):
        with patch(
            "identity_provider_server.app._verify_challenge",
            return_value=True,
        ):
            resp = client.post(
                "/aws",
                data={
                    "username": "alice",
                    "password": "wrong",
                    "csrf_token": csrf_token,
                    "challenge_answer": "42",
                    "challenge_hash": challenge_hash,
                },
            )

    assert resp.status_code == 401
    assert b"Invalid credentials" in resp.data


def test_adfs_mode_no_role_mapping(data_dir, adfs_config):
    """ADFS mode: user authenticates but has no role mappings → 403."""
    from identity_provider_server.app import create_app

    app = create_app(
        str(data_dir),
        adfs_config=adfs_config,
        group_role_map={},  # empty mapping
    )
    app.config["TESTING"] = True
    client = app.test_client()

    get_resp = client.get("/aws")
    html = get_resp.data.decode()

    import re

    csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    csrf_token = csrf_match.group(1)
    hash_match = re.search(r'name="challenge_hash" value="([^"]+)"', html)
    challenge_hash = hash_match.group(1)

    with patch(
        "identity_provider_server.adfs.authenticate_adfs",
        return_value=["SomeGroup"],
    ):
        with patch(
            "identity_provider_server.app._verify_challenge",
            return_value=True,
        ):
            resp = client.post(
                "/aws",
                data={
                    "username": "alice",
                    "password": "pass",
                    "csrf_token": csrf_token,
                    "challenge_answer": "42",
                    "challenge_hash": challenge_hash,
                },
            )

    assert resp.status_code == 403
    assert b"No roles mapped" in resp.data


def test_adfs_mode_health_check(data_dir, adfs_config):
    """Health check works in ADFS mode (no users.json needed)."""
    from identity_provider_server.app import create_app

    app = create_app(str(data_dir), adfs_config=adfs_config)
    app.config["TESTING"] = True
    client = app.test_client()

    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "healthy"}
