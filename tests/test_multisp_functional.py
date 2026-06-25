"""Functional test for multi-service-provider routing."""

import json
import shutil
import tempfile
from pathlib import Path

import yaml

from identity_provider_server.app import create_app


def test_multi_sp_routes_registered():
    """When services.yaml exists, dynamic routes are registered."""
    tmp = Path(tempfile.mkdtemp())
    try:
        src = Path(__file__).parent.parent / "data"
        shutil.copy(src / "idp.crt", tmp / "idp.crt")
        shutil.copy(src / "idp.key", tmp / "idp.key")
        (tmp / "users.json").write_text(json.dumps([
            {"username": "test", "password": "pass", "roles": [{"account_id": "111", "role": "R"}]}
        ]))
        (tmp / "services.yaml").write_text(yaml.dump({
            "saml": {
                "aws": "https://signin.aws.amazon.com/saml",
                "gitlab": "https://gitlab.example.com/saml",
            },
            "oauth": {
                "docs": "https://docs.example.com/",
            },
        }))

        app = create_app(str(tmp))
        client = app.test_client()

        assert client.get("/aws").status_code == 200
        assert client.get("/gitlab").status_code == 200
        assert client.get("/docs").status_code == 200
        assert client.get("/health").status_code == 200
        assert client.get("/metadata").status_code == 200
    finally:
        shutil.rmtree(tmp)


def test_metadata_lists_saml_sps_only():
    """Metadata includes SAML SP paths but not OAuth paths."""
    tmp = Path(tempfile.mkdtemp())
    try:
        src = Path(__file__).parent.parent / "data"
        shutil.copy(src / "idp.crt", tmp / "idp.crt")
        shutil.copy(src / "idp.key", tmp / "idp.key")
        (tmp / "users.json").write_text(json.dumps([]))
        (tmp / "services.yaml").write_text(yaml.dump({
            "saml": {"aws": "https://signin.aws.amazon.com/saml", "gitlab": "https://gl.com/saml"},
            "oauth": {"docs": "https://docs.example.com/"},
        }))

        app = create_app(str(tmp))
        client = app.test_client()
        meta = client.get("/metadata").data.decode()

        assert "/aws" in meta
        assert "/gitlab" in meta
        assert "/docs" not in meta
    finally:
        shutil.rmtree(tmp)


def test_oauth_sp_redirects_with_token():
    """OAuth SP login redirects with a JWT token."""
    tmp = Path(tempfile.mkdtemp())
    try:
        src = Path(__file__).parent.parent / "data"
        shutil.copy(src / "idp.crt", tmp / "idp.crt")
        shutil.copy(src / "idp.key", tmp / "idp.key")
        (tmp / "users.json").write_text(json.dumps([
            {"username": "alice", "password": "pass", "roles": []}
        ]))
        (tmp / "services.yaml").write_text(yaml.dump({
            "oauth": {"docs": "https://docs.example.com/"},
        }))

        app = create_app(str(tmp))
        app.config["TESTING"] = True
        client = app.test_client()

        from unittest.mock import patch

        # Get CSRF token
        import re

        get_resp = client.get("/docs")
        html = get_resp.data.decode()
        csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', html)
        csrf_token = csrf_match.group(1)

        with patch(
            "identity_provider_server.app._verify_challenge",
            return_value=True,
        ):
            resp = client.post(
                "/docs",
                data={
                    "username": "alice",
                    "password": "pass",
                    "csrf_token": csrf_token,
                    "challenge_answer": "42",
                    "challenge_hash": "x",
                },
            )

        assert resp.status_code == 302
        location = resp.headers["Location"]
        assert location.startswith("https://docs.example.com/")
        assert "token=" in location
    finally:
        shutil.rmtree(tmp)


def test_fallback_aws_route_without_services_yaml():
    """Without services.yaml, /aws route still works (backward compat)."""
    tmp = Path(tempfile.mkdtemp())
    try:
        src = Path(__file__).parent.parent / "data"
        shutil.copy(src / "idp.crt", tmp / "idp.crt")
        shutil.copy(src / "idp.key", tmp / "idp.key")
        (tmp / "users.json").write_text(json.dumps([
            {"username": "test", "password": "pass", "roles": [{"account_id": "111", "role": "R"}]}
        ]))
        # No services.yaml

        app = create_app(str(tmp))
        client = app.test_client()

        assert client.get("/aws").status_code == 200
        assert client.get("/health").status_code == 200
    finally:
        shutil.rmtree(tmp)
