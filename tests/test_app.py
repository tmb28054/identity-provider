import base64
import re
from pathlib import Path

import pytest
from lxml import etree

from identity_provider_server.app import create_app

DATA_DIR = str(Path(__file__).parent.parent / "data")


@pytest.fixture(scope="module")
def client():
    app = create_app(DATA_DIR, host="127.0.0.1", port=5000)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _login(client, username="topaztest", password="random1"):
    """Helper: get CSRF token then POST login."""
    # Get the login form to obtain CSRF token
    form_resp = client.get("/aws")
    csrf_match = re.search(rb'name="csrf_token" value="([^"]+)"', form_resp.data)
    csrf_token = csrf_match.group(1).decode() if csrf_match else ""
    # Set the cookie that the GET response would have set
    return client.post(
        "/aws",
        data={"username": username, "password": password, "csrf_token": csrf_token},
    )


# --- GET /health ---

def test_health_check(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "healthy"


# --- GET /aws ---

def test_login_form_status(client):
    r = client.get("/aws")
    assert r.status_code == 200


def test_login_form_has_fields(client):
    data = client.get("/aws").data
    assert b'name="username"' in data
    assert b'name="password"' in data


def test_login_form_has_csrf_token(client):
    data = client.get("/aws").data
    assert b'name="csrf_token"' in data


# --- POST /aws — invalid credentials ---

def test_wrong_password_returns_401(client):
    r = _login(client, "topaztest", "wrong")
    assert r.status_code == 401


def test_unknown_user_returns_401(client):
    r = _login(client, "nobody", "x")
    assert r.status_code == 401


def test_invalid_credentials_shows_error(client):
    r = _login(client, "topaztest", "wrong")
    assert b"Invalid credentials" in r.data


# --- POST /aws — CSRF protection ---

def test_missing_csrf_returns_403(client):
    r = client.post("/aws", data={"username": "topaztest", "password": "random1"})
    assert r.status_code == 403


# --- POST /aws — valid credentials ---

def test_valid_login_returns_200(client):
    r = _login(client)
    assert r.status_code == 200


def test_valid_login_contains_saml_response_field(client):
    r = _login(client)
    assert b'name="SAMLResponse"' in r.data


def test_valid_login_posts_to_aws_acs(client):
    r = _login(client)
    assert b"signin.aws.amazon.com/saml" in r.data


def test_valid_login_saml_is_decodable(client):
    r = _login(client)
    start = r.data.index(b'name="SAMLResponse" value="') + len(b'name="SAMLResponse" value="')
    end = r.data.index(b'"', start)
    xml = base64.b64decode(r.data[start:end])
    assert xml.startswith(b"<?xml")


def test_valid_login_saml_contains_username(client):
    r = _login(client)
    start = r.data.index(b'name="SAMLResponse" value="') + len(b'name="SAMLResponse" value="')
    end = r.data.index(b'"', start)
    xml = base64.b64decode(r.data[start:end])
    assert b"topaztest" in xml


def test_valid_login_saml_contains_role(client):
    r = _login(client)
    start = r.data.index(b'name="SAMLResponse" value="') + len(b'name="SAMLResponse" value="')
    end = r.data.index(b'"', start)
    xml = base64.b64decode(r.data[start:end])
    assert b"topaztestrole" in xml


# --- GET /metadata ---

def test_metadata_status(client):
    r = client.get("/metadata")
    assert r.status_code == 200


def test_metadata_content_type(client):
    r = client.get("/metadata")
    assert "xml" in r.content_type


def test_metadata_is_valid_xml(client):
    r = client.get("/metadata")
    etree.fromstring(r.data)  # raises if invalid


def test_metadata_entity_descriptor(client):
    r = client.get("/metadata")
    root = etree.fromstring(r.data)
    assert "EntityDescriptor" in root.tag


def test_metadata_contains_certificate(client):
    r = client.get("/metadata")
    assert b"X509Certificate" in r.data


def test_metadata_sso_location(client):
    r = client.get("/metadata")
    assert b"/aws" in r.data


def test_metadata_entity_id_matches_host_port(client):
    r = client.get("/metadata")
    assert b"http://127.0.0.1:5000/metadata" in r.data
