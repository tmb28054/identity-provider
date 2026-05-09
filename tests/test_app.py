import base64
import re
from pathlib import Path

import pytest
from lxml import etree

from identity_provider_server.app import create_app

DATA_DIR = str(Path(__file__).parent.parent / "data")


@pytest.fixture()
def client():
    app = create_app(DATA_DIR, host="127.0.0.1", port=5000)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _solve_challenge(html: bytes) -> tuple[str, str]:
    """Extract the challenge question from the form and compute the answer."""
    hash_match = re.search(rb'name="challenge_hash" value="([^"]+)"', html)
    challenge_hash = hash_match.group(1).decode() if hash_match else ""

    # Extract the question text from the challenge-question div
    q_match = re.search(rb"What is (\d+) (.+?) (\d+)\?", html)
    if not q_match:
        return "0", challenge_hash

    a = int(q_match.group(1))
    op = q_match.group(2)
    b = int(q_match.group(3))

    if op == b"+":
        answer = a + b
    elif op == b"-":
        answer = a - b
    else:  # × (UTF-8: \xc3\x97)
        answer = a * b

    return str(answer), challenge_hash


def _login(client, username="topaztest", password="random1"):
    """Helper: get CSRF token, solve challenge, then POST login."""
    form_resp = client.get("/aws")
    csrf_match = re.search(rb'name="csrf_token" value="([^"]+)"', form_resp.data)
    csrf_token = csrf_match.group(1).decode() if csrf_match else ""
    challenge_answer, challenge_hash = _solve_challenge(form_resp.data)
    return client.post(
        "/aws",
        data={
            "username": username,
            "password": password,
            "csrf_token": csrf_token,
            "challenge_answer": challenge_answer,
            "challenge_hash": challenge_hash,
        },
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


def test_login_form_has_challenge(client):
    data = client.get("/aws").data
    assert b'name="challenge_hash"' in data
    assert b"What is" in data
    assert b'name="challenge_answer"' in data


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


# --- POST /aws — challenge verification ---

def test_wrong_challenge_answer_returns_401(client):
    form_resp = client.get("/aws")
    csrf_match = re.search(rb'name="csrf_token" value="([^"]+)"', form_resp.data)
    csrf_token = csrf_match.group(1).decode()
    hash_match = re.search(rb'name="challenge_hash" value="([^"]+)"', form_resp.data)
    challenge_hash = hash_match.group(1).decode()
    r = client.post("/aws", data={
        "username": "topaztest",
        "password": "random1",
        "csrf_token": csrf_token,
        "challenge_answer": "99999",
        "challenge_hash": challenge_hash,
    })
    assert r.status_code == 401
    assert b"Incorrect answer" in r.data


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
