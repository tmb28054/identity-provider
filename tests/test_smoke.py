"""
Smoke tests — start the real server as a subprocess and hit it over HTTP.

These test the fully assembled stack: process startup, port binding, and live
HTTP responses. They are intentionally coarse; detailed assertions live in the
unit tests.

Run alongside the unit tests:
    pytest

Run only smoke tests:
    pytest -m smoke
"""
import base64
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

DATA_DIR = str(Path(__file__).parent.parent / "data")
PORT = 15001  # fixed port unlikely to clash with anything
BASE_URL = f"http://127.0.0.1:{PORT}"


def _wait_for_server(url: str, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return
        except urllib.error.HTTPError:
            return  # server is up, just returned a non-200
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"Server at {url} did not start within {timeout}s")


@pytest.fixture(scope="module")
def server():
    proc = subprocess.Popen(
        [sys.executable, "-m", "identity_provider_server",
         "--data-dir", DATA_DIR, "--port", str(PORT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for_server(f"{BASE_URL}/health")
        yield proc
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def _get(path: str) -> urllib.request.Request:
    return urllib.request.urlopen(f"{BASE_URL}{path}", timeout=5)


def _solve_challenge(body: bytes) -> tuple[str, str]:
    """Extract and solve the math challenge from the form HTML."""
    hash_match = re.search(rb'name="challenge_hash" value="([^"]+)"', body)
    challenge_hash = hash_match.group(1).decode() if hash_match else ""

    q_match = re.search(rb"What is (\d+) (.+?) (\d+)\?", body)
    if not q_match:
        return "0", challenge_hash

    a = int(q_match.group(1))
    op = q_match.group(2)
    b = int(q_match.group(3))

    if op == b"+":
        answer = a + b
    elif op == b"-":
        answer = a - b
    else:
        answer = a * b

    return str(answer), challenge_hash


def _post_with_csrf(path: str, fields: dict) -> bytes:
    """GET the form first to obtain CSRF token and challenge, then POST with it."""
    req = urllib.request.Request(f"{BASE_URL}{path}")
    resp = urllib.request.urlopen(req, timeout=5)
    body = resp.read()
    # Extract CSRF token from form
    match = re.search(rb'name="csrf_token" value="([^"]+)"', body)
    csrf_token = match.group(1).decode() if match else ""
    # Extract csrf_token cookie
    cookie_header = resp.headers.get("Set-Cookie", "")
    cookie_value = ""
    for part in cookie_header.split(";"):
        if part.strip().startswith("csrf_token="):
            cookie_value = part.strip()
            break

    # Solve the challenge
    challenge_answer, challenge_hash = _solve_challenge(body)

    fields["csrf_token"] = csrf_token
    fields["challenge_answer"] = challenge_answer
    fields["challenge_hash"] = challenge_hash
    data = urllib.parse.urlencode(fields).encode()
    post_req = urllib.request.Request(f"{BASE_URL}{path}", data=data, method="POST")
    if cookie_value:
        post_req.add_header("Cookie", cookie_value)
    try:
        return urllib.request.urlopen(post_req, timeout=5).read()
    except urllib.error.HTTPError as e:
        return e.read()


# --- startup ---

@pytest.mark.smoke
def test_server_starts(server):
    assert server.poll() is None  # process still running


# --- GET /health ---

@pytest.mark.smoke
def test_health_check(server):
    r = _get("/health")
    assert r.status == 200


# --- GET /aws ---

@pytest.mark.smoke
def test_login_form_reachable(server):
    r = _get("/aws")
    assert r.status == 200


@pytest.mark.smoke
def test_login_form_content_type(server):
    r = _get("/aws")
    assert "text/html" in r.headers.get("Content-Type", "")


# --- POST /aws ---

@pytest.mark.smoke
def test_invalid_login_returns_error_page(server):
    body = _post_with_csrf("/aws", {"username": "topaztest", "password": "wrong"})
    assert b"Invalid credentials" in body


@pytest.mark.smoke
def test_valid_login_returns_saml_form(server):
    body = _post_with_csrf("/aws", {"username": "topaztest", "password": "random1"})
    assert b"SAMLResponse" in body
    assert b"signin.aws.amazon.com/saml" in body


@pytest.mark.smoke
def test_valid_login_saml_is_valid_base64_xml(server):
    body = _post_with_csrf("/aws", {"username": "topaztest", "password": "random1"})
    start = body.index(b'name="SAMLResponse" value="') + len(b'name="SAMLResponse" value="')
    end = body.index(b'"', start)
    xml = base64.b64decode(body[start:end])
    assert xml.startswith(b"<?xml")


# --- GET /metadata ---

@pytest.mark.smoke
def test_metadata_reachable(server):
    r = _get("/metadata")
    assert r.status == 200


@pytest.mark.smoke
def test_metadata_content_type(server):
    r = _get("/metadata")
    assert "xml" in r.headers.get("Content-Type", "")


@pytest.mark.smoke
def test_metadata_contains_entity_descriptor(server):
    body = _get("/metadata").read()
    assert b"EntityDescriptor" in body


@pytest.mark.smoke
def test_metadata_contains_certificate(server):
    body = _get("/metadata").read()
    assert b"X509Certificate" in body
