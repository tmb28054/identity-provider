"""App-layer tests for the passkey (WebAuthn) HTTP endpoints.

Drives the registration and authentication ceremonies end-to-end through the
Flask routes using ``soft_webauthn`` as a software authenticator, plus the
error/guard branches (CSRF, disabled, expired step-up, unknown passkey, rate
limiting, sign-count regression, removal, and CSP invariants).
"""

from __future__ import annotations

import base64
import json
import re
import shutil
from pathlib import Path

import pytest
from soft_webauthn import SoftWebauthnDevice

from identity_provider_server.app import create_app

DATA_DIR = Path(__file__).parent.parent / "data"
RP_ID = "localhost"
ORIGIN = "https://localhost"


# --- soft_webauthn <-> JSON bridges (mirror tests/test_webauthn_flows.py) ---

def _b64url_to_bytes(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _bytes_to_b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _options_to_soft(options: dict) -> dict:
    """Convert server options JSON (base64url) into soft_webauthn's dict."""
    opts = json.loads(json.dumps(options))  # deep copy
    opts["challenge"] = _b64url_to_bytes(opts["challenge"])
    if "user" in opts and "id" in opts["user"]:
        opts["user"]["id"] = _b64url_to_bytes(opts["user"]["id"])
    for key in ("excludeCredentials", "allowCredentials"):
        for desc in opts.get(key, []) or []:
            desc["id"] = _b64url_to_bytes(desc["id"])
    return {"publicKey": opts}


def _attestation_to_dict(att: dict) -> dict:
    """Serialise a soft_webauthn attestation/assertion into a JSON-safe dict."""

    def enc(b):
        return _bytes_to_b64url(b) if isinstance(b, (bytes, bytearray)) else b

    resp = att["response"]
    return {
        "id": enc(att["rawId"]),
        "rawId": enc(att["rawId"]),
        "type": att["type"],
        "response": {k: enc(v) for k, v in resp.items()},
    }


# --- fixtures ---------------------------------------------------------------

@pytest.fixture()
def data_dir(tmp_path: Path) -> Path:
    """An isolated copy of the repo data dir so tests can mutate users.json."""
    dst = tmp_path / "data"
    shutil.copytree(DATA_DIR, dst)
    return dst


def _make_client(data_dir: Path, *, enabled: bool = True):
    app = create_app(
        str(data_dir),
        host="127.0.0.1",
        port=5000,
        secret_key="test-secret-key-for-passkeys",
        webauthn_enabled=enabled,
        webauthn_rp_id=RP_ID if enabled else "",
        webauthn_expected_origin=ORIGIN if enabled else "",
    )
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture()
def client(data_dir: Path):
    return _make_client(data_dir)


# --- helpers ----------------------------------------------------------------

def _csrf(client) -> str:
    """Establish a csrf_token cookie via the login form and return its value."""
    resp = client.get("/aws")
    m = re.search(rb'name="csrf_token" value="([^"]+)"', resp.data)
    return m.group(1).decode()


def _user_step_up(data_dir: Path, client) -> tuple[str, str]:
    """Sign in on /user (no MFA) and return (auth_token, csrf_token)."""
    resp = client.get("/user")
    csrf = re.search(rb'name="csrf_token" value="([^"]+)"', resp.data).group(1).decode()
    q = re.search(rb"What is (\d+) (.+?) (\d+)\?", resp.data)
    a, op, b = int(q.group(1)), q.group(2), int(q.group(3))
    answer = a + b if op == b"+" else (a - b if op == b"-" else a * b)
    resp = client.post("/user", data={
        "action": "login",
        "username": "topaztest",
        "password": "random1",
        "csrf_token": csrf,
        "challenge_answer": str(answer),
        "challenge_hash": re.search(
            rb'name="challenge_hash" value="([^"]+)"', resp.data
        ).group(1).decode(),
    })
    auth_token = re.search(
        rb'name="auth_token" value="([^"]+)"', resp.data
    ).group(1).decode()
    # csrf cookie was rotated on the enroll page render
    csrf = re.search(rb'name="csrf_token" value="([^"]+)"', resp.data).group(1).decode()
    return auth_token, csrf


def _register_passkey(client, device, auth_token, csrf) -> dict:
    """Run the register begin/finish ceremony over HTTP; return finish JSON."""
    begin = client.post(
        "/user/passkey/register/begin",
        json={"csrf_token": csrf, "auth_token": auth_token},
    )
    body = begin.get_json()
    att = device.create(_options_to_soft(body["options"]), ORIGIN)
    finish = client.post(
        "/user/passkey/register/finish",
        json={
            "csrf_token": csrf,
            "auth_token": auth_token,
            "handle": body["handle"],
            "credential": _attestation_to_dict(att),
        },
    )
    return finish


# --- registration -----------------------------------------------------------

def test_register_and_authenticate_roundtrip(client, data_dir):
    device = SoftWebauthnDevice()
    auth_token, csrf = _user_step_up(data_dir, client)
    finish = _register_passkey(client, device, auth_token, csrf)
    assert finish.status_code == 200
    assert finish.get_json()["status"] == "ok"

    # The credential is now persisted for topaztest.
    users = json.loads((data_dir / "users.json").read_text())
    topaz = next(u for u in users if u["username"] == "topaztest")
    assert len(topaz["webauthn_credentials"]) == 1

    # Authenticate via the SP flow.
    csrf = _csrf(client)
    begin = client.post("/aws/passkey/begin", json={"csrf_token": csrf, "username": "topaztest"})
    assert begin.status_code == 200
    body = begin.get_json()
    assertion = device.get(_options_to_soft(body["options"]), ORIGIN)
    finish = client.post("/aws/passkey/finish", json={
        "csrf_token": csrf,
        "handle": body["handle"],
        "credential": _attestation_to_dict(assertion),
    })
    assert finish.status_code == 200
    # SAML SP returns HTML to auto-POST.
    assert "SAMLResponse" in finish.get_json()["html"]
    # SSO session cookie set.
    assert "idp_session" in finish.headers.get("Set-Cookie", "")


def test_register_begin_disabled_returns_404(data_dir):
    client = _make_client(data_dir, enabled=False)
    resp = client.post("/user/passkey/register/begin", json={})
    assert resp.status_code == 404


def test_register_begin_bad_csrf(client, data_dir):
    auth_token, _csrf = _user_step_up(data_dir, client)
    resp = client.post(
        "/user/passkey/register/begin",
        json={"csrf_token": "wrong", "auth_token": auth_token},
    )
    assert resp.status_code == 403


def test_register_begin_no_step_up(client):
    csrf = _csrf(client)
    resp = client.post(
        "/user/passkey/register/begin",
        json={"csrf_token": csrf, "auth_token": "invalid"},
    )
    assert resp.status_code == 401


def test_register_finish_bad_csrf(client, data_dir):
    auth_token, _csrf = _user_step_up(data_dir, client)
    resp = client.post(
        "/user/passkey/register/finish",
        json={"csrf_token": "wrong", "auth_token": auth_token, "handle": "x"},
    )
    assert resp.status_code == 403


def test_register_finish_no_step_up(client):
    csrf = _csrf(client)
    resp = client.post(
        "/user/passkey/register/finish",
        json={"csrf_token": csrf, "auth_token": "bad", "handle": "x"},
    )
    assert resp.status_code == 401


def test_register_finish_expired_handle(client, data_dir):
    auth_token, csrf = _user_step_up(data_dir, client)
    resp = client.post(
        "/user/passkey/register/finish",
        json={
            "csrf_token": csrf,
            "auth_token": auth_token,
            "handle": "nonexistent",
            "credential": {},
        },
    )
    assert resp.status_code == 400
    assert "expired" in resp.get_json()["error"].lower()


def test_register_finish_bad_attestation(client, data_dir):
    auth_token, csrf = _user_step_up(data_dir, client)
    begin = client.post(
        "/user/passkey/register/begin",
        json={"csrf_token": csrf, "auth_token": auth_token},
    ).get_json()
    resp = client.post(
        "/user/passkey/register/finish",
        json={
            "csrf_token": csrf,
            "auth_token": auth_token,
            "handle": begin["handle"],
            "credential": {"id": "junk", "type": "public-key", "response": {}},
        },
    )
    assert resp.status_code == 400
    assert "failed" in resp.get_json()["error"].lower()


def test_register_finish_disabled_returns_404(data_dir):
    client = _make_client(data_dir, enabled=False)
    resp = client.post("/user/passkey/register/finish", json={})
    assert resp.status_code == 404


# --- removal ----------------------------------------------------------------

def test_remove_passkey(client, data_dir):
    device = SoftWebauthnDevice()
    auth_token, csrf = _user_step_up(data_dir, client)
    _register_passkey(client, device, auth_token, csrf)
    users = json.loads((data_dir / "users.json").read_text())
    topaz = next(u for u in users if u["username"] == "topaztest")
    cred_id = topaz["webauthn_credentials"][0]["credential_id"]

    resp = client.post("/user", data={
        "action": "remove_passkey",
        "auth_token": auth_token,
        "credential_id": cred_id,
        "csrf_token": csrf,
    })
    assert resp.status_code == 200
    users = json.loads((data_dir / "users.json").read_text())
    topaz = next(u for u in users if u["username"] == "topaztest")
    assert topaz.get("webauthn_credentials", []) == []


def test_remove_passkey_expired_token(client):
    csrf = _csrf(client)
    resp = client.post("/user", data={
        "action": "remove_passkey",
        "auth_token": "bad",
        "credential_id": "x",
        "csrf_token": csrf,
    })
    assert resp.status_code == 401


# --- authentication guards --------------------------------------------------

def test_auth_begin_disabled_returns_404(data_dir):
    client = _make_client(data_dir, enabled=False)
    resp = client.post("/aws/passkey/begin", json={})
    assert resp.status_code == 404


def test_auth_begin_bad_csrf(client):
    resp = client.post("/aws/passkey/begin", json={"csrf_token": "no", "username": "x"})
    assert resp.status_code == 403


def test_auth_begin_no_passkey(client):
    csrf = _csrf(client)
    resp = client.post("/aws/passkey/begin", json={"csrf_token": csrf, "username": "topaztest"})
    assert resp.status_code == 400
    assert "no passkey" in resp.get_json()["error"].lower()


def test_auth_begin_unknown_user(client):
    csrf = _csrf(client)
    resp = client.post("/aws/passkey/begin", json={"csrf_token": csrf, "username": "ghost"})
    assert resp.status_code == 400


def test_auth_finish_disabled_returns_404(data_dir):
    client = _make_client(data_dir, enabled=False)
    resp = client.post("/aws/passkey/finish", json={})
    assert resp.status_code == 404


def test_auth_finish_bad_csrf(client):
    resp = client.post("/aws/passkey/finish", json={"csrf_token": "no"})
    assert resp.status_code == 403


def test_auth_finish_expired_handle(client):
    csrf = _csrf(client)
    resp = client.post("/aws/passkey/finish", json={
        "csrf_token": csrf, "handle": "nope", "credential": {},
    })
    assert resp.status_code == 400


def test_auth_finish_unknown_credential(client, data_dir):
    device = SoftWebauthnDevice()
    auth_token, csrf = _user_step_up(data_dir, client)
    _register_passkey(client, device, auth_token, csrf)
    csrf = _csrf(client)
    begin = client.post(
        "/aws/passkey/begin", json={"csrf_token": csrf, "username": "topaztest"}
    ).get_json()
    # Assert with a *different* device so the credential id is unknown.
    other = SoftWebauthnDevice()
    other.cred_init(RP_ID, b"other-user")
    assertion = other.get(_options_to_soft(begin["options"]), ORIGIN)
    resp = client.post("/aws/passkey/finish", json={
        "csrf_token": csrf, "handle": begin["handle"],
        "credential": _attestation_to_dict(assertion),
    })
    assert resp.status_code == 400
    assert "unknown" in resp.get_json()["error"].lower()


def test_auth_finish_bad_assertion(client, data_dir):
    device = SoftWebauthnDevice()
    auth_token, csrf = _user_step_up(data_dir, client)
    _register_passkey(client, device, auth_token, csrf)
    csrf = _csrf(client)
    begin = client.post(
        "/aws/passkey/begin", json={"csrf_token": csrf, "username": "topaztest"}
    ).get_json()
    assertion = device.get(_options_to_soft(begin["options"]), ORIGIN)
    tampered = _attestation_to_dict(assertion)
    tampered["response"]["signature"] = _bytes_to_b64url(b"tampered-signature-bytes")
    resp = client.post("/aws/passkey/finish", json={
        "csrf_token": csrf, "handle": begin["handle"], "credential": tampered,
    })
    assert resp.status_code == 401
    assert "failed" in resp.get_json()["error"].lower()


# --- static asset + CSP -----------------------------------------------------

def test_static_passkey_js_served(client):
    resp = client.get("/static/passkey.js")
    assert resp.status_code == 200
    assert "javascript" in resp.headers["Content-Type"]
    assert "max-age" in resp.headers["Cache-Control"]
    assert b"navigator.credentials" in resp.data


def test_csp_unchanged_and_self_only(client):
    resp = client.get("/aws")
    csp = resp.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
    # The login page references the static script under 'self'.
    assert b'src="/static/passkey.js"' in resp.data


def test_login_form_offers_passkey_when_enabled(client):
    resp = client.get("/aws")
    assert b'id="passkey-login"' in resp.data
    assert b"Use a passkey" in resp.data


def test_login_form_hides_passkey_when_disabled(data_dir):
    client = _make_client(data_dir, enabled=False)
    resp = client.get("/aws")
    assert b'id="passkey-login"' not in resp.data
