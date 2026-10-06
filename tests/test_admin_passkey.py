"""Admin passkey (WebAuthn) login tests — Phase 3.

Exercises the two-step ``/admin/passkey/begin|finish`` ceremony (drives it with
``soft_webauthn``), the ``idpadmin`` authorization re-check, the shared
``idp_session`` issuance, and every guard branch. The existing password + TOTP
admin login path is covered by ``tests/test_admin_full.py``.
"""

from __future__ import annotations

import base64
import json
import re
import shutil
from pathlib import Path

import bcrypt
import pytest
from soft_webauthn import SoftWebauthnDevice

from identity_provider_server.app import create_app

DATA_SRC = Path(__file__).parent.parent / "data"
RP_ID = "localhost"
ORIGIN = "https://localhost"
ADMIN_PW = "AdminPass123!"


# --- soft_webauthn <-> JSON bridges -----------------------------------------

def _b64url_to_bytes(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _bytes_to_b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _options_to_soft(options: dict) -> dict:
    opts = json.loads(json.dumps(options))
    opts["challenge"] = _b64url_to_bytes(opts["challenge"])
    if "user" in opts and "id" in opts["user"]:
        opts["user"]["id"] = _b64url_to_bytes(opts["user"]["id"])
    for key in ("excludeCredentials", "allowCredentials"):
        for desc in opts.get(key, []) or []:
            desc["id"] = _b64url_to_bytes(desc["id"])
    return {"publicKey": opts}


def _att_to_dict(att: dict) -> dict:
    def enc(b):
        return _bytes_to_b64url(b) if isinstance(b, (bytes, bytearray)) else b

    resp = att["response"]
    return {
        "id": enc(att["rawId"]),
        "rawId": enc(att["rawId"]),
        "type": att["type"],
        "response": {k: enc(v) for k, v in resp.items()},
    }


# --- fixtures / helpers -----------------------------------------------------

@pytest.fixture()
def app(tmp_path):
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    pw = bcrypt.hashpw(ADMIN_PW.encode(), bcrypt.gensalt(rounds=4)).decode()
    users = [
        {"username": "admin", "password": pw, "roles": [], "claims": ["idpadmin"]},
        {"username": "bob", "password": pw, "roles": [], "claims": ["developer"]},
    ]
    (tmp_path / "users.json").write_text(json.dumps(users))
    (tmp_path / "claims.json").write_text(json.dumps(["idpadmin", "developer"]))
    application = create_app(
        str(tmp_path), secret_key="adminsecret-00000000000000000000000", secure_cookies=False,
        webauthn_enabled=True, webauthn_rp_id=RP_ID, webauthn_expected_origin=ORIGIN,
    )
    application.config["TESTING"] = True
    application.config["_TMP"] = tmp_path
    return application


def _register_passkey(client, device, username="admin"):
    """Sign in on /user (no MFA) and register a passkey for ``username``."""
    resp = client.get("/user")
    csrf = re.search(rb'name="csrf_token" value="([^"]+)"', resp.data).group(1).decode()
    q = re.search(rb"What is (\d+) (.+?) (\d+)\?", resp.data)
    a, op, b = int(q.group(1)), q.group(2), int(q.group(3))
    ans = a + b if op == b"+" else (a - b if op == b"-" else a * b)
    resp = client.post("/user", data={
        "action": "login", "username": username, "password": ADMIN_PW,
        "csrf_token": csrf, "challenge_answer": str(ans),
        "challenge_hash": re.search(
            rb'name="challenge_hash" value="([^"]+)"', resp.data
        ).group(1).decode(),
    })
    auth = re.search(rb'name="auth_token" value="([^"]+)"', resp.data).group(1).decode()
    csrf = re.search(rb'name="csrf_token" value="([^"]+)"', resp.data).group(1).decode()
    begin = client.post("/user/passkey/register/begin",
                        json={"csrf_token": csrf, "auth_token": auth}).get_json()
    att = device.create(_options_to_soft(begin["options"]), ORIGIN)
    client.post("/user/passkey/register/finish", json={
        "csrf_token": csrf, "auth_token": auth, "handle": begin["handle"],
        "credential": _att_to_dict(att),
    })


def _admin_csrf(client) -> str:
    return re.search(
        rb'name="csrf_token" value="([^"]+)"', client.get("/admin").data
    ).group(1).decode()


def _uv_get(device, options, origin):
    """Produce an assertion with the user-verification (UV) flag set.

    ``soft_webauthn`` only sets user-present (``flags = 0x01``). The admin
    passkey flow now requires user verification, so this mirrors the library's
    ``get`` with ``flags = 0x05`` (UP|UV) and re-signs over that data.
    """
    import json as _json
    from base64 import urlsafe_b64encode
    from hashlib import sha256
    from struct import pack

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    device.sign_count += 1
    client_data = _json.dumps({
        "type": "webauthn.get",
        "challenge": urlsafe_b64encode(
            options["publicKey"]["challenge"]
        ).decode("ascii").rstrip("="),
        "origin": origin,
    }).encode("utf-8")
    client_data_hash = sha256(client_data).digest()
    rp_id_hash = sha256(device.rp_id.encode("ascii")).digest()
    flags = b"\x05"  # user-present + user-verified
    authenticator_data = rp_id_hash + flags + pack(">I", device.sign_count)
    signature = device.private_key.sign(
        authenticator_data + client_data_hash, ec.ECDSA(hashes.SHA256())
    )
    return {
        "id": urlsafe_b64encode(device.credential_id),
        "rawId": device.credential_id,
        "response": {
            "authenticatorData": authenticator_data,
            "clientDataJSON": client_data,
            "signature": signature,
            "userHandle": device.user_handle,
        },
        "type": "public-key",
    }


def _admin_passkey_login(client, device, username="admin", *, user_verified=True):
    csrf = _admin_csrf(client)
    begin = client.post("/admin/passkey/begin",
                        json={"csrf_token": csrf, "username": username})
    if begin.status_code != 200:
        return begin
    body = begin.get_json()
    opts = _options_to_soft(body["options"])
    assertion = _uv_get(device, opts, ORIGIN) if user_verified else device.get(opts, ORIGIN)
    return client.post("/admin/passkey/finish", json={
        "csrf_token": csrf, "handle": body["handle"],
        "credential": _att_to_dict(assertion),
    })


# --- tests ------------------------------------------------------------------

def test_admin_login_form_offers_passkey(app):
    resp = app.test_client().get("/admin")
    assert b'id="passkey-login"' in resp.data
    assert b"/admin/passkey/begin" in resp.data


def test_admin_passkey_login_success(app):
    client = app.test_client()
    device = SoftWebauthnDevice()
    _register_passkey(client, device, "admin")
    resp = _admin_passkey_login(client, device, "admin")
    assert resp.status_code == 200
    assert resp.get_json()["redirect"] == "/admin"
    assert "idp_session" in resp.headers.get("Set-Cookie", "")
    # The session cookie actually grants the admin panel.
    assert b"Add User" in client.get("/admin").data


def test_admin_passkey_begin_non_admin_indistinguishable(app):
    """A non-idpadmin account yields the same 200+options shape as an admin, so
    begin does not enumerate idpadmin membership. The finish still fails."""
    client = app.test_client()
    device = SoftWebauthnDevice()
    _register_passkey(client, device, "bob")
    csrf = _admin_csrf(client)
    resp = client.post("/admin/passkey/begin",
                       json={"csrf_token": csrf, "username": "bob"})
    assert resp.status_code == 200
    assert resp.get_json()["options"]["allowCredentials"]


def test_admin_passkey_begin_unknown_user_indistinguishable(app):
    client = app.test_client()
    csrf = _admin_csrf(client)
    resp = client.post("/admin/passkey/begin",
                       json={"csrf_token": csrf, "username": "ghost"})
    assert resp.status_code == 200
    assert resp.get_json()["options"]["allowCredentials"]


def test_admin_passkey_non_admin_cannot_finish(app):
    """Even though begin returns decoy options, a non-admin cannot finish."""
    client = app.test_client()
    device = SoftWebauthnDevice()
    _register_passkey(client, device, "bob")
    csrf = _admin_csrf(client)
    begin = client.post("/admin/passkey/begin",
                        json={"csrf_token": csrf, "username": "bob"}).get_json()
    assertion = _uv_get(device, _options_to_soft(begin["options"]), ORIGIN)
    resp = client.post("/admin/passkey/finish", json={
        "csrf_token": csrf, "handle": begin["handle"],
        "credential": _att_to_dict(assertion),
    })
    assert resp.status_code == 400


def test_admin_passkey_begin_bad_csrf(app):
    resp = app.test_client().post("/admin/passkey/begin",
                                  json={"csrf_token": "no", "username": "admin"})
    assert resp.status_code == 403


def test_admin_passkey_finish_bad_csrf(app):
    resp = app.test_client().post("/admin/passkey/finish", json={"csrf_token": "no"})
    assert resp.status_code == 403


def test_admin_passkey_finish_expired_handle(app):
    client = app.test_client()
    csrf = _admin_csrf(client)
    resp = client.post("/admin/passkey/finish",
                       json={"csrf_token": csrf, "handle": "nope", "credential": {}})
    assert resp.status_code == 400


def test_admin_passkey_finish_unknown_credential(app):
    client = app.test_client()
    device = SoftWebauthnDevice()
    _register_passkey(client, device, "admin")
    csrf = _admin_csrf(client)
    begin = client.post("/admin/passkey/begin",
                        json={"csrf_token": csrf, "username": "admin"}).get_json()
    other = SoftWebauthnDevice()
    other.cred_init(RP_ID, b"other")
    assertion = other.get(_options_to_soft(begin["options"]), ORIGIN)
    resp = client.post("/admin/passkey/finish", json={
        "csrf_token": csrf, "handle": begin["handle"],
        "credential": _att_to_dict(assertion),
    })
    assert resp.status_code == 400
    assert "unknown passkey" in resp.get_json()["error"].lower()


def test_admin_passkey_finish_bad_assertion(app):
    client = app.test_client()
    device = SoftWebauthnDevice()
    _register_passkey(client, device, "admin")
    csrf = _admin_csrf(client)
    begin = client.post("/admin/passkey/begin",
                        json={"csrf_token": csrf, "username": "admin"}).get_json()
    assertion = device.get(_options_to_soft(begin["options"]), ORIGIN)
    tampered = _att_to_dict(assertion)
    tampered["response"]["signature"] = _bytes_to_b64url(b"tampered")
    resp = client.post("/admin/passkey/finish", json={
        "csrf_token": csrf, "handle": begin["handle"], "credential": tampered,
    })
    assert resp.status_code == 401
    assert "failed" in resp.get_json()["error"].lower()


def test_admin_passkey_finish_idpadmin_revoked_after_begin(app):
    """Revoking idpadmin between begin and finish rejects the assertion.

    ``bob`` is granted idpadmin and a passkey, starts the ceremony, then has the
    claim revoked (in place, via the admin panel) before ``finish`` — the finish
    re-check must reject it.
    """
    # Give bob idpadmin and register a passkey for bob.
    bob_client = app.test_client()
    device = SoftWebauthnDevice()
    # Grant bob idpadmin via the admin panel (in-place mutation the admin
    # routes actually observe), acting as the already-admin "admin" account.
    admin_client = app.test_client()
    admin_device = SoftWebauthnDevice()
    _register_passkey(admin_client, admin_device, "admin")
    login = _admin_passkey_login(admin_client, admin_device, "admin")
    assert login.status_code == 200
    panel = admin_client.get("/admin").data.decode()
    auth = re.search(r'name="auth_token" value="([^"]+)"', panel).group(1)
    admin_csrf = re.search(r'name="csrf_token" value="([^"]+)"', panel).group(1)
    grant = admin_client.post("/admin", data={
        "csrf_token": admin_csrf, "auth_token": auth, "action": "set_claims",
        "claims_user": "bob", "user_claims": "developer,idpadmin",
    })
    assert b"Claims updated" in grant.data

    _register_passkey(bob_client, device, "bob")
    csrf = _admin_csrf(bob_client)
    begin = bob_client.post("/admin/passkey/begin",
                            json={"csrf_token": csrf, "username": "bob"}).get_json()
    assertion = device.get(_options_to_soft(begin["options"]), ORIGIN)

    # Revoke bob's idpadmin (in place) before finish. Fetch fresh tokens — the
    # csrf cookie rotates on each admin render.
    panel = admin_client.get("/admin").data.decode()
    auth = re.search(r'name="auth_token" value="([^"]+)"', panel).group(1)
    admin_csrf = re.search(r'name="csrf_token" value="([^"]+)"', panel).group(1)
    revoke = admin_client.post("/admin", data={
        "csrf_token": admin_csrf, "auth_token": auth, "action": "set_claims",
        "claims_user": "bob", "user_claims": "developer",
    })
    assert b"Claims updated" in revoke.data

    resp = bob_client.post("/admin/passkey/finish", json={
        "csrf_token": csrf, "handle": begin["handle"],
        "credential": _att_to_dict(assertion),
    })
    assert resp.status_code == 400
    assert "unknown passkey" in resp.get_json()["error"].lower()


def test_admin_passkey_begin_rate_limited(app):
    """Per-account throttle: bad admin logins for 'admin' block begin('admin')."""
    client = app.test_client()
    for _ in range(6):
        html = client.get("/admin").data.decode()
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
        q = re.search(r"What is (\d+) (.+?) (\d+)\?", html)
        a, op, b = int(q.group(1)), q.group(2), int(q.group(3))
        ans = str(a + b if op == "+" else (a - b if op == "-" else a * b))
        ch = re.search(r'name="challenge_hash" value="([^"]+)"', html).group(1)
        client.post("/admin", data={
            "csrf_token": csrf, "action": "login", "username": "admin",
            "password": "WRONG", "challenge_answer": ans, "challenge_hash": ch,
        })
    csrf = _admin_csrf(client)
    resp = client.post("/admin/passkey/begin",
                       json={"csrf_token": csrf, "username": "admin"})
    assert resp.status_code == 429


def test_admin_passkey_finish_rate_limited(app):
    """Per-IP throttle: repeated bad finish calls trip the IP limiter."""
    client = app.test_client()
    for _ in range(6):
        csrf = _admin_csrf(client)
        client.post("/admin/passkey/finish",
                    json={"csrf_token": csrf, "handle": "x", "credential": {}})
    csrf = _admin_csrf(client)
    resp = client.post("/admin/passkey/finish",
                       json={"csrf_token": csrf, "handle": "x", "credential": {}})
    assert resp.status_code == 429


def test_admin_passkey_disabled_returns_404(tmp_path):
    """With webauthn off, the admin passkey endpoints are absent (404)."""
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    pw = bcrypt.hashpw(ADMIN_PW.encode(), bcrypt.gensalt(rounds=4)).decode()
    (tmp_path / "users.json").write_text(json.dumps(
        [{"username": "admin", "password": pw, "roles": [], "claims": ["idpadmin"]}]
    ))
    application = create_app(str(tmp_path), secret_key="s-000000000000000000000000000000000", secure_cookies=False)
    application.config["TESTING"] = True
    client = application.test_client()
    csrf = _admin_csrf(client)
    resp = client.post("/admin/passkey/begin",
                       json={"csrf_token": csrf, "username": "admin"})
    assert resp.status_code == 404
    resp = client.post("/admin/passkey/finish", json={"csrf_token": csrf})
    assert resp.status_code == 404
