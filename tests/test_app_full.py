"""Full-flow coverage for app.py.

Drives the SP login flows (password-only, MFA via single-use ticket, session
reuse), the /user self-service actions (enroll, disable, change_password,
force_change), the /recover flow, the metadata route, security headers, and
ADFS mode — through the Flask test client with mocks where needed.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from unittest import mock

import bcrypt
import pyotp
import pytest
import yaml

from identity_provider_server.app import create_app
from identity_provider_server.tokens import PURPOSE_SESSION, issue_token

DATA_SRC = Path(__file__).parent.parent / "data"
PW = "Str0ng-Passw0rd!"


def _write_app(tmp_path, users, services=None, **kwargs):
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    (tmp_path / "users.json").write_text(json.dumps(users))
    if services is not None:
        (tmp_path / "services.yaml").write_text(yaml.dump(services))
    kwargs.setdefault("secure_cookies", False)
    kwargs.setdefault("trust_proxy", False)  # so REMOTE_ADDR overrides work in tests
    app = create_app(str(tmp_path), secret_key="appsecret", **kwargs)
    app.config["TESTING"] = True
    return app


def _hash(pw=PW):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=4)).decode()


def _solve(html: bytes):
    h = re.search(rb'name="challenge_hash" value="([^"]+)"', html)
    q = re.search(rb"What is (\d+) (.+?) (\d+)\?", html)
    a, op, b = int(q.group(1)), q.group(2), int(q.group(3))
    ans = a + b if op == b"+" else a - b if op == b"-" else a * b
    return str(ans), h.group(1).decode()


def _csrf(html: bytes):
    return re.search(rb'name="csrf_token" value="([^"]+)"', html).group(1).decode()


# --- SP login: password only (no MFA) ---------------------------------------

def test_saml_login_no_mfa(tmp_path):
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [{"account_id": "1", "role": "R"}],
         "claims": []}
    ])
    client = app.test_client()
    form = client.get("/aws")
    ans, ch = _solve(form.data)
    resp = client.post("/aws", data={
        "username": "bob", "password": PW, "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    assert b"SAMLResponse" in resp.data


def test_oauth_login_no_mfa(tmp_path):
    app = _write_app(
        tmp_path,
        [{"username": "bob", "password": _hash(), "roles": [], "claims": ["dev"],
          "email": "b@e.com"}],
        services={"oauth": {"wiki": {"url": "https://wiki.example/cb",
                                      "token_expiry_minutes": 60}}},
    )
    client = app.test_client()
    form = client.get("/wiki")
    ans, ch = _solve(form.data)
    resp = client.post("/wiki", data={
        "username": "bob", "password": PW, "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    assert resp.status_code == 302
    assert "token=" in resp.headers["Location"]


# --- SP login: MFA via single-use ticket ------------------------------------

def _login_to_mfa(client, path="/aws", username="bob"):
    form = client.get(path)
    ans, ch = _solve(form.data)
    resp = client.post(path, data={
        "username": username, "password": PW, "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    # Should render the TOTP form with an mfa_ticket.
    ticket = re.search(rb'name="mfa_ticket" value="([^"]+)"', resp.data).group(1).decode()
    csrf = _csrf(resp.data)
    return csrf, ticket


def test_saml_login_with_mfa_ticket(tmp_path):
    secret = pyotp.random_base32()
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [{"account_id": "1", "role": "R"}],
         "claims": [], "totp_secret": secret}
    ])
    client = app.test_client()
    csrf, ticket = _login_to_mfa(client)
    resp = client.post("/aws", data={
        "csrf_token": csrf, "totp_step": "1", "mfa_ticket": ticket,
        "totp_code": pyotp.TOTP(secret).now(),
    })
    assert b"SAMLResponse" in resp.data


def test_oauth_login_with_mfa_ticket(tmp_path):
    secret = pyotp.random_base32()
    app = _write_app(
        tmp_path,
        [{"username": "bob", "password": _hash(), "roles": [], "claims": [],
          "totp_secret": secret}],
        services={"oauth": {"wiki": {"url": "https://wiki.example/cb",
                                      "token_expiry_minutes": 60}}},
    )
    client = app.test_client()
    csrf, ticket = _login_to_mfa(client, "/wiki")
    resp = client.post("/wiki", data={
        "csrf_token": csrf, "totp_step": "1", "mfa_ticket": ticket,
        "totp_code": pyotp.TOTP(secret).now(),
    })
    assert resp.status_code == 302
    assert "token=" in resp.headers["Location"]


def test_mfa_ticket_wrong_code_rerenders(tmp_path):
    secret = pyotp.random_base32()
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "totp_secret": secret}
    ])
    client = app.test_client()
    csrf, ticket = _login_to_mfa(client)
    resp = client.post("/aws", data={
        "csrf_token": csrf, "totp_step": "1", "mfa_ticket": ticket, "totp_code": "000000",
    })
    assert resp.status_code == 401
    assert b"Invalid code" in resp.data


def test_mfa_step_without_ticket_rejected(tmp_path):
    secret = pyotp.random_base32()
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "totp_secret": secret}
    ])
    client = app.test_client()
    form = client.get("/aws")
    resp = client.post("/aws", data={
        "csrf_token": _csrf(form.data), "totp_step": "1",
        "totp_code": pyotp.TOTP(secret).now(),
    })
    assert b"SAMLResponse" not in resp.data


def test_mfa_ticket_for_user_without_secret(tmp_path):
    """A ticket for a user who lost their secret is rejected at the TOTP step."""
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": []}
    ])
    # Manually craft a valid ticket for bob (no totp_secret on the account).
    from identity_provider_server.tokens import PURPOSE_MFA_PENDING, issue_token as it
    ticket = it("appsecret", "bob|nonce123", PURPOSE_MFA_PENDING)
    client = app.test_client()
    form = client.get("/aws")
    resp = client.post("/aws", data={
        "csrf_token": _csrf(form.data), "totp_step": "1", "mfa_ticket": ticket,
        "totp_code": "123456",
    })
    assert b"Invalid request" in resp.data


# --- login failures ---------------------------------------------------------

def test_login_wrong_password(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    form = client.get("/aws")
    ans, ch = _solve(form.data)
    resp = client.post("/aws", data={
        "username": "bob", "password": "WRONG", "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    assert resp.status_code == 401
    assert b"Invalid credentials" in resp.data


def test_login_bad_captcha(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    form = client.get("/aws")
    resp = client.post("/aws", data={
        "username": "bob", "password": PW, "csrf_token": _csrf(form.data),
        "challenge_answer": "99999", "challenge_hash": "bad",
    })
    assert resp.status_code == 401
    assert b"Incorrect answer" in resp.data


def test_login_bad_csrf(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    resp = app.test_client().post("/aws", data={"username": "bob", "password": PW})
    assert resp.status_code == 403


def test_login_account_locked_after_attempts(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    for _ in range(6):
        form = client.get("/aws")
        ans, ch = _solve(form.data)
        client.post("/aws", data={
            "username": "bob", "password": "WRONG", "csrf_token": _csrf(form.data),
            "challenge_answer": ans, "challenge_hash": ch,
        })
    form = client.get("/aws")
    ans, ch = _solve(form.data)
    resp = client.post("/aws", data={
        "username": "bob", "password": "WRONG", "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    assert resp.status_code == 429


# --- session reuse -----------------------------------------------------------

def test_session_reuse_saml(tmp_path):
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [{"account_id": "1", "role": "R"}],
         "claims": []}
    ])
    client = app.test_client()
    client.set_cookie("idp_session", issue_token("appsecret", "bob", PURPOSE_SESSION),
                      domain="localhost")
    resp = client.get("/aws")
    assert b"SAMLResponse" in resp.data


def test_session_reuse_oauth(tmp_path):
    app = _write_app(
        tmp_path,
        [{"username": "bob", "password": _hash(), "roles": [], "claims": []}],
        services={"oauth": {"wiki": {"url": "https://wiki.example/cb"}}},
    )
    client = app.test_client()
    client.set_cookie("idp_session", issue_token("appsecret", "bob", PURPOSE_SESSION),
                      domain="localhost")
    resp = client.get("/wiki")
    assert resp.status_code == 302


# --- forced password change --------------------------------------------------

def test_forced_change_on_saml_login(tmp_path):
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "force_password_change": True}
    ])
    client = app.test_client()
    form = client.get("/aws")
    ans, ch = _solve(form.data)
    resp = client.post("/aws", data={
        "username": "bob", "password": PW, "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    assert b"Password change required" in resp.data
    assert b"SAMLResponse" not in resp.data


def test_forced_change_on_mfa_login(tmp_path):
    secret = pyotp.random_base32()
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "totp_secret": secret, "force_password_change": True}
    ])
    client = app.test_client()
    csrf, ticket = _login_to_mfa(client)
    resp = client.post("/aws", data={
        "csrf_token": csrf, "totp_step": "1", "mfa_ticket": ticket,
        "totp_code": pyotp.TOTP(secret).now(),
    })
    assert b"Password change required" in resp.data


# --- disabled / must-set-password accounts ----------------------------------

def test_disabled_account_cannot_login(tmp_path):
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [], "enabled": False}
    ])
    client = app.test_client()
    form = client.get("/aws")
    ans, ch = _solve(form.data)
    resp = client.post("/aws", data={
        "username": "bob", "password": PW, "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    assert resp.status_code == 401


# --- /user self-service flow ------------------------------------------------

def _user_login_no_mfa(client):
    """Log into /user (no MFA) and return the enroll-page response."""
    form = client.get("/user")
    ans, ch = _solve(form.data)
    return client.post("/user", data={
        "action": "login", "username": "bob", "password": PW,
        "csrf_token": _csrf(form.data), "challenge_answer": ans, "challenge_hash": ch,
    })


def test_user_get_page(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    assert app.test_client().get("/user").status_code == 200


def test_user_login_bad_csrf(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    resp = app.test_client().post("/user", data={"action": "login"})
    assert resp.status_code == 403


def test_user_login_bad_captcha(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    form = client.get("/user")
    resp = client.post("/user", data={
        "action": "login", "username": "bob", "password": PW,
        "csrf_token": _csrf(form.data), "challenge_answer": "9", "challenge_hash": "bad",
    })
    assert resp.status_code == 401


def test_user_login_wrong_password(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    form = client.get("/user")
    ans, ch = _solve(form.data)
    resp = client.post("/user", data={
        "action": "login", "username": "bob", "password": "WRONG",
        "csrf_token": _csrf(form.data), "challenge_answer": ans, "challenge_hash": ch,
    })
    assert resp.status_code == 401


def test_user_enroll_mfa_and_disable(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    enroll = _user_login_no_mfa(client)
    assert enroll.status_code == 200
    html = enroll.data.decode()
    csrf = _csrf(enroll.data)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    secret = re.search(r'name="totp_secret" value="([^"]+)"', html).group(1)
    # enroll with a valid code
    resp = client.post("/user", data={
        "action": "enroll", "csrf_token": csrf, "auth_token": auth,
        "totp_secret": secret, "totp_code": pyotp.TOTP(secret).now(),
    })
    assert b"enabled" in resp.data
    users = json.loads((tmp_path / "users.json").read_text())
    assert users[0].get("totp_secret") == secret
    # disable
    csrf2 = _csrf(resp.data)
    auth2 = re.search(rb'name="auth_token" value="([^"]+)"', resp.data).group(1).decode()
    dis = client.post("/user", data={
        "action": "disable", "csrf_token": csrf2, "auth_token": auth2,
    })
    assert dis.status_code == 200


def test_user_enroll_bad_code(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    enroll = _user_login_no_mfa(client)
    html = enroll.data.decode()
    csrf = _csrf(enroll.data)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    secret = re.search(r'name="totp_secret" value="([^"]+)"', html).group(1)
    resp = client.post("/user", data={
        "action": "enroll", "csrf_token": csrf, "auth_token": auth,
        "totp_secret": secret, "totp_code": "000000",
    })
    assert resp.status_code == 401


def test_user_enroll_expired_token(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    form = client.get("/user")
    resp = client.post("/user", data={
        "action": "enroll", "csrf_token": _csrf(form.data), "auth_token": "bogus",
        "totp_secret": "x", "totp_code": "1",
    })
    assert resp.status_code == 401


def test_user_change_password(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    enroll = _user_login_no_mfa(client)
    csrf = _csrf(enroll.data)
    auth = re.search(rb'name="auth_token" value="([^"]+)"', enroll.data).group(1).decode()
    # wrong current password
    bad = client.post("/user", data={
        "action": "change_password", "csrf_token": csrf, "auth_token": auth,
        "current_password": "WRONG", "new_password": "N3w-Passw0rd!!",
        "confirm_password": "N3w-Passw0rd!!",
    })
    assert bad.status_code == 200  # re-renders with error
    # mismatch
    enroll = _user_login_no_mfa(client)
    csrf = _csrf(enroll.data)
    auth = re.search(rb'name="auth_token" value="([^"]+)"', enroll.data).group(1).decode()
    client.post("/user", data={
        "action": "change_password", "csrf_token": csrf, "auth_token": auth,
        "current_password": PW, "new_password": "N3w-Passw0rd!!",
        "confirm_password": "different",
    })
    # success
    enroll = _user_login_no_mfa(client)
    csrf = _csrf(enroll.data)
    auth = re.search(rb'name="auth_token" value="([^"]+)"', enroll.data).group(1).decode()
    ok = client.post("/user", data={
        "action": "change_password", "csrf_token": csrf, "auth_token": auth,
        "current_password": PW, "new_password": "N3w-Passw0rd!!",
        "confirm_password": "N3w-Passw0rd!!",
    })
    assert ok.status_code == 200


def test_user_change_password_expired_token(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    form = client.get("/user")
    resp = client.post("/user", data={
        "action": "change_password", "csrf_token": _csrf(form.data), "auth_token": "bogus",
    })
    assert resp.status_code == 401


def test_user_disable_expired_token(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    form = client.get("/user")
    resp = client.post("/user", data={
        "action": "disable", "csrf_token": _csrf(form.data), "auth_token": "bogus",
    })
    assert resp.status_code == 401


def test_user_login_with_mfa_shows_totp(tmp_path):
    secret = pyotp.random_base32()
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "totp_secret": secret}
    ])
    client = app.test_client()
    form = client.get("/user")
    ans, ch = _solve(form.data)
    resp = client.post("/user", data={
        "action": "login", "username": "bob", "password": PW,
        "csrf_token": _csrf(form.data), "challenge_answer": ans, "challenge_hash": ch,
    })
    ticket = re.search(rb'name="mfa_ticket" value="([^"]+)"', resp.data).group(1).decode()
    csrf = _csrf(resp.data)
    # complete the /user TOTP step
    done = client.post("/user", data={
        "csrf_token": csrf, "totp_step": "1", "service_path": "user",
        "mfa_ticket": ticket, "totp_code": pyotp.TOTP(secret).now(),
    })
    assert done.status_code == 200


def test_user_totp_step_rate_limited(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    # Exhaust the IP limiter on /user login attempts.
    for _ in range(6):
        form = client.get("/user")
        ans, ch = _solve(form.data)
        client.post("/user", data={
            "action": "login", "username": "bob", "password": "WRONG",
            "csrf_token": _csrf(form.data), "challenge_answer": ans, "challenge_hash": ch,
        })
    form = client.get("/user")
    ans, ch = _solve(form.data)
    resp = client.post("/user", data={
        "action": "login", "username": "bob", "password": "WRONG",
        "csrf_token": _csrf(form.data), "challenge_answer": ans, "challenge_hash": ch,
    })
    assert resp.status_code == 429


def test_user_unknown_action(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    form = client.get("/user")
    resp = client.post("/user", data={
        "action": "bogus", "csrf_token": _csrf(form.data),
    })
    assert resp.status_code == 200


# --- forced-change /user action ---------------------------------------------

def test_user_force_change_action(tmp_path):
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "force_password_change": True}
    ])
    client = app.test_client()
    # login triggers forced-change page carrying the step-up token
    form = client.get("/aws")
    ans, ch = _solve(form.data)
    fc = client.post("/aws", data={
        "username": "bob", "password": PW, "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    def fc_tokens(resp):
        return (_csrf(resp.data),
                re.search(rb'name="auth_token" value="([^"]+)"', resp.data).group(1).decode())

    # wrong current (400, re-renders forced-change page with fresh tokens)
    csrf, auth = fc_tokens(fc)
    r = client.post("/user", data={
        "action": "force_change", "csrf_token": csrf, "auth_token": auth,
        "current_password": "WRONG", "new_password": "N3w-Passw0rd!!",
        "confirm_password": "N3w-Passw0rd!!",
    })
    assert r.status_code == 400
    # reused password
    csrf, auth = fc_tokens(r)
    r = client.post("/user", data={
        "action": "force_change", "csrf_token": csrf, "auth_token": auth,
        "current_password": PW, "new_password": PW, "confirm_password": PW,
    })
    assert r.status_code == 400
    # mismatch
    csrf, auth = fc_tokens(r)
    r = client.post("/user", data={
        "action": "force_change", "csrf_token": csrf, "auth_token": auth,
        "current_password": PW, "new_password": "N3w-Passw0rd!!",
        "confirm_password": "nope",
    })
    assert r.status_code == 400
    # success
    csrf, auth = fc_tokens(r)
    ok = client.post("/user", data={
        "action": "force_change", "csrf_token": csrf, "auth_token": auth,
        "current_password": PW, "new_password": "N3w-Passw0rd!!",
        "confirm_password": "N3w-Passw0rd!!",
    })
    assert b"Please sign in again" in ok.data
    users = json.loads((tmp_path / "users.json").read_text())
    assert "force_password_change" not in users[0]


def test_user_force_change_expired_token(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    form = client.get("/user")
    resp = client.post("/user", data={
        "action": "force_change", "csrf_token": _csrf(form.data), "auth_token": "bogus",
    })
    assert resp.status_code == 401


# --- recover flow -----------------------------------------------------------

def _make_recovery_token(app, tmp_path, username="bob"):
    """Create a recovery token via the admin helper bound to this app."""
    from identity_provider_server import admin as admin_mod
    # admin module-level fns are set by the most recent create_app; regenerate.
    import time as _t
    path = tmp_path / "recovery_tokens.json"
    import secrets as _s
    token = _s.token_urlsafe(48)
    path.write_text(json.dumps({token: {"username": username, "created": _t.time(),
                                          "expires": _t.time() + 3600}}))
    return token


def test_recover_get_valid_and_invalid(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    token = _make_recovery_token(app, tmp_path)
    client = app.test_client()
    ok = client.get(f"/recover/{token}")
    assert ok.status_code == 200
    assert client.get("/recover/bogus").status_code == 404


def test_recover_post_success_with_mfa(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    token = _make_recovery_token(app, tmp_path)
    client = app.test_client()
    get = client.get(f"/recover/{token}")
    csrf = _csrf(get.data)
    secret = re.search(rb'name="totp_secret" value="([^"]+)"', get.data).group(1).decode()
    resp = client.post(f"/recover/{token}", data={
        "csrf_token": csrf, "new_password": "N3w-Passw0rd!!",
        "confirm_password": "N3w-Passw0rd!!", "totp_secret": secret,
        "totp_code": pyotp.TOTP(secret).now(),
    })
    assert b"updated successfully" in resp.data


def test_recover_post_branches(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    token = _make_recovery_token(app, tmp_path)
    get = client.get(f"/recover/{token}")
    csrf = _csrf(get.data)
    # bad csrf
    assert client.post(f"/recover/{token}", data={"new_password": "x"}).status_code == 403
    # weak password
    weak = client.post(f"/recover/{token}", data={
        "csrf_token": csrf, "new_password": "short", "confirm_password": "short",
    })
    assert b"at least" in weak.data
    # mismatch
    mm = client.post(f"/recover/{token}", data={
        "csrf_token": csrf, "new_password": "N3w-Passw0rd!!", "confirm_password": "nope",
    })
    assert b"do not match" in mm.data
    # invalid mfa code
    get = client.get(f"/recover/{token}")
    csrf = _csrf(get.data)
    secret = re.search(rb'name="totp_secret" value="([^"]+)"', get.data).group(1).decode()
    badmfa = client.post(f"/recover/{token}", data={
        "csrf_token": csrf, "new_password": "N3w-Passw0rd!!",
        "confirm_password": "N3w-Passw0rd!!", "totp_secret": secret, "totp_code": "000000",
    })
    assert b"Invalid MFA" in badmfa.data


def test_recover_get_enrolled_user_shows_confirm_not_enroll(tmp_path):
    """An enrolled user's recovery page asks to confirm their existing code."""
    secret = pyotp.random_base32()
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "totp_secret": secret},
    ])
    token = _make_recovery_token(app, tmp_path)
    get = app.test_client().get(f"/recover/{token}")
    assert get.status_code == 200
    # No enrollment QR and no secret leaked into the page for enrolled users.
    assert b'name="totp_secret"' not in get.data
    assert b"QR Code" not in get.data
    # The confirm-MFA field is present and required.
    assert b'name="totp_code"' in get.data
    assert b"Confirm MFA" in get.data


def test_recover_enrolled_user_correct_code_succeeds(tmp_path):
    """An enrolled user entering their real code resets the password.

    This is the regression test for the bug where the reset flow verified
    against a freshly generated secret instead of the user's stored one.
    """
    secret = pyotp.random_base32()
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "totp_secret": secret},
    ])
    token = _make_recovery_token(app, tmp_path)
    client = app.test_client()
    get = client.get(f"/recover/{token}")
    csrf = _csrf(get.data)
    resp = client.post(f"/recover/{token}", data={
        "csrf_token": csrf, "new_password": "N3w-Passw0rd!!",
        "confirm_password": "N3w-Passw0rd!!",
        "totp_code": pyotp.TOTP(secret).now(),
    })
    assert b"updated successfully" in resp.data
    # The stored secret is unchanged (no re-enrollment).
    users = json.loads((tmp_path / "users.json").read_text())
    assert users[0]["totp_secret"] == secret


def test_recover_enrolled_user_wrong_code_rejected(tmp_path):
    """An enrolled user entering a wrong code is rejected; password unchanged."""
    secret = pyotp.random_base32()
    original = _hash()
    app = _write_app(tmp_path, [
        {"username": "bob", "password": original, "roles": [], "claims": [],
         "totp_secret": secret},
    ])
    token = _make_recovery_token(app, tmp_path)
    client = app.test_client()
    get = client.get(f"/recover/{token}")
    csrf = _csrf(get.data)
    resp = client.post(f"/recover/{token}", data={
        "csrf_token": csrf, "new_password": "N3w-Passw0rd!!",
        "confirm_password": "N3w-Passw0rd!!", "totp_code": "000000",
    })
    assert b"Invalid MFA" in resp.data
    # Password was not changed.
    users = json.loads((tmp_path / "users.json").read_text())
    assert users[0]["password"] == original


def test_recover_enrolled_user_missing_code_rejected(tmp_path):
    """An enrolled user who omits the MFA code cannot reset the password."""
    secret = pyotp.random_base32()
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "totp_secret": secret},
    ])
    token = _make_recovery_token(app, tmp_path)
    client = app.test_client()
    get = client.get(f"/recover/{token}")
    csrf = _csrf(get.data)
    resp = client.post(f"/recover/{token}", data={
        "csrf_token": csrf, "new_password": "N3w-Passw0rd!!",
        "confirm_password": "N3w-Passw0rd!!",  # no totp_code
    })
    assert b"Invalid MFA" in resp.data


def test_recover_enrolled_password_error_keeps_mfa_mode(tmp_path):
    """A password error for an enrolled user re-renders in confirm-MFA mode."""
    secret = pyotp.random_base32()
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "totp_secret": secret},
    ])
    token = _make_recovery_token(app, tmp_path)
    client = app.test_client()
    get = client.get(f"/recover/{token}")
    csrf = _csrf(get.data)
    resp = client.post(f"/recover/{token}", data={
        "csrf_token": csrf, "new_password": "short", "confirm_password": "short",
        "totp_code": pyotp.TOTP(secret).now(),
    })
    assert b"at least" in resp.data
    # Still in confirm-MFA mode (no enrollment QR / secret exposed).
    assert b"Confirm MFA" in resp.data
    assert b'name="totp_secret"' not in resp.data


def test_recover_post_invalid_token(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    # need a valid csrf cookie; get it from a valid recovery page first
    token = _make_recovery_token(app, tmp_path)
    get = client.get(f"/recover/{token}")
    csrf = _csrf(get.data)
    resp = client.post("/recover/bogustoken", data={
        "csrf_token": csrf, "new_password": "N3w-Passw0rd!!",
        "confirm_password": "N3w-Passw0rd!!",
    })
    assert resp.status_code == 404


def test_recover_post_rate_limited(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    token = _make_recovery_token(app, tmp_path)
    get = client.get(f"/recover/{token}")
    csrf = _csrf(get.data)
    for _ in range(6):
        client.post("/recover/bogus", data={
            "csrf_token": csrf, "new_password": "N3w-Passw0rd!!",
            "confirm_password": "N3w-Passw0rd!!",
        })
    resp = client.post("/recover/bogus", data={
        "csrf_token": csrf, "new_password": "N3w-Passw0rd!!",
        "confirm_password": "N3w-Passw0rd!!",
    })
    assert resp.status_code == 429


# --- metadata + headers -----------------------------------------------------

def test_metadata_route(tmp_path):
    app = _write_app(
        tmp_path,
        [{"username": "bob", "password": _hash(), "roles": [], "claims": []}],
        services={"saml": {"aws": "https://signin.aws.amazon.com/saml"}},
    )
    resp = app.test_client().get("/metadata")
    assert resp.status_code == 200
    assert b"EntityDescriptor" in resp.data


def test_security_headers_and_secure_cookies(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}],
                     secure_cookies=True)
    resp = app.test_client().get("/aws")
    assert "Strict-Transport-Security" in resp.headers
    assert "Content-Security-Policy" in resp.headers
    # cookie rewritten to include Secure
    assert any("Secure" in c for c in resp.headers.getlist("Set-Cookie"))


def test_health(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    assert app.test_client().get("/health").get_json()["status"] == "healthy"


# --- ADFS mode --------------------------------------------------------------

def test_adfs_login_flow(tmp_path):
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    (tmp_path / "services.yaml").write_text(yaml.dump(
        {"saml": {"aws": "https://signin.aws.amazon.com/saml"}}))
    app = create_app(
        str(tmp_path), secret_key="appsecret", secure_cookies=False,
        adfs_config={"host": "ldaps://x", "username": "svc", "base_dn": "dc=x",
                     "password": "p"},
        group_role_map={"AWS-Admins": [{"account_id": "1", "role": "Admin"}]},
    )
    app.config["TESTING"] = True
    client = app.test_client()
    with mock.patch("identity_provider_server.adfs.authenticate_adfs",
                    return_value=["AWS-Admins"]):
        form = client.get("/aws")
        ans, ch = _solve(form.data)
        resp = client.post("/aws", data={
            "username": "alice", "password": "pw", "csrf_token": _csrf(form.data),
            "challenge_answer": ans, "challenge_hash": ch,
        })
    assert b"SAMLResponse" in resp.data


def test_adfs_login_no_roles(tmp_path):
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    (tmp_path / "services.yaml").write_text(yaml.dump(
        {"saml": {"aws": "https://signin.aws.amazon.com/saml"}}))
    app = create_app(
        str(tmp_path), secret_key="appsecret", secure_cookies=False,
        adfs_config={"host": "ldaps://x", "username": "svc", "base_dn": "dc=x",
                     "password": "p"},
        group_role_map={},
    )
    app.config["TESTING"] = True
    client = app.test_client()
    with mock.patch("identity_provider_server.adfs.authenticate_adfs",
                    return_value=["Unmapped-Group"]):
        form = client.get("/aws")
        ans, ch = _solve(form.data)
        resp = client.post("/aws", data={
            "username": "alice", "password": "pw", "csrf_token": _csrf(form.data),
            "challenge_answer": ans, "challenge_hash": ch,
        })
    assert resp.status_code == 403


def test_adfs_auth_failure(tmp_path):
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    (tmp_path / "services.yaml").write_text(yaml.dump(
        {"saml": {"aws": "https://signin.aws.amazon.com/saml"}}))
    app = create_app(
        str(tmp_path), secret_key="appsecret", secure_cookies=False,
        adfs_config={"host": "ldaps://x", "username": "svc", "base_dn": "dc=x",
                     "password": "p"},
    )
    app.config["TESTING"] = True
    client = app.test_client()
    with mock.patch("identity_provider_server.adfs.authenticate_adfs", return_value=None):
        form = client.get("/aws")
        ans, ch = _solve(form.data)
        resp = client.post("/aws", data={
            "username": "alice", "password": "bad", "csrf_token": _csrf(form.data),
            "challenge_answer": ans, "challenge_hash": ch,
        })
    assert resp.status_code == 401


# --- direct unit branches ---------------------------------------------------

def test_check_password_rejects_non_bcrypt():
    from identity_provider_server.app import _check_password
    assert _check_password("plaintext-not-bcrypt", "plaintext-not-bcrypt") is False


def test_validate_helpers_direct():
    from identity_provider_server.app import _validate_claim, _validate_username
    assert _validate_username("ok.name") is True
    assert _validate_username("bad name") is False
    assert _validate_claim("ok-claim") is True
    assert _validate_claim("Bad") is False


def test_verify_challenge_malformed_and_bad_ts():
    from identity_provider_server.app import _verify_challenge
    assert _verify_challenge("s", "5", "only:two") is False
    assert _verify_challenge("s", "5", "n:notanint:sig") is False


def test_entity_id_https_port_443(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}],
                     port=443)
    assert "https://" in app.config["IDP_ENTITY_ID"]


def test_entity_id_http_port_80(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}],
                     port=80)
    assert app.config["IDP_ENTITY_ID"].startswith("http://")


def test_claim_roles_resolution(tmp_path):
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    (tmp_path / "users.json").write_text(json.dumps([
        {"username": "bob", "password": _hash(), "roles": [], "claims": ["awsadmin"]}
    ]))
    (tmp_path / "claim_roles.yaml").write_text(yaml.dump(
        {"awsadmin": [{"account_id": "1", "role": "Admin"}]}))
    app = create_app(str(tmp_path), secret_key="appsecret", secure_cookies=False)
    app.config["TESTING"] = True
    client = app.test_client()
    form = client.get("/aws")
    ans, ch = _solve(form.data)
    resp = client.post("/aws", data={
        "username": "bob", "password": PW, "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    assert b"SAMLResponse" in resp.data


def test_users_hot_reload(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    assert client.get("/health").status_code == 200
    # Modify users.json on disk; next request reloads it.
    import time
    time.sleep(0.01)
    (tmp_path / "users.json").write_text(json.dumps([
        {"username": "bob", "password": _hash(), "roles": [], "claims": []},
        {"username": "carol", "password": _hash(), "roles": [], "claims": []},
    ]))
    # A login as carol proves the reload happened.
    form = client.get("/aws")
    ans, ch = _solve(form.data)
    resp = client.post("/aws", data={
        "username": "carol", "password": PW, "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    assert b"SAMLResponse" in resp.data


def test_services_hot_reload(tmp_path):
    app = _write_app(
        tmp_path,
        [{"username": "bob", "password": _hash(), "roles": [], "claims": []}],
        services={"saml": {"aws": "https://signin.aws.amazon.com/saml"}},
    )
    client = app.test_client()
    client.get("/aws")
    import time
    time.sleep(0.01)
    (tmp_path / "services.yaml").write_text(yaml.dump(
        {"saml": {"aws": "https://signin.aws.amazon.com/saml",
                  "gitlab": "https://gitlab.example/acs"}}))
    # Trigger reload via a request; the new route is registered after SIGHUP in
    # prod, but load_services is re-read here (no crash).
    assert client.get("/aws").status_code == 200


def test_mfa_ticket_replay_rejected(tmp_path):
    """Reusing a consumed MFA ticket is rejected (nonce store)."""
    secret = pyotp.random_base32()
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [{"account_id": "1", "role": "R"}],
         "claims": [], "totp_secret": secret}
    ])
    client = app.test_client()
    csrf, ticket = _login_to_mfa(client)
    # First use succeeds.
    ok = client.post("/aws", data={
        "csrf_token": csrf, "totp_step": "1", "mfa_ticket": ticket,
        "totp_code": pyotp.TOTP(secret).now(),
    })
    assert b"SAMLResponse" in ok.data
    # Replay the same ticket with a FRESH client (no session cookie) -> rejected.
    client2 = app.test_client()
    form = client2.get("/aws")
    replay = client2.post("/aws", data={
        "csrf_token": _csrf(form.data), "totp_step": "1", "mfa_ticket": ticket,
        "totp_code": pyotp.TOTP(secret).now(),
    })
    assert b"SAMLResponse" not in replay.data


def test_metadata_no_services(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    resp = app.test_client().get("/metadata")
    assert resp.status_code == 200


def test_last_login_persist_oserror(tmp_path, monkeypatch):
    """last_login save failure is swallowed (OSError branch)."""
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [{"account_id": "1", "role": "R"}],
         "claims": []}
    ])
    client = app.test_client()
    form = client.get("/aws")
    ans, ch = _solve(form.data)
    # Make the users.json write fail during _record_login.
    import identity_provider_server.app as appmod
    orig = appmod._save_users
    monkeypatch.setattr(appmod, "_save_users",
                        mock.Mock(side_effect=OSError("disk full")))
    resp = client.post("/aws", data={
        "username": "bob", "password": PW, "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    assert b"SAMLResponse" in resp.data
    monkeypatch.setattr(appmod, "_save_users", orig)


# --- /user TOTP-step branches -----------------------------------------------

def _user_to_mfa(client, secret):
    form = client.get("/user")
    ans, ch = _solve(form.data)
    resp = client.post("/user", data={
        "action": "login", "username": "bob", "password": PW,
        "csrf_token": _csrf(form.data), "challenge_answer": ans, "challenge_hash": ch,
    })
    ticket = re.search(rb'name="mfa_ticket" value="([^"]+)"', resp.data).group(1).decode()
    return _csrf(resp.data), ticket


def test_user_totp_step_no_ticket(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    form = client.get("/user")
    resp = client.post("/user", data={
        "csrf_token": _csrf(form.data), "totp_step": "1", "service_path": "user",
        "totp_code": "123456",
    })
    assert resp.status_code == 401


def test_user_totp_step_wrong_code(tmp_path):
    secret = pyotp.random_base32()
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [], "totp_secret": secret}
    ])
    client = app.test_client()
    csrf, ticket = _user_to_mfa(client, secret)
    resp = client.post("/user", data={
        "csrf_token": csrf, "totp_step": "1", "service_path": "user",
        "mfa_ticket": ticket, "totp_code": "000000",
    })
    assert resp.status_code == 401
    assert b"Invalid code" in resp.data


def test_user_totp_step_ticket_user_lost_secret(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    from identity_provider_server.tokens import PURPOSE_MFA_PENDING, issue_token as it
    ticket = it("appsecret", "bob|n1", PURPOSE_MFA_PENDING)
    client = app.test_client()
    form = client.get("/user")
    resp = client.post("/user", data={
        "csrf_token": _csrf(form.data), "totp_step": "1", "service_path": "user",
        "mfa_ticket": ticket, "totp_code": "123456",
    })
    assert resp.status_code == 401
    assert b"Invalid request" in resp.data


def test_user_totp_step_nonce_replay(tmp_path):
    secret = pyotp.random_base32()
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [], "totp_secret": secret}
    ])
    client = app.test_client()
    csrf, ticket = _user_to_mfa(client, secret)
    ok = client.post("/user", data={
        "csrf_token": csrf, "totp_step": "1", "service_path": "user",
        "mfa_ticket": ticket, "totp_code": pyotp.TOTP(secret).now(),
    })
    assert ok.status_code == 200
    # replay same ticket on a fresh client
    c2 = app.test_client()
    form = c2.get("/user")
    replay = c2.post("/user", data={
        "csrf_token": _csrf(form.data), "totp_step": "1", "service_path": "user",
        "mfa_ticket": ticket, "totp_code": pyotp.TOTP(secret).now(),
    })
    assert replay.status_code == 401


# --- small direct branches --------------------------------------------------

def test_password_policy_three_classes_message():
    from identity_provider_server.app import _password_policy_error
    # 12+ chars but only one class -> "three of" message (line 585)
    msg = _password_policy_error("aaaaaaaaaaaaaa")
    assert msg is not None and "three of" in msg


def test_captcha_expired():
    from identity_provider_server.app import _verify_challenge
    import hashlib
    import hmac
    # Build a token with an ancient timestamp but valid signature.
    secret = "s"
    nonce, ts, answer = "n", "1", "5"
    sig = hmac.new(secret.encode(), f"{nonce}:{ts}:{answer}".encode(),
                   hashlib.sha256).hexdigest()
    assert _verify_challenge(secret, answer, f"{nonce}:{ts}:{sig}") is False


def test_must_set_password_blocks_login(tmp_path):
    app = _write_app(tmp_path, [
        {"username": "bob", "must_set_password": True, "claims": [], "roles": []}
    ])
    client = app.test_client()
    form = client.get("/aws")
    ans, ch = _solve(form.data)
    resp = client.post("/aws", data={
        "username": "bob", "password": "anything", "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    assert resp.status_code == 401


def test_change_password_weak_new(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    enroll = _user_login_no_mfa(client)
    csrf = _csrf(enroll.data)
    auth = re.search(rb'name="auth_token" value="([^"]+)"', enroll.data).group(1).decode()
    resp = client.post("/user", data={
        "action": "change_password", "csrf_token": csrf, "auth_token": auth,
        "current_password": PW, "new_password": "weak", "confirm_password": "weak",
    })
    assert resp.status_code == 200  # re-renders with policy error


def test_force_change_weak_new(tmp_path):
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "force_password_change": True}
    ])
    client = app.test_client()
    form = client.get("/aws")
    ans, ch = _solve(form.data)
    fc = client.post("/aws", data={
        "username": "bob", "password": PW, "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    csrf = _csrf(fc.data)
    auth = re.search(rb'name="auth_token" value="([^"]+)"', fc.data).group(1).decode()
    resp = client.post("/user", data={
        "action": "force_change", "csrf_token": csrf, "auth_token": auth,
        "current_password": PW, "new_password": "weak", "confirm_password": "weak",
    })
    assert resp.status_code == 400


def test_hot_reload_stat_oserror(tmp_path, monkeypatch):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    # Make reading users.json fail during the hot-reload digest check
    # (covers _users_digest OSError -> None and the "could not read" branch).
    import pathlib
    real_read_bytes = pathlib.Path.read_bytes

    def flaky_read_bytes(self, *a, **k):
        if self.name == "users.json":
            raise OSError("read failed")
        return real_read_bytes(self, *a, **k)

    monkeypatch.setattr(pathlib.Path, "read_bytes", flaky_read_bytes)
    assert client.get("/health").status_code == 200


def test_hot_reload_load_error(tmp_path, monkeypatch):
    """If the file content changes but is unparseable, the reload is skipped."""
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    client.get("/health")
    import time
    time.sleep(0.01)
    # Change content (so the digest differs) to invalid JSON; reload swallows it.
    (tmp_path / "users.json").write_text("{ not valid json")
    assert client.get("/health").status_code == 200


def test_users_digest_none_on_missing(tmp_path):
    from identity_provider_server.app import _users_digest
    assert _users_digest(tmp_path / "nonexistent.json") is None


# --- logout routes ----------------------------------------------------------

def test_logout_fallback_route(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    resp = app.test_client().get("/aws/logout")
    assert resp.status_code == 200


def test_logout_dynamic_route(tmp_path):
    app = _write_app(
        tmp_path,
        [{"username": "bob", "password": _hash(), "roles": [], "claims": []}],
        services={"saml": {"aws": "https://signin.aws.amazon.com/saml"}},
    )
    resp = app.test_client().get("/aws/logout")
    assert resp.status_code == 200


# --- per-account SP rate-limit render (distinct IPs, same account) ----------

def test_sp_per_account_lockout_render(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    # Spray one account from many different source IPs so the ip-only limiter
    # never trips but the per-account limiter does (line 1235 block).
    for i in range(6):
        c = app.test_client()
        form = c.get("/aws", environ_overrides={"REMOTE_ADDR": f"10.0.0.{i}"})
        ans, ch = _solve(form.data)
        c.post("/aws", environ_overrides={"REMOTE_ADDR": f"10.0.0.{i}"}, data={
            "username": "bob", "password": "WRONG", "csrf_token": _csrf(form.data),
            "challenge_answer": ans, "challenge_hash": ch,
        })
    c = app.test_client()
    form = c.get("/aws", environ_overrides={"REMOTE_ADDR": "10.0.0.99"})
    ans, ch = _solve(form.data)
    resp = c.post("/aws", environ_overrides={"REMOTE_ADDR": "10.0.0.99"}, data={
        "username": "bob", "password": PW, "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    assert resp.status_code == 429


def test_user_login_ip_rate_limited_render(tmp_path):
    """Same-IP flood trips the ip-only limiter on /user login (1510 block)."""
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    for _ in range(6):
        form = client.get("/user")
        ans, ch = _solve(form.data)
        client.post("/user", data={
            "action": "login", "username": "bob", "password": "WRONG",
            "csrf_token": _csrf(form.data), "challenge_answer": ans, "challenge_hash": ch,
        })
    form = client.get("/user")
    ans, ch = _solve(form.data)
    resp = client.post("/user", data={
        "action": "login", "username": "bob", "password": "WRONG",
        "csrf_token": _csrf(form.data), "challenge_answer": ans, "challenge_hash": ch,
    })
    assert resp.status_code == 429


def test_user_per_account_lockout_render(tmp_path):
    """Cross-IP spraying of one account trips the per-account lockout (1614)."""
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    for i in range(6):
        c = app.test_client()
        form = c.get("/user", environ_overrides={"REMOTE_ADDR": f"10.1.0.{i}"})
        ans, ch = _solve(form.data)
        c.post("/user", environ_overrides={"REMOTE_ADDR": f"10.1.0.{i}"}, data={
            "action": "login", "username": "bob", "password": "WRONG",
            "csrf_token": _csrf(form.data), "challenge_answer": ans, "challenge_hash": ch,
        })
    c = app.test_client()
    form = c.get("/user", environ_overrides={"REMOTE_ADDR": "10.1.0.99"})
    ans, ch = _solve(form.data)
    resp = c.post("/user", environ_overrides={"REMOTE_ADDR": "10.1.0.99"}, data={
        "action": "login", "username": "bob", "password": PW,
        "csrf_token": _csrf(form.data), "challenge_answer": ans, "challenge_hash": ch,
    })
    assert resp.status_code == 429


def test_services_reload_error(tmp_path, monkeypatch):
    app = _write_app(
        tmp_path,
        [{"username": "bob", "password": _hash(), "roles": [], "claims": []}],
        services={"saml": {"aws": "https://signin.aws.amazon.com/saml"}},
    )
    client = app.test_client()
    client.get("/aws")
    import time
    time.sleep(0.01)
    # Corrupt services.yaml so the reload raises (OSError/ValueError branch).
    (tmp_path / "services.yaml").write_text("::: not valid : yaml : [")
    import identity_provider_server.app as appmod
    monkeypatch.setattr(appmod, "load_services",
                        mock.Mock(side_effect=ValueError("bad services")))
    # Request triggers _reload_services_if_changed which swallows the error.
    assert client.get("/health").status_code == 200
