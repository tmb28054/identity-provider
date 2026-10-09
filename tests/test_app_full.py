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
from identity_provider_server.tokens import issue_session_token


def _session_cookie(secret: str, username: str) -> str:
    """Mint a session cookie in the current (epoch + auth_time) scheme."""
    import time as _time

    return issue_session_token(
        secret, username, auth_time=int(_time.time()), epoch=0,
    )

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
    app = create_app(str(tmp_path), secret_key="appsecret-0000000000000000000000000", **kwargs)
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


# --- trust_proxy / ProxyFix (finding idp-2026-10-06 F3) ---------------------

def test_trust_proxy_true_installs_proxyfix(tmp_path):
    """When trust_proxy=True, create_app wraps the WSGI app in ProxyFix."""
    from werkzeug.middleware.proxy_fix import ProxyFix

    app = _write_app(tmp_path, [], trust_proxy=True)
    assert isinstance(app.wsgi_app, ProxyFix)


def test_trust_proxy_false_skips_proxyfix(tmp_path):
    """The default (trust_proxy=False) leaves the WSGI app unwrapped."""
    from werkzeug.middleware.proxy_fix import ProxyFix

    app = _write_app(tmp_path, [])  # helper defaults trust_proxy=False
    assert not isinstance(app.wsgi_app, ProxyFix)


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
    _assert_fragment_token(resp.headers["Location"])


def _assert_fragment_token(location: str) -> None:
    """Assert the OAuth JWT is delivered in a URL fragment, not a query string.

    Keeping the bearer token out of the query string stops it being written to
    gunicorn access logs or leaked via the Referer header (idp-20261006 F2).
    """
    assert "#token=" in location
    assert "?token=" not in location
    assert "&token=" not in location


@pytest.mark.smoke
def test_oauth_login_delivers_token_in_fragment(tmp_path):
    """Smoke: password-only OAuth login hands the JWT back in a URL fragment."""
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
    _assert_fragment_token(resp.headers["Location"])


def test_oauth_fragment_preserved_for_url_with_query(tmp_path):
    """Even when the SP callback URL has a query string, the token stays in the
    fragment (never appended as another query parameter) (F2)."""
    app = _write_app(
        tmp_path,
        [{"username": "bob", "password": _hash(), "roles": [], "claims": ["dev"],
          "email": "b@e.com"}],
        services={"oauth": {"wiki": {"url": "https://wiki.example/cb?rp=1",
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
    location = resp.headers["Location"]
    assert "#token=" in location
    assert "&token=" not in location
    # The SP's own query string is untouched; only our token moved to the frag.
    assert location.split("#", 1)[0] == "https://wiki.example/cb?rp=1"


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
    _assert_fragment_token(resp.headers["Location"])


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
    ticket = it("appsecret-0000000000000000000000000", "bob|nonce123", PURPOSE_MFA_PENDING)
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
    client.set_cookie("idp_session", _session_cookie("appsecret-0000000000000000000000000", "bob"),
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
    client.set_cookie("idp_session", _session_cookie("appsecret-0000000000000000000000000", "bob"),
                      domain="localhost")
    resp = client.get("/wiki")
    assert resp.status_code == 302
    # SSO short-circuit GET must also deliver the JWT in the fragment (F2).
    _assert_fragment_token(resp.headers["Location"])


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
    handle = re.search(r'name="secret_handle" value="([^"]+)"', html).group(1)
    secret = re.search(r'class="secret-code">([^<]+)<', html).group(1)
    # enroll with a valid code — now requires the current password and the
    # server-bound secret handle (not a client-supplied secret).
    resp = client.post("/user", data={
        "action": "enroll", "csrf_token": csrf, "auth_token": auth,
        "secret_handle": handle, "current_password": PW,
        "totp_code": pyotp.TOTP(secret).now(),
    })
    assert b"enabled" in resp.data
    users = json.loads((tmp_path / "users.json").read_text())
    assert users[0].get("totp_secret") == secret
    # disable — requires the current password and a current authenticator code
    csrf2 = _csrf(resp.data)
    auth2 = re.search(rb'name="auth_token" value="([^"]+)"', resp.data).group(1).decode()
    dis = client.post("/user", data={
        "action": "disable", "csrf_token": csrf2, "auth_token": auth2,
        "current_password": PW, "totp_code": pyotp.TOTP(secret).now(),
    })
    assert dis.status_code == 200


def test_user_enroll_bad_code(tmp_path):
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    client = app.test_client()
    enroll = _user_login_no_mfa(client)
    html = enroll.data.decode()
    csrf = _csrf(enroll.data)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    handle = re.search(r'name="secret_handle" value="([^"]+)"', html).group(1)
    resp = client.post("/user", data={
        "action": "enroll", "csrf_token": csrf, "auth_token": auth,
        "secret_handle": handle, "current_password": PW, "totp_code": "000000",
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


def test_recover_rejects_password_reuse(tmp_path):
    """The recovery flow refuses to set the account's current password again."""
    app = _write_app(tmp_path, [{"username": "bob", "password": _hash(), "roles": [], "claims": []}])
    token = _make_recovery_token(app, tmp_path)
    client = app.test_client()
    get = client.get(f"/recover/{token}")
    csrf = _csrf(get.data)
    secret = re.search(rb'name="totp_secret" value="([^"]+)"', get.data).group(1).decode()
    resp = client.post(f"/recover/{token}", data={
        "csrf_token": csrf, "new_password": PW, "confirm_password": PW,
        "totp_secret": secret,
    })
    assert b"differ from the last" in resp.data


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
        str(tmp_path), secret_key="appsecret-0000000000000000000000000", secure_cookies=False,
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
        str(tmp_path), secret_key="appsecret-0000000000000000000000000", secure_cookies=False,
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
        str(tmp_path), secret_key="appsecret-0000000000000000000000000", secure_cookies=False,
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
    app = create_app(str(tmp_path), secret_key="appsecret-0000000000000000000000000", secure_cookies=False)
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
    ticket = it("appsecret-0000000000000000000000000", "bob|n1", PURPOSE_MFA_PENDING)
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


# --- passkey (WebAuthn) coverage: OAuth issuance, forced change, fallback ---

import base64  # noqa: E402

from soft_webauthn import SoftWebauthnDevice  # noqa: E402

PK_RP_ID = "localhost"
PK_ORIGIN = "https://localhost"


def _pk_b64url_to_bytes(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _pk_bytes_to_b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _pk_options_to_soft(options: dict) -> dict:
    opts = json.loads(json.dumps(options))
    opts["challenge"] = _pk_b64url_to_bytes(opts["challenge"])
    if "user" in opts and "id" in opts["user"]:
        opts["user"]["id"] = _pk_b64url_to_bytes(opts["user"]["id"])
    for key in ("excludeCredentials", "allowCredentials"):
        for desc in opts.get(key, []) or []:
            desc["id"] = _pk_b64url_to_bytes(desc["id"])
    return {"publicKey": opts}


def _pk_att_to_dict(att: dict) -> dict:
    def enc(b):
        return _pk_bytes_to_b64url(b) if isinstance(b, (bytes, bytearray)) else b

    resp = att["response"]
    return {
        "id": enc(att["rawId"]),
        "rawId": enc(att["rawId"]),
        "type": att["type"],
        "response": {k: enc(v) for k, v in resp.items()},
    }


def _pk_step_up(client, username="bob"):
    """Sign in on /user (no MFA) and return (auth_token, csrf_token)."""
    resp = client.get("/user")
    csrf = _csrf(resp.data)
    ans, ch = _solve(resp.data)
    resp = client.post("/user", data={
        "action": "login", "username": username, "password": PW,
        "csrf_token": csrf, "challenge_answer": ans, "challenge_hash": ch,
    })
    auth_token = re.search(
        rb'name="auth_token" value="([^"]+)"', resp.data
    ).group(1).decode()
    return auth_token, _csrf(resp.data)


def _pk_register(client, device, auth_token, csrf):
    begin = client.post("/user/passkey/register/begin",
                        json={"csrf_token": csrf, "auth_token": auth_token}).get_json()
    att = device.create(_pk_options_to_soft(begin["options"]), PK_ORIGIN)
    return client.post("/user/passkey/register/finish", json={
        "csrf_token": csrf, "auth_token": auth_token,
        "handle": begin["handle"], "credential": _pk_att_to_dict(att),
    })


def _pk_authenticate(client, device, path):
    csrf = re.search(rb'name="csrf_token" value="([^"]+)"',
                     client.get(path).data).group(1).decode()
    begin = client.post(f"{path}/passkey/begin",
                        json={"csrf_token": csrf, "username": "bob"}).get_json()
    assertion = device.get(_pk_options_to_soft(begin["options"]), PK_ORIGIN)
    return client.post(f"{path}/passkey/finish", json={
        "csrf_token": csrf, "handle": begin["handle"],
        "credential": _pk_att_to_dict(assertion),
    })


def test_passkey_oauth_issuance(tmp_path):
    app = _write_app(
        tmp_path,
        [{"username": "bob", "password": _hash(), "roles": [], "claims": ["dev"],
          "email": "b@e.com"}],
        services={"oauth": {"wiki": {"url": "https://wiki.example/cb",
                                     "token_expiry_minutes": 60}}},
        webauthn_enabled=True, webauthn_rp_id=PK_RP_ID,
        webauthn_expected_origin=PK_ORIGIN,
    )
    client = app.test_client()
    device = SoftWebauthnDevice()
    auth_token, csrf = _pk_step_up(client)
    assert _pk_register(client, device, auth_token, csrf).status_code == 200
    finish = _pk_authenticate(client, device, "/wiki")
    assert finish.status_code == 200
    _assert_fragment_token(finish.get_json()["redirect"])
    assert "idp_session" in finish.headers.get("Set-Cookie", "")


def test_passkey_forced_password_change(tmp_path):
    app = _write_app(
        tmp_path,
        [{"username": "bob", "password": _hash(), "roles": [], "claims": [],
          "force_password_change": True}],
        services={"saml": {"aws": "https://signin.aws.amazon.com/saml"}},
        webauthn_enabled=True, webauthn_rp_id=PK_RP_ID,
        webauthn_expected_origin=PK_ORIGIN,
    )
    client = app.test_client()
    device = SoftWebauthnDevice()
    auth_token, csrf = _pk_step_up(client)
    _pk_register(client, device, auth_token, csrf)
    finish = _pk_authenticate(client, device, "/aws")
    assert finish.status_code == 200
    assert finish.get_json()["redirect"] == "/aws"


def test_passkey_fallback_aws_routes(tmp_path):
    # No services.yaml -> the /aws fallback passkey routes are registered.
    app = _write_app(
        tmp_path,
        [{"username": "bob", "password": _hash(),
          "roles": [{"account_id": "1", "role": "R"}], "claims": []}],
        webauthn_enabled=True, webauthn_rp_id=PK_RP_ID,
        webauthn_expected_origin=PK_ORIGIN,
    )
    client = app.test_client()
    device = SoftWebauthnDevice()
    auth_token, csrf = _pk_step_up(client)
    assert _pk_register(client, device, auth_token, csrf).status_code == 200
    finish = _pk_authenticate(client, device, "/aws")
    assert finish.status_code == 200
    assert "SAMLResponse" in finish.get_json()["html"]


def test_passkey_begin_rate_limited(tmp_path):
    app = _write_app(
        tmp_path,
        [{"username": "bob", "password": _hash(), "roles": [], "claims": []}],
        webauthn_enabled=True, webauthn_rp_id=PK_RP_ID,
        webauthn_expected_origin=PK_ORIGIN,
        rate_limit_max_attempts=1,
    )
    client = app.test_client()
    ip = {"REMOTE_ADDR": "10.9.9.9"}
    # Trip the per-IP limiter with a failed password login first.
    form = client.get("/aws", environ_overrides=ip)
    ans, ch = _solve(form.data)
    client.post("/aws", environ_overrides=ip, data={
        "username": "bob", "password": "WRONG", "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    # Fresh csrf cookie so the passkey call passes CSRF and reaches the limiter.
    csrf = re.search(rb'name="csrf_token" value="([^"]+)"',
                     client.get("/aws", environ_overrides=ip).data).group(1).decode()
    begin = client.post("/aws/passkey/begin", environ_overrides=ip,
                        json={"csrf_token": csrf, "username": "bob"})
    assert begin.status_code == 429
    finish = client.post("/aws/passkey/finish", environ_overrides=ip,
                         json={"csrf_token": csrf, "handle": "x", "credential": {}})
    assert finish.status_code == 429


def test_passkey_auth_blocked_when_account_disabled(tmp_path):
    """A disabled account's passkey begin is indistinguishable (decoy options),
    so it does not leak that the account exists or has a passkey. The account
    still cannot actually authenticate (covered by the finish-side test)."""
    app = _write_app(
        tmp_path,
        [{"username": "bob", "password": _hash(), "roles": [], "claims": []}],
        webauthn_enabled=True, webauthn_rp_id=PK_RP_ID,
        webauthn_expected_origin=PK_ORIGIN,
    )
    client = app.test_client()
    device = SoftWebauthnDevice()
    auth_token, csrf = _pk_step_up(client)
    _pk_register(client, device, auth_token, csrf)

    # Disable the account out-of-band; hot-reload picks it up.
    users = json.loads((tmp_path / "users.json").read_text())
    for u in users:
        if u["username"] == "bob":
            u["enabled"] = False
    (tmp_path / "users.json").write_text(json.dumps(users))

    csrf = re.search(rb'name="csrf_token" value="([^"]+)"',
                     client.get("/aws").data).group(1).decode()
    begin = client.post("/aws/passkey/begin",
                        json={"csrf_token": csrf, "username": "bob"})
    # Indistinguishable from an eligible account: 200 with options.
    assert begin.status_code == 200
    assert begin.get_json()["options"]["allowCredentials"]


def test_passkey_finish_blocked_if_disabled_after_begin(tmp_path):
    """Disabling the account between begin and finish rejects the assertion."""
    app = _write_app(
        tmp_path,
        [{"username": "bob", "password": _hash(),
          "roles": [{"account_id": "1", "role": "R"}], "claims": []}],
        webauthn_enabled=True, webauthn_rp_id=PK_RP_ID,
        webauthn_expected_origin=PK_ORIGIN,
    )
    client = app.test_client()
    device = SoftWebauthnDevice()
    auth_token, csrf = _pk_step_up(client)
    _pk_register(client, device, auth_token, csrf)

    csrf = re.search(rb'name="csrf_token" value="([^"]+)"',
                     client.get("/aws").data).group(1).decode()
    begin = client.post("/aws/passkey/begin",
                        json={"csrf_token": csrf, "username": "bob"}).get_json()
    assertion = device.get(_pk_options_to_soft(begin["options"]), PK_ORIGIN)

    # Disable the account after begin, before finish.
    users = json.loads((tmp_path / "users.json").read_text())
    for u in users:
        if u["username"] == "bob":
            u["enabled"] = False
    (tmp_path / "users.json").write_text(json.dumps(users))

    finish = client.post("/aws/passkey/finish", json={
        "csrf_token": csrf, "handle": begin["handle"],
        "credential": _pk_att_to_dict(assertion),
    })
    assert finish.status_code == 400
    assert "unknown passkey" in finish.get_json()["error"].lower()


# --- P2.3: no-MFA session-cookie consistency + passkey-aware forced rotation ---

def test_saml_no_mfa_sets_session_cookie(tmp_path):
    """A password-only (no-MFA) SAML login now establishes the SSO session."""
    app = _write_app(tmp_path, [
        {"username": "bob", "password": _hash(),
         "roles": [{"account_id": "1", "role": "R"}], "claims": []}
    ])
    client = app.test_client()
    form = client.get("/aws")
    ans, ch = _solve(form.data)
    resp = client.post("/aws", data={
        "username": "bob", "password": PW, "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    assert b"SAMLResponse" in resp.data
    assert "idp_session" in resp.headers.get("Set-Cookie", "")


def test_oauth_no_mfa_sets_session_cookie(tmp_path):
    """A password-only (no-MFA) OAuth login now establishes the SSO session."""
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
    assert "idp_session" in resp.headers.get("Set-Cookie", "")


def test_passwordless_account_skips_forced_rotation(tmp_path):
    """force_password_change is ignored for a passwordless passkey login."""
    app = _write_app(
        tmp_path,
        [{"username": "bob", "password": _hash(),
          "roles": [{"account_id": "1", "role": "R"}], "claims": [],
          "force_password_change": True}],
        webauthn_enabled=True, webauthn_rp_id=PK_RP_ID,
        webauthn_expected_origin=PK_ORIGIN,
    )
    client = app.test_client()
    device = SoftWebauthnDevice()
    auth_token, csrf = _pk_step_up(client)
    _pk_register(client, device, auth_token, csrf)

    # Mark the account passwordless out-of-band (P2.4 sets this via UI; here we
    # assert the forced-rotation gate is skipped once it is passwordless).
    users = json.loads((tmp_path / "users.json").read_text())
    for u in users:
        if u["username"] == "bob":
            u["passwordless"] = True
    (tmp_path / "users.json").write_text(json.dumps(users))

    finish = _pk_authenticate(client, device, "/aws")
    assert finish.status_code == 200
    # Not redirected to the forced-change page; a SAML assertion is issued.
    assert "SAMLResponse" in finish.get_json()["html"]


# --- P2.4: passwordless entry point + lockout guard -------------------------

def _pk_app(tmp_path, extra_user=None):
    user = {"username": "bob", "password": _hash(),
            "roles": [{"account_id": "1", "role": "R"}], "claims": []}
    if extra_user:
        user.update(extra_user)
    return _write_app(
        tmp_path, [user],
        webauthn_enabled=True, webauthn_rp_id=PK_RP_ID,
        webauthn_expected_origin=PK_ORIGIN,
    )


def test_set_passwordless_refused_without_recovery_path(tmp_path):
    """One passkey + password is enough; but a single passkey and nothing else
    (simulated by removing the password) is refused."""
    app = _pk_app(tmp_path)
    client = app.test_client()
    device = SoftWebauthnDevice()
    auth_token, csrf = _pk_step_up(client)
    _pk_register(client, device, auth_token, csrf)

    # Drop the password so the sole factor is one passkey (lockout risk).
    users = json.loads((tmp_path / "users.json").read_text())
    for u in users:
        if u["username"] == "bob":
            u.pop("password", None)
    (tmp_path / "users.json").write_text(json.dumps(users))

    resp = client.post("/user", data={
        "action": "set_passwordless", "auth_token": auth_token, "csrf_token": csrf,
    })
    assert resp.status_code == 400
    assert b"second passkey" in resp.data
    users = json.loads((tmp_path / "users.json").read_text())
    assert not any(u.get("passwordless") for u in users)


def test_set_passwordless_ok_with_password_retained(tmp_path):
    """One passkey + retained password satisfies the minimum-factor policy."""
    app = _pk_app(tmp_path)
    client = app.test_client()
    device = SoftWebauthnDevice()
    auth_token, csrf = _pk_step_up(client)
    _pk_register(client, device, auth_token, csrf)

    resp = client.post("/user", data={
        "action": "set_passwordless", "auth_token": auth_token, "csrf_token": csrf,
    })
    assert resp.status_code == 200
    users = json.loads((tmp_path / "users.json").read_text())
    assert any(u["username"] == "bob" and u.get("passwordless") for u in users)


def test_unset_passwordless(tmp_path):
    app = _pk_app(tmp_path, {"passwordless": True})
    client = app.test_client()
    auth_token, csrf = _pk_step_up(client)
    resp = client.post("/user", data={
        "action": "unset_passwordless", "auth_token": auth_token, "csrf_token": csrf,
    })
    assert resp.status_code == 200
    users = json.loads((tmp_path / "users.json").read_text())
    assert not any(u.get("passwordless") for u in users)


def test_set_passwordless_expired_token(tmp_path):
    app = _pk_app(tmp_path)
    client = app.test_client()
    csrf = re.search(rb'name="csrf_token" value="([^"]+)"',
                     client.get("/user").data).group(1).decode()
    resp = client.post("/user", data={
        "action": "set_passwordless", "auth_token": "bad", "csrf_token": csrf,
    })
    assert resp.status_code == 401


def test_passwordless_login_without_password(tmp_path):
    """A no-password account with a passkey logs in via the SP passkey flow."""
    app = _pk_app(tmp_path)
    client = app.test_client()
    device = SoftWebauthnDevice()
    auth_token, csrf = _pk_step_up(client)
    _pk_register(client, device, auth_token, csrf)

    # Go fully password-less: flag on, password removed.
    users = json.loads((tmp_path / "users.json").read_text())
    for u in users:
        if u["username"] == "bob":
            u["passwordless"] = True
            u.pop("password", None)
    (tmp_path / "users.json").write_text(json.dumps(users))

    finish = _pk_authenticate(client, device, "/aws")
    assert finish.status_code == 200
    assert "SAMLResponse" in finish.get_json()["html"]
    assert "idp_session" in finish.headers.get("Set-Cookie", "")


def test_enroll_page_shows_passwordless_toggle(tmp_path):
    app = _pk_app(tmp_path)
    client = app.test_client()
    device = SoftWebauthnDevice()
    auth_token, csrf = _pk_step_up(client)
    reg = _pk_register(client, device, auth_token, csrf)
    assert reg.status_code == 200
    # Re-fetch the enroll page via a fresh step-up to see the rendered toggle.
    auth_token, csrf = _pk_step_up(client)
    # The step-up landing page is the enroll page itself.
    page = client.post("/user", data={
        "action": "unset_passwordless", "auth_token": auth_token, "csrf_token": csrf,
    })
    assert b"Password-less sign-in" in page.data
    assert b'value="set_passwordless"' in page.data


# --- create_app as single config entry point (finding idp-2026-10-06 F1) ----


def _write_data_files(tmp_path, users=None):
    """Copy cert/key and a users.json into tmp_path (no create_app call)."""
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    (tmp_path / "users.json").write_text(json.dumps(users or []))


def test_create_app_reads_config_yaml_no_kwargs(tmp_path):
    """config.yaml alone drives trust_proxy and webauthn via create_app()."""
    from werkzeug.middleware.proxy_fix import ProxyFix

    _write_data_files(tmp_path)
    (tmp_path / "config.yaml").write_text(
        yaml.dump(
            {
                "server": {"trust_proxy": True},
                "webauthn": {
                    "enabled": True,
                    "rp_id": "idp.example.com",
                    "rp_name": "Example IdP",
                    "expected_origin": "https://idp.example.com",
                },
            }
        )
    )

    app = create_app(str(tmp_path))

    assert isinstance(app.wsgi_app, ProxyFix)
    assert app.config["WEBAUTHN_ENABLED"] is True
    assert app.config["WEBAUTHN_RP_ID"] == "idp.example.com"
    assert app.config["WEBAUTHN_RP_NAME"] == "Example IdP"
    assert app.config["WEBAUTHN_EXPECTED_ORIGIN"] == "https://idp.example.com"


def test_create_app_reads_idp_env_vars_no_kwargs(tmp_path, monkeypatch):
    """IDP_* env vars drive trust_proxy/webauthn via create_app() (no file)."""
    from werkzeug.middleware.proxy_fix import ProxyFix

    _write_data_files(tmp_path)
    monkeypatch.setenv("IDP_TRUST_PROXY", "true")
    monkeypatch.setenv("IDP_WEBAUTHN_ENABLED", "true")
    monkeypatch.setenv("IDP_WEBAUTHN_RP_ID", "idp.env.test")
    monkeypatch.setenv("IDP_WEBAUTHN_EXPECTED_ORIGIN", "https://idp.env.test")

    app = create_app(str(tmp_path))

    assert isinstance(app.wsgi_app, ProxyFix)
    assert app.config["WEBAUTHN_ENABLED"] is True
    assert app.config["WEBAUTHN_RP_ID"] == "idp.env.test"
    assert app.config["WEBAUTHN_EXPECTED_ORIGIN"] == "https://idp.env.test"


def test_create_app_explicit_kwarg_overrides_config(tmp_path):
    """An explicit kwarg still wins over config.yaml (CLI-launcher path)."""
    from werkzeug.middleware.proxy_fix import ProxyFix

    _write_data_files(tmp_path)
    (tmp_path / "config.yaml").write_text(
        yaml.dump({"server": {"trust_proxy": True}})
    )

    # Caller passes trust_proxy=False explicitly: it must shadow the config.
    app = create_app(str(tmp_path), trust_proxy=False)

    assert not isinstance(app.wsgi_app, ProxyFix)


def test_unconsumed_config_guard_fires(tmp_path, caplog):
    """The guard raises and logs at ERROR when a supplied field is dropped."""
    from identity_provider_server.app import (
        ConfigNotConsumedError,
        _assert_config_consumed,
    )
    from identity_provider_server.config import load_config

    (tmp_path / "config.yaml").write_text(
        yaml.dump({"server": {"trust_proxy": True}})
    )
    cfg = load_config(str(tmp_path))

    # Feed a resolved map that is missing a mapped field (trust_proxy) to
    # simulate a loader field that was never threaded through create_app.
    resolved = {"host": cfg.server.host, "port": cfg.server.port}

    with caplog.at_level("ERROR"):
        with pytest.raises(ConfigNotConsumedError) as excinfo:
            _assert_config_consumed(str(tmp_path), cfg, resolved)

    assert "trust_proxy" in str(excinfo.value)
    assert any("not applied" in rec.message for rec in caplog.records)


def test_unconsumed_config_guard_silent_without_config(tmp_path):
    """With no config file or env vars, the guard never fires on any input."""
    from identity_provider_server.app import _assert_config_consumed
    from identity_provider_server.config import load_config

    cfg = load_config(str(tmp_path))
    # Even a deliberately empty resolved map is fine: nothing was supplied.
    _assert_config_consumed(str(tmp_path), cfg, {})


@pytest.mark.smoke
def test_create_app_config_entrypoint_smoke(tmp_path):
    """Smoke: documented create_app('/data') path honors config end-to-end."""
    from werkzeug.middleware.proxy_fix import ProxyFix

    _write_data_files(tmp_path)
    (tmp_path / "config.yaml").write_text(
        yaml.dump({"server": {"trust_proxy": True}})
    )

    app = create_app(str(tmp_path))

    assert app is not None
    assert isinstance(app.wsgi_app, ProxyFix)
