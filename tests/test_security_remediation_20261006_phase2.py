"""Phase 2 security remediation tests (review idp-2026-10-06).

Covers two findings:

* **Finding 6 (High)** — mandatory administrator MFA was bypassed on GET
  /admin. The session cookie now carries a signed factor marker (``mfa``) and
  the admin-entry gate refuses a single-factor cookie, so a password-only (or
  bare passkey) session can no longer reach the panel or mint a PURPOSE_ADMIN
  step-up token. ``remove_mfa`` additionally refuses to strip the last factor
  from an idpadmin account.
* **Finding 2 (Medium)** — three second-leg auth handlers dropped the
  account-eligibility re-check, letting a just-disabled/locked account complete
  the ceremony. Each now re-runs the full predicate before issuance.
"""

from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path

import bcrypt
import pyotp
import pytest

from identity_provider_server.app import create_app
from identity_provider_server.tokens import (
    PURPOSE_ADMIN,
    issue_session_token,
    issue_token,
    verify_session_token,
)

DATA_SRC = Path(__file__).parent.parent / "data"
SECRET = "phase2secret-00000000000000000000000"
PW = "Str0ng-Passw0rd!"


def _hash(pw: str = PW) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=4)).decode()


def _solve(html: bytes) -> tuple[str, str]:
    """Solve the arithmetic human-verification challenge in a login form."""
    h = re.search(rb'name="challenge_hash" value="([^"]+)"', html)
    q = re.search(rb"What is (\d+) (.+?) (\d+)\?", html)
    a, op, b = int(q.group(1)), q.group(2), int(q.group(3))
    ans = a + b if op == b"+" else a - b if op == b"-" else a * b
    return str(ans), h.group(1).decode()


def _csrf(html: bytes) -> str:
    return re.search(rb'name="csrf_token" value="([^"]+)"', html).group(1).decode()


def _app(tmp_path: Path, users: list[dict], services: str | None = None):
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    (tmp_path / "users.json").write_text(json.dumps(users))
    (tmp_path / "claims.json").write_text(json.dumps(["idpadmin", "developer"]))
    (tmp_path / "services.yaml").write_text(
        services or "saml:\n  aws: https://signin.aws.amazon.com/saml\n"
    )
    app = create_app(
        str(tmp_path), secret_key=SECRET, secure_cookies=False, trust_proxy=False,
    )
    app.config["TESTING"] = True
    return app


def _set_session(client, username: str, *, mfa: bool) -> None:
    client.set_cookie(
        "idp_session",
        issue_session_token(
            SECRET, username, auth_time=int(time.time()), epoch=0, mfa=mfa,
        ),
        domain="localhost",
    )


def _audit_records(tmp_path: Path) -> list[dict]:
    path = tmp_path / "audit.log"
    if not path.is_file():
        return []
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


# ===========================================================================
# Finding 6 — mandatory admin MFA on the GET /admin entry path
# ===========================================================================

def test_single_factor_session_cannot_reach_admin_panel(tmp_path):
    """A password-only (single-factor) admin session is refused at GET /admin.

    The gate must fall through to the login form rather than render the panel
    and mint a PURPOSE_ADMIN step-up token.
    """
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "claims": ["idpadmin"],
         "roles": [], "totp_secret": pyotp.random_base32(), "session_epoch": 0},
    ])
    client = app.test_client()
    _set_session(client, "admin", mfa=False)
    resp = client.get("/admin")
    body = resp.data.decode()
    assert "Sign in" in body
    # No step-up token is minted for a single-factor session.
    assert 'name="auth_token"' not in body


def test_two_factor_session_reaches_admin_panel(tmp_path):
    """A two-factor admin session renders the panel and mints a step-up token."""
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "claims": ["idpadmin"],
         "roles": [], "totp_secret": pyotp.random_base32(), "session_epoch": 0},
    ])
    client = app.test_client()
    _set_session(client, "admin", mfa=True)
    resp = client.get("/admin")
    body = resp.data.decode()
    assert resp.status_code == 200
    assert "Add User" in body
    auth = re.search(r'name="auth_token" value="([^"]+)"', body).group(1)
    # The minted token is a genuine PURPOSE_ADMIN step-up token.
    from identity_provider_server.tokens import verify_token

    assert verify_token(SECRET, auth, PURPOSE_ADMIN, 3600) == "admin"


def test_totpless_admin_cannot_reach_panel_via_get(tmp_path):
    """A TOTP-less idpadmin cannot reach the panel via GET /admin.

    Even a (necessarily single-factor) session for an admin who never enrolled
    a second factor is refused — the mandatory-MFA gate is honoured on the GET
    entry path, not only on POST login.
    """
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "claims": ["idpadmin"],
         "roles": [], "session_epoch": 0},  # no totp_secret
    ])
    client = app.test_client()
    _set_session(client, "admin", mfa=False)
    resp = client.get("/admin")
    assert "Sign in" in resp.data.decode()


def test_single_factor_session_cannot_reach_backups_or_user_detail(tmp_path):
    """The other two session-cookie admin entry points enforce the gate too."""
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "claims": ["idpadmin"],
         "roles": [], "totp_secret": pyotp.random_base32(), "session_epoch": 0},
    ])
    client = app.test_client()
    _set_session(client, "admin", mfa=False)
    # /admin/backups redirects back to /admin (no panel) for a one-factor cookie.
    assert client.get("/admin/backups").status_code in (302, 308)
    # The user-detail GET also refuses and redirects to the admin login.
    assert client.get("/admin/user/admin").status_code in (302, 308)


def test_legacy_session_cookie_verifies_as_single_factor():
    """An old 3-field session cookie (no mfa marker) still verifies.

    It must be read back as single-factor rather than rejected, so an existing
    cookie minted before the field existed does not crash verification.
    """
    now = int(time.time())
    legacy = issue_token(SECRET, f"alice|{now}|0", "session")
    out = verify_session_token(SECRET, legacy, 3600, 12 * 3600)
    assert out == ("alice", now, 0, False)


def test_remove_mfa_refused_for_admin_without_passkey(tmp_path):
    """Stripping the last factor from an idpadmin account is refused.

    TOTP may only be removed when a registered passkey remains; otherwise the
    account would be left able to log in with a password alone — the
    precondition the GET /admin bypass exploited.
    """
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "claims": ["idpadmin"],
         "roles": [], "totp_secret": pyotp.random_base32(), "session_epoch": 0},
        {"username": "boss", "password": _hash(), "claims": ["idpadmin"],
         "roles": [], "totp_secret": pyotp.random_base32(), "session_epoch": 0},
    ])
    client = app.test_client()
    _set_session(client, "admin", mfa=True)
    html = client.get("/admin").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    resp = client.post("/admin", data={
        "csrf_token": csrf, "auth_token": auth, "action": "remove_mfa",
        "target_user": "boss",
    })
    assert b"must" in resp.data and b"second factor" in resp.data
    # The target still holds its second factor.
    stored = json.loads((tmp_path / "users.json").read_text())
    boss = next(u for u in stored if u["username"] == "boss")
    assert boss.get("totp_secret")


def test_remove_mfa_allowed_for_non_admin(tmp_path):
    """A non-admin account can still have its MFA removed (regression guard)."""
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "claims": ["idpadmin"],
         "roles": [], "totp_secret": pyotp.random_base32(), "session_epoch": 0},
        {"username": "bob", "password": _hash(), "claims": ["developer"],
         "roles": [], "totp_secret": pyotp.random_base32(), "session_epoch": 0},
    ])
    client = app.test_client()
    _set_session(client, "admin", mfa=True)
    html = client.get("/admin").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    resp = client.post("/admin", data={
        "csrf_token": csrf, "auth_token": auth, "action": "remove_mfa",
        "target_user": "bob",
    })
    assert b"MFA removed" in resp.data


# ===========================================================================
# Finding 2 — eligibility re-check on the three second-leg handlers
# ===========================================================================

def _login_to_sp_mfa(client, secret, path="/aws", username="bob"):
    """Complete the password leg and return (csrf, ticket) for the TOTP leg."""
    form = client.get(path)
    ans, ch = _solve(form.data)
    resp = client.post(path, data={
        "username": username, "password": PW, "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    ticket = re.search(
        rb'name="mfa_ticket" value="([^"]+)"', resp.data
    ).group(1).decode()
    return _csrf(resp.data), ticket


def _disable_user(tmp_path: Path, username: str) -> None:
    users = json.loads((tmp_path / "users.json").read_text())
    for u in users:
        if u["username"] == username:
            u["enabled"] = False
    (tmp_path / "users.json").write_text(json.dumps(users))


def test_sp_totp_leg_refuses_disabled_account(tmp_path):
    """SP login TOTP leg refuses an account disabled after the password leg.

    No credential is issued and no success audit record is written.
    """
    secret = pyotp.random_base32()
    app = _app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "totp_secret": secret, "enabled": True},
    ])
    client = app.test_client()
    csrf, ticket = _login_to_sp_mfa(client, secret)
    # Disable the account between the two legs.
    _disable_user(tmp_path, "bob")
    resp = client.post("/aws", data={
        "csrf_token": csrf, "totp_step": "1", "mfa_ticket": ticket,
        "totp_code": pyotp.TOTP(secret).now(),
    })
    assert resp.status_code == 401
    assert b"SAMLResponse" not in resp.data
    assert "idp_session" not in resp.headers.get("Set-Cookie", "")
    assert not any(r.get("result") == "success" for r in _audit_records(tmp_path))


def test_user_totp_leg_refuses_disabled_account(tmp_path):
    """/user TOTP leg refuses an account disabled after the password leg."""
    secret = pyotp.random_base32()
    app = _app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "totp_secret": secret, "enabled": True},
    ])
    client = app.test_client()
    form = client.get("/user")
    ans, ch = _solve(form.data)
    resp = client.post("/user", data={
        "action": "login", "username": "bob", "password": PW,
        "csrf_token": _csrf(form.data),
        "challenge_answer": ans, "challenge_hash": ch,
    })
    ticket = re.search(
        rb'name="mfa_ticket" value="([^"]+)"', resp.data
    ).group(1).decode()
    csrf = _csrf(resp.data)
    _disable_user(tmp_path, "bob")
    done = client.post("/user", data={
        "csrf_token": csrf, "totp_step": "1", "service_path": "user",
        "mfa_ticket": ticket, "totp_code": pyotp.TOTP(secret).now(),
    })
    assert done.status_code == 401
    # The account-settings page is not rendered for a disabled account.
    assert b"Change Password" not in done.data


def test_sp_totp_leg_refuses_locked_account(tmp_path):
    """SP TOTP leg also honours a durable lockout earned after the first leg."""
    secret = pyotp.random_base32()
    app = _app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "totp_secret": secret, "enabled": True},
    ])
    client = app.test_client()
    csrf, ticket = _login_to_sp_mfa(client, secret)
    # Simulate a durable lockout landing between the legs. The lockout state
    # lives on the user record (``locked_until``); the before-request reload
    # picks up the rewritten users.json.
    users = json.loads((tmp_path / "users.json").read_text())
    for u in users:
        if u["username"] == "bob":
            u["failed_count"] = 99
            u["locked_until"] = time.time() + 3600
    (tmp_path / "users.json").write_text(json.dumps(users))
    resp = client.post("/aws", data={
        "csrf_token": csrf, "totp_step": "1", "mfa_ticket": ticket,
        "totp_code": pyotp.TOTP(secret).now(),
    })
    assert resp.status_code == 401
    assert b"SAMLResponse" not in resp.data


# ===========================================================================
# Smoke
# ===========================================================================

@pytest.mark.smoke
def test_admin_mfa_gate_smoke(tmp_path):
    """Happy path + bypass guard: two-factor reaches the panel, one-factor does
    not."""
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "claims": ["idpadmin"],
         "roles": [], "totp_secret": pyotp.random_base32(), "session_epoch": 0},
    ])
    client = app.test_client()
    _set_session(client, "admin", mfa=True)
    assert b"Add User" in client.get("/admin").data

    one_factor = app.test_client()
    _set_session(one_factor, "admin", mfa=False)
    assert b"Sign in" in one_factor.get("/admin").data
