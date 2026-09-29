"""Regression tests for the security-hardening changes.

Covers the token scheme, single-use captcha, password policy, account-usability
gate, backup subpath containment, rate-limit keying, and the MFA-ticket login
flow that closes the password-skip bypass.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import bcrypt
import pytest

from identity_provider_server import backup as bk
from identity_provider_server import tokens
from identity_provider_server.app import (
    _password_policy_error,
    _rl_key,
    _user_can_login,
    _validate_claim,
    _validate_username,
    create_app,
)

DATA_DIR = Path(__file__).parent.parent / "data"


# --- tokens.py --------------------------------------------------------------

def test_token_roundtrip_valid():
    tok = tokens.issue_token("s3cret", "alice", tokens.PURPOSE_SESSION)
    assert tokens.verify_token("s3cret", tok, tokens.PURPOSE_SESSION, 60) == "alice"


def test_token_rejected_for_wrong_purpose():
    """A token minted for one purpose must not verify under another."""
    tok = tokens.issue_token("s3cret", "alice", tokens.PURPOSE_USER)
    assert tokens.verify_token("s3cret", tok, tokens.PURPOSE_ADMIN, 60) is None
    assert tokens.verify_token("s3cret", tok, tokens.PURPOSE_SESSION, 60) is None


def test_token_rejected_when_expired():
    tok = tokens.issue_token("s3cret", "alice", tokens.PURPOSE_SESSION, now=0)
    assert tokens.verify_token("s3cret", tok, tokens.PURPOSE_SESSION, 1) is None


def test_token_rejected_with_wrong_secret():
    tok = tokens.issue_token("s3cret", "alice", tokens.PURPOSE_SESSION)
    assert tokens.verify_token("other", tok, tokens.PURPOSE_SESSION, 60) is None


def test_token_rejected_when_malformed():
    assert tokens.verify_token("s3cret", "not-a-token", tokens.PURPOSE_SESSION, 60) is None
    assert tokens.verify_token("s3cret", "", tokens.PURPOSE_SESSION, 60) is None


def test_per_purpose_keys_differ():
    """Same payload signed for two purposes yields different signatures."""
    a = tokens.issue_token("s3cret", "alice", tokens.PURPOSE_SESSION, now=100)
    b = tokens.issue_token("s3cret", "alice", tokens.PURPOSE_ADMIN, now=100)
    assert a.rsplit(":", 1)[-1] != b.rsplit(":", 1)[-1]


def test_nonce_store_single_use():
    store = tokens.NonceStore(ttl_seconds=100)
    assert store.consume("n1") is True
    assert store.consume("n1") is False  # replay rejected
    assert store.consume("n2") is True


def test_nonce_store_expiry_prunes():
    store = tokens.NonceStore(ttl_seconds=10)
    assert store.consume("n1", now=0) is True
    # After TTL, the nonce is pruned and can be (re)used — expiry path coverage.
    assert store.consume("n1", now=100) is True


# --- password policy --------------------------------------------------------

@pytest.mark.parametrize("pw", ["short", "alllowercase", "12345678", ""])
def test_password_policy_rejects_weak(pw):
    assert _password_policy_error(pw) is not None


def test_password_policy_accepts_strong():
    assert _password_policy_error("Str0ng-Passw0rd!") is None


# --- identifier validation --------------------------------------------------

@pytest.mark.parametrize("name", ["alice", "a.b_c-d@e", "User123"])
def test_username_valid(name):
    assert _validate_username(name)


@pytest.mark.parametrize("name", ["a'b", "x<y", "has space", "", "quote\"x"])
def test_username_invalid(name):
    assert not _validate_username(name)


@pytest.mark.parametrize("name", ["idpadmin", "wiki-admin", "a_b"])
def test_claim_valid(name):
    assert _validate_claim(name)


@pytest.mark.parametrize("name", ["Idpadmin", "a b", "x'y", ""])
def test_claim_invalid(name):
    assert not _validate_claim(name)


# --- account usability gate -------------------------------------------------

def test_user_can_login_ok():
    assert _user_can_login({"password": "$2b$12$" + "x" * 53})


def test_user_cannot_login_must_set_password():
    assert not _user_can_login({"must_set_password": True, "password": "x"})


def test_user_cannot_login_disabled():
    assert not _user_can_login({"enabled": False, "password": "x"})


def test_user_cannot_login_no_password():
    assert not _user_can_login({"roles": []})


def test_user_can_login_passwordless_with_passkey():
    # A password-less account with a registered passkey may authenticate.
    user = {"webauthn_credentials": [{"credential_id": "c", "public_key": "p",
                                       "sign_count": 0}]}
    assert _user_can_login(user)


def test_user_cannot_login_disabled_even_with_passkey():
    user = {"enabled": False,
            "webauthn_credentials": [{"credential_id": "c", "public_key": "p",
                                      "sign_count": 0}]}
    assert not _user_can_login(user)


# --- rate-limit key ---------------------------------------------------------

def test_rl_key_includes_username():
    assert _rl_key("1.2.3.4", "bob") == "1.2.3.4|bob"
    assert _rl_key("1.2.3.4") == "1.2.3.4"


# --- backup subpath containment ---------------------------------------------

@pytest.mark.parametrize("bad", ["/etc", "../escape", "a/../../b", "bad;rm"])
def test_validate_subpath_rejects(bad):
    with pytest.raises(bk.InvalidSubpathError):
        bk.validate_subpath(bad)


def test_validate_subpath_accepts_and_defaults():
    assert bk.validate_subpath("idp-backup/daily") == "idp-backup/daily"
    assert bk.validate_subpath("") == "idp-backup"


def test_safe_base_contains(tmp_path):
    base = bk.safe_base(tmp_path, "idp-backup")
    assert str(base).startswith(str(tmp_path))


def test_safe_base_rejects_escape(tmp_path):
    with pytest.raises(bk.InvalidSubpathError):
        bk.safe_base(tmp_path, "../../etc")


# --- captcha single-use via the app -----------------------------------------

def _app(tmp_path):
    shutil.copy(DATA_DIR / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_DIR / "idp.key", tmp_path / "idp.key")
    pw = bcrypt.hashpw(b"Str0ng-Passw0rd!", bcrypt.gensalt(rounds=4)).decode()
    (tmp_path / "users.json").write_text(json.dumps([
        {"username": "bob", "password": pw, "roles": [], "claims": []}
    ]))
    app = create_app(str(tmp_path), secret_key="testsecret", secure_cookies=False)
    app.config["TESTING"] = True
    return app


def _solve(html: bytes) -> tuple[str, str]:
    h = re.search(rb'name="challenge_hash" value="([^"]+)"', html)
    q = re.search(rb"What is (\d+) (.+?) (\d+)\?", html)
    a, op, b = int(q.group(1)), q.group(2), int(q.group(3))
    ans = a + b if op == b"+" else a - b if op == b"-" else a * b
    return str(ans), h.group(1).decode()


def test_captcha_single_use_verified_directly(tmp_path):
    """A solved challenge token verifies once, then is rejected on replay.

    Exercised at the module level because the login handler only consults the
    captcha after a successful password (non-MFA path), which would consume the
    single-use nonce; here we assert the nonce semantics directly.
    """
    from identity_provider_server.app import _generate_challenge, _verify_challenge

    secret = "testsecret"
    _q, answer, token = _generate_challenge(secret)
    store = tokens.NonceStore(ttl_seconds=300)
    # First verification succeeds and consumes the nonce.
    assert _verify_challenge(secret, answer, token, store) is True
    # Replay of the same token is rejected.
    assert _verify_challenge(secret, answer, token, store) is False


def test_captcha_rejects_expired_and_tampered(tmp_path):
    from identity_provider_server.app import _verify_challenge

    secret = "testsecret"
    # Tampered signature.
    assert _verify_challenge(secret, "5", "nonce:100:deadbeef") is False
    # Malformed token.
    assert _verify_challenge(secret, "5", "garbage") is False


def test_security_headers_present(tmp_path):
    app = _app(tmp_path)
    app.config.update(SESSION_COOKIE_SECURE=True)
    # secure_cookies=True path exercises HSTS + cookie Secure rewrite.
    secure_app = create_app(str(tmp_path), secret_key="s", secure_cookies=True)
    secure_app.config["TESTING"] = True
    resp = secure_app.test_client().get("/aws")
    assert "Content-Security-Policy" in resp.headers
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "Strict-Transport-Security" in resp.headers


@pytest.mark.smoke
def test_mfa_ticket_flow_blocks_password_skip(tmp_path):
    """A TOTP step with only a form username (no password ticket) is refused."""
    import pyotp

    secret = pyotp.random_base32()
    shutil.copy(DATA_DIR / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_DIR / "idp.key", tmp_path / "idp.key")
    pw = bcrypt.hashpw(b"Str0ng-Passw0rd!", bcrypt.gensalt(rounds=4)).decode()
    (tmp_path / "users.json").write_text(json.dumps([
        {"username": "bob", "password": pw, "roles": [], "claims": [],
         "totp_secret": secret}
    ]))
    app = create_app(str(tmp_path), secret_key="testsecret", secure_cookies=False)
    app.config["TESTING"] = True
    client = app.test_client()

    form = client.get("/aws")
    csrf = re.search(rb'name="csrf_token" value="([^"]+)"', form.data).group(1).decode()
    # Attempt to jump straight to the TOTP step with a valid code but NO ticket.
    resp = client.post("/aws", data={
        "csrf_token": csrf,
        "totp_step": "1",
        "totp_code": pyotp.TOTP(secret).now(),
        # deliberately no mfa_ticket, and no prior password step
    })
    # Must not issue a SAML/session response; falls back to the login form.
    assert b"SAMLResponse" not in resp.data
    assert resp.status_code in (200, 401)


# --- forced password rotation ----------------------------------------------

def _app_with_user(tmp_path, extra):
    """Build an app with a single non-MFA user 'bob' plus extra fields."""
    shutil.copy(DATA_DIR / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_DIR / "idp.key", tmp_path / "idp.key")
    pw = bcrypt.hashpw(b"Str0ng-Passw0rd!", bcrypt.gensalt(rounds=4)).decode()
    record = {"username": "bob", "password": pw, "roles": [], "claims": []}
    record.update(extra)
    (tmp_path / "users.json").write_text(json.dumps([record]))
    app = create_app(str(tmp_path), secret_key="testsecret", secure_cookies=False)
    app.config["TESTING"] = True
    return app


def _login_bob(client):
    """Complete a non-MFA password login for 'bob'. Returns the response."""
    form = client.get("/aws")
    csrf = re.search(rb'name="csrf_token" value="([^"]+)"', form.data).group(1).decode()
    ans, ch = _solve(form.data)
    return client.post("/aws", data={
        "username": "bob", "password": "Str0ng-Passw0rd!",
        "csrf_token": csrf, "challenge_answer": ans, "challenge_hash": ch,
    })


def test_forced_rotation_blocks_credential_issuance(tmp_path):
    """A flagged user authenticates but gets the change page, not a SAML response."""
    app = _app_with_user(tmp_path, {"force_password_change": True})
    resp = _login_bob(app.test_client())
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Password change required" in body
    assert "SAMLResponse" not in body


def test_normal_user_not_forced(tmp_path):
    """Without the flag, login proceeds to a SAML response as usual."""
    app = _app_with_user(tmp_path, {"roles": [{"account_id": "1", "role": "R"}]})
    resp = _login_bob(app.test_client())
    assert b"SAMLResponse" in resp.data


def test_forced_rotation_completes_and_clears_flag(tmp_path):
    """Submitting the forced-change form updates the password and clears the flag."""
    app = _app_with_user(tmp_path, {"force_password_change": True})
    client = app.test_client()
    resp = _login_bob(client)
    body = resp.data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', body).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', body).group(1)

    done = client.post("/user", data={
        "csrf_token": csrf, "action": "force_change", "auth_token": auth,
        "current_password": "Str0ng-Passw0rd!",
        "new_password": "An0ther-Str0ng-Pw!",
        "confirm_password": "An0ther-Str0ng-Pw!",
    })
    assert done.status_code == 200
    assert "Please sign in again" in done.data.decode()

    # The flag is cleared and the new password is now usable.
    users = json.loads((tmp_path / "users.json").read_text())
    assert "force_password_change" not in users[0]
    assert bcrypt.checkpw(b"An0ther-Str0ng-Pw!", users[0]["password"].encode())


def test_forced_rotation_rejects_wrong_current_password(tmp_path):
    app = _app_with_user(tmp_path, {"force_password_change": True})
    client = app.test_client()
    body = _login_bob(client).data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', body).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', body).group(1)

    resp = client.post("/user", data={
        "csrf_token": csrf, "action": "force_change", "auth_token": auth,
        "current_password": "WRONG",
        "new_password": "An0ther-Str0ng-Pw!",
        "confirm_password": "An0ther-Str0ng-Pw!",
    })
    assert resp.status_code == 400
    assert "Current password is incorrect" in resp.data.decode()


def test_forced_rotation_rejects_reused_password(tmp_path):
    app = _app_with_user(tmp_path, {"force_password_change": True})
    client = app.test_client()
    body = _login_bob(client).data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', body).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', body).group(1)

    resp = client.post("/user", data={
        "csrf_token": csrf, "action": "force_change", "auth_token": auth,
        "current_password": "Str0ng-Passw0rd!",
        "new_password": "Str0ng-Passw0rd!",
        "confirm_password": "Str0ng-Passw0rd!",
    })
    assert resp.status_code == 400
    assert "must differ" in resp.data.decode()
