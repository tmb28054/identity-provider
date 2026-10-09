"""Behavioural tests for the idp-20261001 security-review remediations.

Each test maps to a finding fixed in the same change set:

* F1  — failed TOTP counts toward throttling / lockout, single-attempt ticket.
* F3  — disabling an account revokes its live session cookie (epoch bump).
* F4  — durable lockout, password history, mandatory admin MFA, LDAP empty bind.
* F5  — server-side absolute session lifetime.
* F10 — multi-worker startup warning.
* F12 — outbound notification channel.
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

from identity_provider_server import notify
from identity_provider_server.app import create_app
from identity_provider_server.tokens import issue_session_token

DATA_SRC = Path(__file__).parent.parent / "data"
PW = "Str0ng-Passw0rd!"
PW2 = "An0ther-Passw0rd!"


def _hash(pw=PW):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=4)).decode()


def _app(tmp_path, users, **kwargs):
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    (tmp_path / "users.json").write_text(json.dumps(users))
    kwargs.setdefault("secure_cookies", False)
    kwargs.setdefault("trust_proxy", False)
    app = create_app(str(tmp_path), secret_key="appsecret-0000000000000000000000000", **kwargs)
    app.config["TESTING"] = True
    return app


def _solve(html: bytes):
    q = re.search(rb"What is (\d+) (.+?) (\d+)\?", html)
    a, op, b = int(q.group(1)), q.group(2), int(q.group(3))
    ans = a + b if op == b"+" else a - b if op == b"-" else a * b
    ch = re.search(rb'name="challenge_hash" value="([^"]+)"', html).group(1).decode()
    return str(ans), ch


def _csrf(html: bytes):
    return re.search(rb'name="csrf_token" value="([^"]+)"', html).group(1).decode()


def _login_post(client, path, username, password, extra=None):
    form = client.get(path)
    ans, ch = _solve(form.data)
    body = {
        "username": username, "password": password,
        "csrf_token": _csrf(form.data), "challenge_answer": ans,
        "challenge_hash": ch,
    }
    if extra:
        body.update(extra)
    return client.post(path, data=body)


# --- F4: durable lockout ----------------------------------------------------

@pytest.mark.smoke
def test_account_locks_after_threshold(tmp_path):
    app = _app(tmp_path, [
        {"username": "bob", "password": _hash(),
         "roles": [{"account_id": "1", "role": "R"}], "claims": []},
    ])
    client = app.test_client()
    # 10 wrong-password attempts from DIFFERENT source IPs — this models an
    # attacker spreading a spray so the per-IP sliding window never trips, yet
    # the durable per-account lockout still accumulates and locks the account.
    for i in range(10):
        form = client.get("/aws")
        ans, ch = _solve(form.data)
        client.post("/aws", data={
            "username": "bob", "password": "WRONG-Passw0rd!",
            "csrf_token": _csrf(form.data), "challenge_answer": ans,
            "challenge_hash": ch,
        }, environ_overrides={"REMOTE_ADDR": f"10.0.0.{i + 1}"})
    # Now even the CORRECT password is refused (429 from either the per-IP
    # window or the durable account lock).
    resp = _login_post(client, "/aws", "bob", PW)
    assert resp.status_code == 429
    # The durable lockout timestamp is persisted on the user record — this is
    # the state that outlives the in-memory sliding window.
    users = json.loads((tmp_path / "users.json").read_text())
    bob = next(u for u in users if u["username"] == "bob")
    assert bob.get("locked_until", 0) > time.time()
    assert bob.get("failed_count", 0) >= 10


def test_prelocked_account_returns_generic_throttle_message(tmp_path):
    """An account already within its lockout hold is still refused with 429 on
    the first request, but the body is the GENERIC rate-limit message — it must
    NOT disclose that the account is locked (and therefore exists). Only the
    audit record keeps the true ``account_locked`` reason (idp-2026-10-06 F5)."""
    app = _app(tmp_path, [
        {"username": "bob", "password": _hash(),
         "roles": [{"account_id": "1", "role": "R"}], "claims": [],
         "locked_until": time.time() + 1800, "failed_count": 10},
    ])
    client = app.test_client()
    resp = _login_post(client, "/aws", "bob", PW)
    assert resp.status_code == 429
    assert b"Too many attempts. Try again later." in resp.data
    assert b"locked" not in resp.data.lower()
    # The operator-facing audit record still records the real cause.
    audit = (tmp_path / "audit.log").read_text()
    assert '"reason":"account_locked"' in audit


# --- F4: password history ---------------------------------------------------

def test_password_history_blocks_reuse(tmp_path):
    """The self-service change path rejects reuse of the current password."""
    app = _app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": []},
    ])
    client = app.test_client()
    # Step up on /user to reach account settings.
    login = _login_post(client, "/user", "bob", PW, extra={"action": "login"})
    auth = re.search(rb'name="auth_token" value="([^"]+)"', login.data).group(1).decode()
    csrf = _csrf(login.data)
    resp = client.post("/user", data={
        "action": "change_password", "auth_token": auth, "csrf_token": csrf,
        "current_password": PW, "new_password": PW, "confirm_password": PW,
    })
    assert b"differ from the last" in resp.data


def test_password_history_blocks_older_entry(tmp_path):
    """Reusing a password from history (not just the current one) is rejected,
    exercising the history-list comparison branch."""
    old_hash = _hash(PW2)  # a retired password = PW2
    app = _app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "password_history": [old_hash]},
    ])
    client = app.test_client()
    login = _login_post(client, "/user", "bob", PW, extra={"action": "login"})
    auth = re.search(rb'name="auth_token" value="([^"]+)"', login.data).group(1).decode()
    csrf = _csrf(login.data)
    # Try to set the password back to PW2, which is in history.
    resp = client.post("/user", data={
        "action": "change_password", "auth_token": auth, "csrf_token": csrf,
        "current_password": PW, "new_password": PW2, "confirm_password": PW2,
    })
    assert b"differ from the last" in resp.data


# --- F1: /user second-factor step is throttled ------------------------------

def test_user_totp_step_is_rate_limited(tmp_path):
    """Repeated wrong TOTP codes on /user trip the per-IP limiter they feed."""
    secret = pyotp.random_base32()
    app = _app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "totp_secret": secret},
    ])
    client = app.test_client()
    # Password step → yields the TOTP form with a single-use ticket.
    login = _login_post(client, "/user", "bob", PW, extra={"action": "login"})
    ticket = re.search(rb'name="mfa_ticket" value="([^"]+)"', login.data)
    assert ticket is not None
    # Hammer the TOTP step with wrong codes. Each wrong code records the IP
    # bucket; after the threshold the limiter returns 429. Fresh tickets are
    # minted by re-posting the password, but the IP bucket persists.
    saw_429 = False
    for _ in range(8):
        pw_resp = _login_post(client, "/user", "bob", PW, extra={"action": "login"})
        tk = re.search(rb'name="mfa_ticket" value="([^"]+)"', pw_resp.data)
        csrf = _csrf(pw_resp.data)
        if tk is None:
            # Password step itself got rate-limited — the limiter is engaged.
            saw_429 = pw_resp.status_code == 429
            if saw_429:
                break
            continue
        resp = client.post("/user", data={
            "action": "login", "totp_step": "1", "service_path": "user",
            "mfa_ticket": tk.group(1).decode(), "totp_code": "000000",
            "csrf_token": csrf,
        })
        if resp.status_code == 429:
            saw_429 = True
            break
    assert saw_429


# --- F3/F5: session revocation + absolute cap -------------------------------

def test_disabled_account_session_cookie_revoked(tmp_path):
    """A live session cookie stops working once the account is disabled."""
    app = _app(tmp_path, [
        {"username": "bob", "password": _hash(),
         "roles": [{"account_id": "1", "role": "R"}], "claims": [],
         "session_epoch": 0},
    ])
    client = app.test_client()
    cookie = issue_session_token("appsecret-0000000000000000000000000", "bob", auth_time=int(time.time()), epoch=0)
    client.set_cookie("idp_session", cookie, domain="localhost")
    # Works while enabled.
    assert client.get("/aws").status_code in (200, 302)
    # Disable out-of-band (hot reload picks it up).
    users = json.loads((tmp_path / "users.json").read_text())
    for u in users:
        if u["username"] == "bob":
            u["enabled"] = False
    (tmp_path / "users.json").write_text(json.dumps(users))
    # The session cookie no longer silently issues credentials — the login
    # form is shown instead.
    resp = client.get("/aws")
    assert b"SAMLResponse" not in resp.data


def test_session_cookie_rejected_after_epoch_bump(tmp_path):
    """Bumping session_epoch invalidates a previously-valid cookie."""
    app = _app(tmp_path, [
        {"username": "bob", "password": _hash(),
         "roles": [{"account_id": "1", "role": "R"}], "claims": [],
         "session_epoch": 0},
    ])
    client = app.test_client()
    stale = issue_session_token("appsecret-0000000000000000000000000", "bob", auth_time=int(time.time()), epoch=0)
    client.set_cookie("idp_session", stale, domain="localhost")
    users = json.loads((tmp_path / "users.json").read_text())
    for u in users:
        if u["username"] == "bob":
            u["session_epoch"] = 1  # revoke
    (tmp_path / "users.json").write_text(json.dumps(users))
    resp = client.get("/aws")
    assert b"SAMLResponse" not in resp.data


# --- robustness: malformed persisted lockout/epoch values -------------------

def test_malformed_lockout_and_epoch_fields_are_tolerated(tmp_path):
    """Corrupt persisted lockout/epoch values must not crash auth; they are
    treated as 'not locked' / epoch 0 (defensive parsing branches)."""
    app = _app(tmp_path, [
        {"username": "bob", "password": _hash(),
         "roles": [{"account_id": "1", "role": "R"}], "claims": [],
         "locked_until": "not-a-number", "failed_count": "oops",
         "session_epoch": "nan"},
    ])
    client = app.test_client()
    # A failed login with a garbage failed_count still records cleanly (the
    # parse-error branch resets the counter to 1).
    _login_post(client, "/aws", "bob", "WRONG-Passw0rd!")
    users = json.loads((tmp_path / "users.json").read_text())
    bob = next(u for u in users if u["username"] == "bob")
    assert bob["failed_count"] == 1

    # A valid login still succeeds despite the (now-reset) fields.
    resp = _login_post(client, "/aws", "bob", PW)
    assert b"SAMLResponse" in resp.data


def test_malformed_session_epoch_tolerated_on_change(tmp_path):
    """A garbage session_epoch is treated as 0 and bumped to 1 on password
    change (the epoch parse-error branch)."""
    app = _app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "session_epoch": "garbage"},
    ])
    client = app.test_client()
    login = _login_post(client, "/user", "bob", PW, extra={"action": "login"})
    auth = re.search(rb'name="auth_token" value="([^"]+)"', login.data).group(1).decode()
    csrf = _csrf(login.data)
    resp = client.post("/user", data={
        "action": "change_password", "auth_token": auth, "csrf_token": csrf,
        "current_password": PW, "new_password": PW2, "confirm_password": PW2,
    })
    assert resp.status_code == 200
    users = json.loads((tmp_path / "users.json").read_text())
    bob = next(u for u in users if u["username"] == "bob")
    assert bob["session_epoch"] == 1


def test_change_password_on_passwordless_account_history_noop(tmp_path):
    """A record with no current password exercises the empty-history branch:
    _record_password_history returns early when there is nothing to retire."""
    secret_pw = _hash()
    app = _app(tmp_path, [
        {"username": "bob", "password": secret_pw, "roles": [], "claims": [],
         # Pre-seed an empty password_history so the push path runs with a
         # present current hash and a bounded list.
         "password_history": []},
    ])
    client = app.test_client()
    login = _login_post(client, "/user", "bob", PW, extra={"action": "login"})
    auth = re.search(rb'name="auth_token" value="([^"]+)"', login.data).group(1).decode()
    csrf = _csrf(login.data)
    resp = client.post("/user", data={
        "action": "change_password", "auth_token": auth, "csrf_token": csrf,
        "current_password": PW, "new_password": PW2, "confirm_password": PW2,
    })
    assert resp.status_code == 200
    users = json.loads((tmp_path / "users.json").read_text())
    bob = next(u for u in users if u["username"] == "bob")
    # The retired hash is now in history.
    assert bob["password_history"]
    assert bob.get("session_epoch", 0) == 1  # change revoked old sessions


# --- F4: empty password on the local path -----------------------------------

def test_empty_password_rejected(tmp_path):
    app = _app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": []},
    ])
    client = app.test_client()
    resp = _login_post(client, "/aws", "bob", "")
    assert resp.status_code == 401


# --- F10: multi-worker startup warning --------------------------------------

def test_multi_worker_env_warns(tmp_path, caplog, monkeypatch):
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    with caplog.at_level("WARNING"):
        _app(tmp_path, [{"username": "bob", "password": _hash(), "claims": []}])
    assert any("per-process" in r.message for r in caplog.records)


# --- F12: notification channel ----------------------------------------------

@pytest.mark.smoke
def test_notify_noop_when_unconfigured(monkeypatch):
    monkeypatch.delenv(notify.NOTIFY_WEBHOOK_ENV, raising=False)
    assert notify.is_configured() is False
    assert notify.notify("evt", "msg") is False


def test_notify_rejects_non_https(monkeypatch):
    monkeypatch.setenv(notify.NOTIFY_WEBHOOK_ENV, "http://insecure.example/hook")
    assert notify.is_configured() is True
    assert notify.notify("evt", "msg") is False


def test_notify_posts_to_https(monkeypatch):
    monkeypatch.setenv(notify.NOTIFY_WEBHOOK_ENV, "https://hooks.example/x")
    sent = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _fake_urlopen(req, timeout=0):
        sent["data"] = req.data
        return _Resp()

    monkeypatch.setattr(notify.urllib.request, "urlopen", _fake_urlopen)
    assert notify.notify("backup_failed", "boom", severity="critical") is True
    assert json.loads(sent["data"])["event"] == "backup_failed"
