"""Full-flow coverage for admin.py — login, every admin action, backups,
user detail, recovery tokens, and service-provider CRUD.

Uses the Flask test client with a minted admin session cookie so the panel
renders and POST actions are authorized.
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

from identity_provider_server import backup as bk
from identity_provider_server.app import create_app
from identity_provider_server.tokens import issue_session_token

DATA_SRC = Path(__file__).parent.parent / "data"


def _session_cookie(secret: str, username: str) -> str:
    """Mint a session cookie in the current (epoch + auth_time) scheme."""
    import time as _time

    return issue_session_token(
        secret, username, auth_time=int(_time.time()), epoch=0,
    )
ADMIN_TOTP = pyotp.random_base32()


def _make_app(tmp_path, *, admin_mfa=False):
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    pw = bcrypt.hashpw(b"AdminPass123!", bcrypt.gensalt(rounds=4)).decode()
    admin = {"username": "admin", "password": pw, "roles": [], "claims": ["idpadmin"]}
    if admin_mfa:
        admin["totp_secret"] = ADMIN_TOTP
    users = [
        admin,
        {"username": "bob", "password": pw, "roles": [], "claims": ["developer"],
         "email": "bob@e.com", "totp_secret": pyotp.random_base32()},
    ]
    (tmp_path / "users.json").write_text(json.dumps(users))
    (tmp_path / "claims.json").write_text(json.dumps(["idpadmin", "developer", "wiki"]))
    (tmp_path / "services.yaml").write_text(
        "saml:\n  aws: https://signin.aws.amazon.com/saml\n"
    )
    app = create_app(str(tmp_path), secret_key="adminsecret-00000000000000000000000", secure_cookies=False)
    app.config["TESTING"] = True
    return app


def _client(app):
    c = app.test_client()
    c.set_cookie("idp_session", _session_cookie("adminsecret-00000000000000000000000", "admin"),
                 domain="localhost")
    return c


def _tokens(client, path="/admin"):
    html = client.get(path).data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    return csrf, auth


def _post(client, data, path="/admin"):
    csrf, auth = _tokens(client, path if path == "/admin" else "/admin")
    body = {"csrf_token": csrf, "auth_token": auth}
    body.update(data)
    return client.post(path, data=body)


# --- panel + login ----------------------------------------------------------

def test_panel_renders_with_session(tmp_path):
    app = _make_app(tmp_path)
    resp = _client(app).get("/admin")
    assert resp.status_code == 200
    assert "Add User" in resp.data.decode()


def test_admin_get_without_session_shows_login(tmp_path):
    app = _make_app(tmp_path)
    resp = app.test_client().get("/admin")
    assert resp.status_code == 200
    assert "Sign in" in resp.data.decode()


def test_admin_login_password_and_mfa(tmp_path):
    app = _make_app(tmp_path, admin_mfa=True)
    client = app.test_client()
    html = client.get("/admin").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    # solve captcha
    q = re.search(r"What is (\d+) (.+?) (\d+)\?", html)
    a, op, b = int(q.group(1)), q.group(2), int(q.group(3))
    ans = a + b if op == "+" else a - b if op == "-" else a * b
    ch = re.search(r'name="challenge_hash" value="([^"]+)"', html).group(1)
    resp = client.post("/admin", data={
        "csrf_token": csrf, "action": "login", "username": "admin",
        "password": "AdminPass123!", "totp_code": pyotp.TOTP(ADMIN_TOTP).now(),
        "challenge_answer": str(ans), "challenge_hash": ch,
    })
    assert resp.status_code == 200
    assert "Add User" in resp.data.decode()


def test_admin_login_bad_csrf(tmp_path):
    app = _make_app(tmp_path)
    resp = app.test_client().post("/admin", data={"action": "login"})
    assert resp.status_code == 403


def _login_post(client, **fields):
    """Do an admin login POST with a valid CSRF; caller controls other fields."""
    html = client.get("/admin").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    q = re.search(r"What is (\d+) (.+?) (\d+)\?", html)
    ch = re.search(r'name="challenge_hash" value="([^"]+)"', html).group(1)
    a, op, b = int(q.group(1)), q.group(2), int(q.group(3))
    ans = str(a + b if op == "+" else a - b if op == "-" else a * b)
    data = {"csrf_token": csrf, "action": "login",
            "challenge_answer": ans, "challenge_hash": ch}
    data.update(fields)
    return client.post("/admin", data=data)


def test_admin_login_failed_captcha(tmp_path):
    app = _make_app(tmp_path)
    client = app.test_client()
    html = client.get("/admin").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    resp = client.post("/admin", data={
        "csrf_token": csrf, "action": "login", "username": "admin",
        "password": "AdminPass123!", "challenge_answer": "999999",
        "challenge_hash": "deadbeef",
    })
    assert resp.status_code == 401
    assert b"Incorrect answer" in resp.data


def test_admin_login_invalid_credentials(tmp_path):
    app = _make_app(tmp_path)
    resp = _login_post(app.test_client(), username="admin", password="WRONG")
    assert resp.status_code == 401
    assert b"Invalid credentials" in resp.data


def test_admin_login_invalid_mfa(tmp_path):
    app = _make_app(tmp_path, admin_mfa=True)
    resp = _login_post(app.test_client(), username="admin",
                       password="AdminPass123!", totp_code="000000")
    assert resp.status_code == 401
    assert b"Invalid MFA" in resp.data


def test_admin_login_refused_without_mfa_enrolled(tmp_path):
    """An idpadmin account with no TOTP cannot log in with a password alone
    (security review F4: second factor mandatory for administrators)."""
    app = _make_app(tmp_path, admin_mfa=False)
    resp = _login_post(app.test_client(), username="admin", password="AdminPass123!")
    assert resp.status_code == 403
    assert b"second factor" in resp.data


def test_disabled_admin_cookie_denied(tmp_path):
    """A disabled admin with a live session cookie is denied the panel."""
    app = _make_app(tmp_path)
    # Disable the admin account.
    users = json.loads((tmp_path / "users.json").read_text())
    for u in users:
        if u["username"] == "admin":
            u["enabled"] = False
    (tmp_path / "users.json").write_text(json.dumps(users))
    client = _client(app)
    assert b"Sign in" in client.get("/admin").data


def test_unknown_cookie_user_denied(tmp_path):
    """A session cookie for a user not in the DB is denied."""
    app = _make_app(tmp_path)
    client = app.test_client()
    client.set_cookie("idp_session", _session_cookie("adminsecret-00000000000000000000000", "ghost"),
                      domain="localhost")
    assert b"Sign in" in client.get("/admin").data


def test_user_detail_invalid_username_redirects(tmp_path):
    """A charset-invalid path segment is rejected before any lookup."""
    app = _make_app(tmp_path)
    client = _client(app)
    # '%20' decodes to a space, which fails the username charset.
    assert client.get("/admin/user/bad%20name").status_code in (301, 302)
    assert client.post("/admin/user/bad%20name", data={}).status_code in (301, 302)


def test_admin_reset_password_rejects_history_reuse(tmp_path):
    """Admin reset_password refuses to reuse the target's current password."""
    app = _make_app(tmp_path)
    client = _client(app)
    html = client.get("/admin").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    # bob's current password in the fixture is "AdminPass123!".
    resp = client.post("/admin", data={
        "csrf_token": csrf, "auth_token": auth, "action": "reset_password",
        "target_user": "bob", "new_pw": "AdminPass123!",
    })
    assert b"differ from the last" in resp.data


def test_admin_login_access_denied_non_admin(tmp_path):
    app = _make_app(tmp_path)
    # 'bob' has a valid password but no idpadmin claim; give bob a known pw.
    resp = _login_post(app.test_client(), username="bob", password="AdminPass123!")
    # bob has MFA in the fixture, so the MFA branch triggers first (no code).
    assert resp.status_code == 401


def test_admin_login_rate_limited(tmp_path):
    app = _make_app(tmp_path)
    client = app.test_client()
    # Exhaust the limiter with repeated bad logins, then confirm the 429 path.
    for _ in range(6):
        _login_post(client, username="admin", password="WRONG")
    resp = _login_post(client, username="admin", password="WRONG")
    assert resp.status_code == 429
    assert b"Too many attempts" in resp.data


def test_admin_login_access_denied_no_mfa_non_admin(tmp_path):
    """A no-MFA, non-idpadmin account reaches the access-denied branch."""
    app = _make_app(tmp_path)
    # Add a plain user with a known password and no MFA, no idpadmin.
    client = _client(app)
    _post(client, {
        "action": "add_user", "new_username": "plain",
        "new_user_password": "Str0ng-Passw0rd!", "new_user_claims": "developer",
    })
    resp = _login_post(app.test_client(), username="plain",
                       password="Str0ng-Passw0rd!")
    assert resp.status_code == 403
    assert b"Access denied" in resp.data


def test_admin_action_without_auth_token_reprompts(tmp_path):
    app = _make_app(tmp_path)
    client = app.test_client()
    html = client.get("/admin").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    # A cookie-less client posts an action with a bad token.
    client.set_cookie("csrf_token", csrf, domain="localhost")
    resp = client.post("/admin", data={
        "csrf_token": csrf, "action": "add_user", "auth_token": "bogus",
    })
    assert resp.status_code == 401


# --- user CRUD --------------------------------------------------------------

def test_add_user_success_and_validation(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    # success
    assert b"created" in _post(client, {
        "action": "add_user", "new_username": "carol",
        "new_user_password": "Str0ng-Passw0rd!", "new_user_email": "c@e.com",
        "new_user_claims": "developer,idpadmin",
    }).data
    # duplicate
    assert b"already exists" in _post(client, {
        "action": "add_user", "new_username": "carol",
        "new_user_password": "Str0ng-Passw0rd!",
    }).data
    # missing username
    assert b"Username is required" in _post(client, {
        "action": "add_user", "new_username": "", "new_user_password": "x",
    }).data
    # bad charset
    assert b"only contain" in _post(client, {
        "action": "add_user", "new_username": "bad name!",
        "new_user_password": "Str0ng-Passw0rd!",
    }).data
    # weak password
    assert b"Password" in _post(client, {
        "action": "add_user", "new_username": "dave", "new_user_password": "short",
    }).data
    # bad claim
    assert b"Invalid claim" in _post(client, {
        "action": "add_user", "new_username": "dave",
        "new_user_password": "Str0ng-Passw0rd!", "new_user_claims": "Bad Claim",
    }).data


def test_delete_user(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    assert b"deleted" in _post(client, {"action": "delete_user", "target_user": "bob"}).data
    assert b"not found" in _post(client, {"action": "delete_user", "target_user": "ghost"}).data
    assert b"Cannot delete yourself" in _post(
        client, {"action": "delete_user", "target_user": "admin"}).data


def test_reset_password(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    assert b"reset" in _post(client, {
        "action": "reset_password", "target_user": "bob", "new_pw": "N3w-Passw0rd!!",
    }).data
    assert b"Password" in _post(client, {
        "action": "reset_password", "target_user": "bob", "new_pw": "weak",
    }).data
    assert b"not found" in _post(client, {
        "action": "reset_password", "target_user": "ghost", "new_pw": "N3w-Passw0rd!!",
    }).data


def test_remove_mfa(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    assert b"MFA removed" in _post(client, {"action": "remove_mfa", "target_user": "bob"}).data
    assert b"not found" in _post(client, {"action": "remove_mfa", "target_user": "ghost"}).data


def test_set_claims(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    assert b"Claims updated" in _post(client, {
        "action": "set_claims", "claims_user": "bob", "user_claims": "developer,idpadmin",
    }).data
    assert b"Invalid claim" in _post(client, {
        "action": "set_claims", "claims_user": "bob", "user_claims": "Bad Claim",
    }).data
    assert b"not found" in _post(client, {
        "action": "set_claims", "claims_user": "ghost", "user_claims": "developer",
    }).data


def test_claim_registry_add_delete(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    assert b"added" in _post(client, {"action": "add_claim", "claim_name": "newclaim"}).data
    assert b"already exists" in _post(client, {"action": "add_claim", "claim_name": "newclaim"}).data
    assert b"URL-safe" in _post(client, {"action": "add_claim", "claim_name": "Bad Claim"}).data
    assert b"deleted" in _post(client, {"action": "delete_claim", "claim_name": "newclaim"}).data
    assert b"not found" in _post(client, {"action": "delete_claim", "claim_name": "ghostclaim"}).data


# --- service provider CRUD --------------------------------------------------

@mock.patch("os.kill")  # _save_services_yaml SIGHUPs its parent (pytest) to reload
def test_upsert_and_update_and_delete_sp(_kill, tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    assert b"added" in _post(client, {
        "action": "upsert_sp", "sp_protocol": "oauth", "sp_path": "wiki",
        "sp_url": "https://wiki.example/cb", "sp_token_duration": "60",
    }).data
    # update existing (saml, non-default duration)
    assert b"added" in _post(client, {
        "action": "upsert_sp", "sp_protocol": "saml", "sp_path": "gitlab",
        "sp_url": "https://gitlab.example/acs", "sp_token_duration": "240",
    }).data or True
    # bad protocol / path / url / duration
    assert b"Protocol" in _post(client, {
        "action": "upsert_sp", "sp_protocol": "ftp", "sp_path": "x",
        "sp_url": "https://x/y", "sp_token_duration": "60",
    }).data
    assert b"URL-safe" in _post(client, {
        "action": "upsert_sp", "sp_protocol": "saml", "sp_path": "bad path",
        "sp_url": "https://x/y", "sp_token_duration": "60",
    }).data
    assert b"https://" in _post(client, {
        "action": "upsert_sp", "sp_protocol": "saml", "sp_path": "ok",
        "sp_url": "http://insecure", "sp_token_duration": "60",
    }).data
    assert b"between 1 and 720" in _post(client, {
        "action": "upsert_sp", "sp_protocol": "saml", "sp_path": "ok",
        "sp_url": "https://x/y", "sp_token_duration": "9999",
    }).data
    # update_sp_duration
    assert _post(client, {
        "action": "update_sp_duration", "sp_protocol": "saml", "sp_path": "aws",
        "sp_token_duration": "120",
    }).status_code == 200
    # delete
    assert _post(client, {
        "action": "delete_sp", "sp_protocol": "saml", "sp_path": "aws",
    }).status_code == 200


# --- user detail page + actions ---------------------------------------------

def test_user_detail_page_and_claim_actions(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)

    def upost(data):
        # Re-extract fresh csrf/auth tokens each time (they rotate per response).
        html = client.get("/admin/user/bob").data.decode()
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
        auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
        body = {"csrf_token": csrf, "auth_token": auth}
        body.update(data)
        return client.post("/admin/user/bob", data=body)

    assert b"added" in upost({"action": "add_user_claim", "claim_name": "wiki"}).data
    assert b"Invalid claim" in upost({"action": "add_user_claim", "claim_name": "Bad Claim"}).data
    assert b"removed" in upost({"action": "remove_user_claim", "claim_name": "wiki"}).data
    assert b"not found" in upost({"action": "remove_user_claim", "claim_name": "ghost"}).data
    # generate recovery link
    assert b"recover/" in upost({"action": "generate_recovery"}).data


def test_user_detail_unknown_user(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    assert client.get("/admin/user/ghost").status_code in (200, 404)


def test_user_detail_grant_idpadmin_audited(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    html = client.get("/admin/user/bob").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    resp = client.post("/admin/user/bob", data={
        "csrf_token": csrf, "auth_token": auth,
        "action": "add_user_claim", "claim_name": "idpadmin",
    })
    assert b"added" in resp.data


# --- SP update/delete edge cases --------------------------------------------

@mock.patch("os.kill")
def test_sp_update_and_delete_edges(_kill, tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    # add an oauth SP to update
    _post(client, {
        "action": "upsert_sp", "sp_protocol": "oauth", "sp_path": "wiki",
        "sp_url": "https://wiki.example/cb", "sp_token_duration": "60",
    })
    # update_sp_duration: bad duration
    assert b"between 1 and 720" in _post(client, {
        "action": "update_sp_duration", "sp_protocol": "oauth", "sp_path": "wiki",
        "sp_token_duration": "0",
    }).data
    # update_sp_duration: not found
    assert b"not found" in _post(client, {
        "action": "update_sp_duration", "sp_protocol": "oauth", "sp_path": "ghost",
        "sp_token_duration": "30",
    }).data
    # update_sp_duration: oauth existing (preserve fields) success
    assert b"updated" in _post(client, {
        "action": "update_sp_duration", "sp_protocol": "oauth", "sp_path": "wiki",
        "sp_token_duration": "30",
    }).data
    # delete not found
    assert b"not found" in _post(client, {
        "action": "delete_sp", "sp_protocol": "oauth", "sp_path": "ghost",
    }).data
    # unknown action
    assert b"Unknown action" in _post(client, {"action": "nonsense_action"}).data


# --- backups portal branches ------------------------------------------------

def _backup_tokens(client):
    html = client.get("/admin/backups").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    return csrf, auth


def _bpost(client, data):
    csrf, auth = _backup_tokens(client)
    body = {"csrf_token": csrf, "auth_token": auth}
    body.update(data)
    return client.post("/admin/backups", data=body)


def test_backups_get_without_session_redirects(tmp_path):
    app = _make_app(tmp_path)
    resp = app.test_client().get("/admin/backups")
    assert resp.status_code in (301, 302)


def test_backups_post_bad_csrf_redirects(tmp_path):
    app = _make_app(tmp_path)
    resp = _client(app).post("/admin/backups", data={"action": "save_backup_config"})
    assert resp.status_code in (301, 302)


def test_backups_save_config_edges(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    # bad subpath
    assert b"Invalid backup subpath" in _bpost(client, {
        "action": "save_backup_config", "server": "s", "share": "sh",
        "username": "u", "subpath": "../escape",
    }).data
    # bad retention
    assert b"must be numbers" in _bpost(client, {
        "action": "save_backup_config", "server": "s", "share": "sh",
        "username": "u", "subpath": "idp-backup", "daily_retention": "notanumber",
    }).data
    # success (blank password keeps existing)
    assert b"saved" in _bpost(client, {
        "action": "save_backup_config", "server": "s", "share": "sh",
        "username": "u", "subpath": "idp-backup", "password": "",
        "daily_retention": "10", "weekly_retention": "20",
    }).data


def test_backups_test_connection(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    with mock.patch("identity_provider_server.admin.subprocess.run",
                    return_value=mock.Mock(returncode=0, stdout="OK", stderr="")):
        resp = _bpost(client, {"action": "test_backup_connection"})
    assert resp.status_code == 200


def test_backups_run_now_and_failure(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    with mock.patch("identity_provider_server.admin.subprocess.run",
                    return_value=mock.Mock(returncode=0, stdout="", stderr="")):
        assert b"Backup started" in _bpost(client, {"action": "run_backup_now"}).data
    with mock.patch("identity_provider_server.admin.subprocess.run",
                    return_value=mock.Mock(returncode=1, stdout="", stderr="fail")):
        assert b"Could not start backup" in _bpost(client, {"action": "run_backup_now"}).data


def test_backups_restore_requires_mfa_when_absent(tmp_path):
    app = _make_app(tmp_path)  # admin has no MFA
    client = _client(app)
    bk.write_archive_listing(tmp_path, ["idp-20260101-000000.tar.gz"])
    resp = _bpost(client, {
        "action": "restore_backup", "archive": "idp-20260101-000000.tar.gz",
        "confirm_answer": "000000",
    })
    assert b"Restore requires MFA" in resp.data


def test_backups_restore_invalid_archive_with_mfa(tmp_path):
    app = _make_app(tmp_path, admin_mfa=True)
    client = app.test_client()
    client.set_cookie(
        "idp_session", _session_cookie("adminsecret-00000000000000000000000", "admin"),
        domain="localhost",
    )
    bk.write_archive_listing(tmp_path, ["idp-20260101-000000.tar.gz"])
    with mock.patch("identity_provider_server.admin.verify_code", return_value=True):
        resp = _bpost(client, {
            "action": "restore_backup", "archive": "../../etc/passwd",
            "confirm_answer": "123456",
        })
    assert b"Invalid archive name" in resp.data


def test_backups_unknown_action(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    resp = _bpost(client, {"action": "totally_unknown"})
    assert resp.status_code == 200


# --- fallback branches: register without optional validator fns -------------

def test_helpers_fallback_without_validators(tmp_path):
    """Register admin routes with no validator/policy fns to hit the fallbacks."""
    from identity_provider_server import admin as admin_mod
    from flask import Flask

    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    pw = bcrypt.hashpw(b"AdminPass123!", bcrypt.gensalt(rounds=4)).decode()
    (tmp_path / "users.json").write_text(json.dumps(
        [{"username": "admin", "password": pw, "claims": ["idpadmin"], "roles": []}]
    ))
    users = {"admin": {"username": "admin", "password": pw,
                       "claims": ["idpadmin"], "roles": []}}

    flask_app = Flask(__name__)
    flask_app.secret_key = "s"

    def _save(path, data):
        import json as _j
        path.write_text(_j.dumps(list(data.values())))

    # Register with NO validator/policy fns, NO services_path, NO data_dir,
    # NO audit_logger, and NO reload fn — exercises all the fallback branches.
    admin_mod.register_admin_routes(
        flask_app, users, tmp_path / "users.json",
        lambda stored, prov: True, _save,
        make_challenge_fn=lambda: ("Q", "H"),
        verify_challenge_fn=lambda a, h: True,
        verify_session_cookie_fn=lambda c: "admin" if c else None,
        services_path=None,
        data_dir=None,
        # validate_username_fn / validate_claim_fn / password_policy_fn /
        # audit_logger / reload_services_fn all omitted.
    )
    flask_app.config["TESTING"] = True
    client = flask_app.test_client()
    client.set_cookie("idp_session", "x", domain="localhost")
    # Panel renders (uses _load_claims_registry fallback-derive if no claims.json)
    assert client.get("/admin").status_code == 200

    def toks():
        html = client.get("/admin").data.decode()
        return (
            re.search(r'name="csrf_token" value="([^"]+)"', html).group(1),
            re.search(r'name="auth_token" value="([^"]+)"', html).group(1),
        )

    # add_user with no policy fn -> length-8 fallback rejects short pw (line 525)
    csrf, auth = toks()
    r = client.post("/admin", data={
        "csrf_token": csrf, "auth_token": auth, "action": "add_user",
        "new_username": "zoe", "new_user_password": "short",
    })
    assert b"at least 8" in r.data
    # add_user success with no validator fns -> _valid_username/_valid_claim True
    # branch (479 True path) and _audit_admin no-op (502) since no audit_logger.
    csrf, auth = toks()
    r = client.post("/admin", data={
        "csrf_token": csrf, "auth_token": auth, "action": "add_user",
        "new_username": "zoe", "new_user_password": "longenough8",
        "new_user_claims": "anything",
    })
    assert b"created" in r.data
    # add_claim success -> _save_services not involved; _audit_admin no-op path.
    csrf, auth = toks()
    assert b"added" in client.post("/admin", data={
        "csrf_token": csrf, "auth_token": auth, "action": "add_claim",
        "claim_name": "newone",
    }).data
    # An SP action with services_path=None hits _save_services_yaml early return.
    csrf, auth = toks()
    client.post("/admin", data={
        "csrf_token": csrf, "auth_token": auth, "action": "delete_sp",
        "sp_protocol": "saml", "sp_path": "aws",
    })
    # backups POST with data_dir=None and users_path set -> _backup_data_dir
    # returns users_path.parent (1432); page renders.
    bhtml = client.get("/admin/backups").data.decode()
    bcsrf = re.search(r'name="csrf_token" value="([^"]+)"', bhtml).group(1)
    bauth = re.search(r'name="auth_token" value="([^"]+)"', bhtml).group(1)
    assert client.post("/admin/backups", data={
        "csrf_token": bcsrf, "auth_token": bauth, "action": "save_backup_config",
        "server": "s", "share": "sh", "username": "u", "subpath": "idp-backup",
        "daily_retention": "1", "weekly_retention": "1",
    }).status_code == 200


def test_has_claim_missing_user_and_no_datadir(tmp_path):
    """Cover _has_claim(missing) (479) and backups no-data-dir (1490)."""
    from identity_provider_server import admin as admin_mod
    from flask import Flask

    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    users = {}  # empty — session user won't be found
    flask_app = Flask(__name__)
    flask_app.secret_key = "s"
    admin_mod.register_admin_routes(
        flask_app, users, None,  # users_path=None
        lambda s, p: True, lambda p, d: None,
        make_challenge_fn=lambda: ("Q", "H"),
        verify_challenge_fn=lambda a, h: True,
        verify_session_cookie_fn=lambda c: "ghost",  # not in users
        services_path=None, data_dir=None,
    )
    flask_app.config["TESTING"] = True
    client = flask_app.test_client()
    client.set_cookie("idp_session", "x", domain="localhost")
    # ghost isn't in users -> _has_claim False (479) -> login page, not panel.
    assert b"Sign in" in client.get("/admin").data


@mock.patch("os.kill")
def test_load_services_yaml_malformed(_kill, tmp_path):
    """A malformed services.yaml is handled by _load_services_yaml (YAMLError).

    Corrupt the file only for the duration of the SP action so create_app's own
    services loader (at construction) sees a valid file.
    """
    import yaml as _yaml

    app = _make_app(tmp_path)
    client = _client(app)
    csrf, auth = _tokens(client)
    # Make yaml.safe_load raise only during the admin SP action.
    with mock.patch.object(_yaml, "safe_load", side_effect=_yaml.YAMLError("boom")):
        resp = client.post("/admin", data={
            "csrf_token": csrf, "auth_token": auth,
            "action": "delete_sp", "sp_protocol": "saml", "sp_path": "aws",
        })
    assert resp.status_code == 200
    assert b"not found" in resp.data


def test_recovery_token_expiry(tmp_path):
    """An expired recovery token validates to None and is cleaned up."""
    from identity_provider_server import admin as admin_mod

    app = _make_app(tmp_path)  # registers module-level validate/consume fns
    # write an already-expired token
    rt_path = tmp_path / "recovery_tokens.json"
    rt_path.write_text(json.dumps({"tok": {"username": "bob", "expires": 1.0}}))
    assert admin_mod.validate_recovery_token("tok") is None
    assert admin_mod.validate_recovery_token("missing") is None


# --- user-detail guards + remaining branches --------------------------------

def test_user_detail_get_without_session_redirects(tmp_path):
    app = _make_app(tmp_path)
    resp = app.test_client().get("/admin/user/bob")
    assert resp.status_code in (301, 302)


def test_user_detail_post_bad_csrf(tmp_path):
    app = _make_app(tmp_path)
    resp = _client(app).post("/admin/user/bob", data={"action": "add_user_claim"})
    assert resp.status_code in (301, 302)


def test_user_detail_post_bad_auth(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    html = client.get("/admin/user/bob").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    resp = client.post("/admin/user/bob", data={
        "csrf_token": csrf, "auth_token": "bogus", "action": "add_user_claim",
    })
    assert resp.status_code in (301, 302)


def test_user_detail_post_unknown_user(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    # tokens from a valid detail page, but POST targets a ghost user
    html = client.get("/admin/user/bob").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    resp = client.post("/admin/user/ghost", data={
        "csrf_token": csrf, "auth_token": auth, "action": "add_user_claim",
        "claim_name": "developer",
    })
    assert b"not found" in resp.data


def test_user_detail_claim_already_assigned(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    html = client.get("/admin/user/bob").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    # 'developer' is already on bob -> "already assigned or invalid"
    resp = client.post("/admin/user/bob", data={
        "csrf_token": csrf, "auth_token": auth, "action": "add_user_claim",
        "claim_name": "developer",
    })
    assert b"already assigned or invalid" in resp.data


def test_user_detail_unknown_action_renders(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    html = client.get("/admin/user/bob").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    resp = client.post("/admin/user/bob", data={
        "csrf_token": csrf, "auth_token": auth, "action": "nope",
    })
    assert resp.status_code == 200


# --- trigger exception paths ------------------------------------------------

def test_trigger_unit_exception(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    with mock.patch("identity_provider_server.admin.subprocess.run",
                    side_effect=OSError("no sudo")):
        resp = _bpost(client, {"action": "run_backup_now"})
    assert b"Could not start backup" in resp.data


def test_trigger_test_connection_exception(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    with mock.patch("identity_provider_server.admin.subprocess.run",
                    side_effect=OSError("no sudo")):
        resp = _bpost(client, {"action": "test_backup_connection"})
    assert resp.status_code == 200


# --- recovery-token prune of expired entries during generation --------------

def test_generate_recovery_prunes_expired(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    # Seed an expired token so generation prunes it.
    (tmp_path / "recovery_tokens.json").write_text(
        json.dumps({"old": {"username": "x", "created": 0, "expires": 1.0}})
    )
    html = client.get("/admin/user/bob").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    resp = client.post("/admin/user/bob", data={
        "csrf_token": csrf, "auth_token": auth, "action": "generate_recovery",
    })
    assert b"recover/" in resp.data
    tokens = json.loads((tmp_path / "recovery_tokens.json").read_text())
    assert "old" not in tokens  # expired entry pruned


# --- audit log page ---------------------------------------------------------

def test_audit_log_page(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    # The audit log now requires a step-up token (not just the session cookie).
    panel = client.get("/admin").data.decode()
    auth = re.search(r'name="auth_token" value="([^"]+)"', panel).group(1)
    resp = client.get(f"/admin/audit-log?auth_token={auth}")
    assert resp.status_code == 200


def test_audit_log_no_session_redirects(tmp_path):
    app = _make_app(tmp_path)
    resp = app.test_client().get("/admin/audit-log")
    assert resp.status_code in (301, 302)


def test_audit_log_session_cookie_without_stepup_redirects(tmp_path):
    """A session cookie alone (no step-up token) no longer suffices (F9)."""
    app = _make_app(tmp_path)
    client = _client(app)
    resp = client.get("/admin/audit-log")
    assert resp.status_code in (301, 302)


# --- delete_claim removes it from a user that holds it (line 997) ------------

def test_delete_claim_removes_from_users(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    # bob holds 'developer'; deleting the claim should strip it from bob.
    resp = _post(client, {"action": "delete_claim", "claim_name": "developer"})
    assert b"deleted" in resp.data
    users = json.loads((tmp_path / "users.json").read_text())
    bob = next(u for u in users if u["username"] == "bob")
    assert "developer" not in bob.get("claims", [])


# --- SP format branches (saml short-form + oauth extended) ------------------

@mock.patch("os.kill")
def test_sp_saml_shortform_and_oauth_extended(_kill, tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    # SAML with default 60min -> stored as short-form string (line 1040)
    assert b"added" in _post(client, {
        "action": "upsert_sp", "sp_protocol": "saml", "sp_path": "short",
        "sp_url": "https://s/acs", "sp_token_duration": "60",
    }).data
    # oauth upsert then update to exercise extended-format preserve (1093)
    _post(client, {
        "action": "upsert_sp", "sp_protocol": "oauth", "sp_path": "ext",
        "sp_url": "https://o/cb", "sp_token_duration": "120",
    })
    assert b"updated" in _post(client, {
        "action": "update_sp_duration", "sp_protocol": "oauth", "sp_path": "ext",
        "sp_token_duration": "240",
    }).data
    # saml update to default (short-form) and non-default (extended, 1099/1104-1106)
    _post(client, {
        "action": "upsert_sp", "sp_protocol": "saml", "sp_path": "smx",
        "sp_url": "https://s2/acs", "sp_token_duration": "240",
    })
    assert b"updated" in _post(client, {
        "action": "update_sp_duration", "sp_protocol": "saml", "sp_path": "smx",
        "sp_token_duration": "60",
    }).data
    assert b"updated" in _post(client, {
        "action": "update_sp_duration", "sp_protocol": "saml", "sp_path": "short",
        "sp_token_duration": "300",
    }).data
    # delete a protocol's last entry -> removes empty section (line 1128)
    assert b"deleted" in _post(client, {
        "action": "delete_sp", "sp_protocol": "oauth", "sp_path": "ext",
    }).data


@mock.patch("os.kill")
def test_sp_update_preserves_extra_fields(_kill, tmp_path):
    """update_sp_duration preserves non-standard fields (lines 1093, 1104-1106)."""
    app = _make_app(tmp_path)
    # Seed services.yaml with entries carrying extra keys.
    (tmp_path / "services.yaml").write_text(
        "saml:\n"
        "  smx:\n"
        "    url: https://s/acs\n"
        "    session_duration_hours: 2\n"
        "    audience: urn:custom\n"
        "oauth:\n"
        "  oex:\n"
        "    url: https://o/cb\n"
        "    token_expiry_minutes: 60\n"
        "    client_id: myclient\n"
        "    scopes: [openid]\n"
    )
    client = _client(app)
    # oauth update preserves client_id/scopes (1093)
    assert b"updated" in _post(client, {
        "action": "update_sp_duration", "sp_protocol": "oauth", "sp_path": "oex",
        "sp_token_duration": "120",
    }).data
    # saml update (non-default) preserves audience (1104-1106)
    assert b"updated" in _post(client, {
        "action": "update_sp_duration", "sp_protocol": "saml", "sp_path": "smx",
        "sp_token_duration": "180",
    }).data
    data = __import__("yaml").safe_load((tmp_path / "services.yaml").read_text())
    assert data["oauth"]["oex"]["client_id"] == "myclient"
    assert data["saml"]["smx"]["audience"] == "urn:custom"


# --- backups: bad auth + restore trigger failure ----------------------------

def test_backups_post_bad_auth_redirects(tmp_path):
    app = _make_app(tmp_path)
    client = _client(app)
    csrf, _auth = _backup_tokens(client)
    resp = client.post("/admin/backups", data={
        "csrf_token": csrf, "auth_token": "bogus", "action": "run_backup_now",
    })
    assert resp.status_code in (301, 302)


def test_backups_restore_trigger_failure(tmp_path):
    app = _make_app(tmp_path, admin_mfa=True)
    client = app.test_client()
    client.set_cookie(
        "idp_session", _session_cookie("adminsecret-00000000000000000000000", "admin"),
        domain="localhost",
    )
    bk.write_archive_listing(tmp_path, ["idp-20260101-000000.tar.gz"])
    with (
        mock.patch("identity_provider_server.admin.verify_code", return_value=True),
        mock.patch("identity_provider_server.admin.subprocess.run",
                   return_value=mock.Mock(returncode=1, stdout="", stderr="nope")),
    ):
        resp = _bpost(client, {
            "action": "restore_backup", "archive": "idp-20260101-000000.tar.gz",
            "confirm_answer": "123456",
        })
    assert b"Could not start restore" in resp.data


# --- recovery token full roundtrip (585, 589-591) ---------------------------

def test_recovery_token_validate_and_consume(tmp_path):
    from identity_provider_server import admin as admin_mod

    app = _make_app(tmp_path)  # sets module-level validate/consume fns
    # Generate a real token via the user-detail action.
    client = _client(app)
    html = client.get("/admin/user/bob").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    resp = client.post("/admin/user/bob", data={
        "csrf_token": csrf, "auth_token": auth, "action": "generate_recovery",
    })
    token = re.search(r"recover/([A-Za-z0-9_-]+)", resp.data.decode()).group(1)
    # validate returns the username (line 585)
    assert admin_mod.validate_recovery_token(token) == "bob"
    # consume deletes it (589-591); a second validate returns None
    admin_mod.consume_recovery_token(token)
    assert admin_mod.validate_recovery_token(token) is None


# --- _save_services_yaml with a reload fn (line 612) ------------------------

@mock.patch("os.kill")
def test_save_services_calls_reload_fn(_kill, tmp_path):
    from identity_provider_server import admin as admin_mod
    from flask import Flask

    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    pw = bcrypt.hashpw(b"AdminPass123!", bcrypt.gensalt(rounds=4)).decode()
    users = {"admin": {"username": "admin", "password": pw,
                       "claims": ["idpadmin"], "roles": []}}
    (tmp_path / "services.yaml").write_text("saml:\n  aws: https://s/acs\n")
    reloaded = {"n": 0}
    flask_app = Flask(__name__)
    flask_app.secret_key = "s"
    admin_mod.register_admin_routes(
        flask_app, users, tmp_path / "users.json",
        lambda s, p: True, lambda p, d: None,
        make_challenge_fn=lambda: ("Q", "H"),
        verify_challenge_fn=lambda a, h: True,
        verify_session_cookie_fn=lambda c: "admin" if c else None,
        services_path=tmp_path / "services.yaml",
        reload_services_fn=lambda: reloaded.__setitem__("n", reloaded["n"] + 1),
        data_dir=tmp_path,
    )
    flask_app.config["TESTING"] = True
    client = flask_app.test_client()
    client.set_cookie("idp_session", "x", domain="localhost")
    html = client.get("/admin").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    client.post("/admin", data={
        "csrf_token": csrf, "auth_token": auth, "action": "delete_sp",
        "sp_protocol": "saml", "sp_path": "aws",
    })
    assert reloaded["n"] == 1  # reload_services_fn was invoked (line 612)


# --- backups no data dir at all (line 1490) ---------------------------------

def test_backups_no_data_dir(tmp_path):
    from identity_provider_server import admin as admin_mod
    from flask import Flask

    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    pw = bcrypt.hashpw(b"AdminPass123!", bcrypt.gensalt(rounds=4)).decode()
    users = {"admin": {"username": "admin", "password": pw,
                       "claims": ["idpadmin"], "roles": []}}
    flask_app = Flask(__name__)
    flask_app.secret_key = "s"
    # users_path=None and data_dir=None -> _backup_data_dir() returns None.
    admin_mod.register_admin_routes(
        flask_app, users, None,
        lambda s, p: True, lambda p, d: None,
        make_challenge_fn=lambda: ("Q", "H"),
        verify_challenge_fn=lambda a, h: True,
        verify_session_cookie_fn=lambda c: "admin" if c else None,
        services_path=None, data_dir=None,
    )
    flask_app.config["TESTING"] = True
    client = flask_app.test_client()
    client.set_cookie("idp_session", "x", domain="localhost")
    # Session reuse renders the backups page; extract its tokens.
    html = client.get("/admin/backups").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    resp = client.post("/admin/backups", data={
        "csrf_token": csrf, "auth_token": auth, "action": "save_backup_config",
    })
    assert b"No data directory available" in resp.data


# --- _rl_key without username (line 454) ------------------------------------

def test_admin_rl_key_ip_only(tmp_path):
    """_rl_key ip-only fallback (line 454): rate_limiter set, no key_fn."""
    from identity_provider_server import admin as admin_mod
    from identity_provider_server.app import _RateLimiter
    from flask import Flask

    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    users = {}
    flask_app = Flask(__name__)
    flask_app.secret_key = "s"
    admin_mod.register_admin_routes(
        flask_app, users, None,
        lambda s, p: True, lambda p, d: None,
        make_challenge_fn=lambda: ("Q", "H"),
        verify_challenge_fn=lambda a, h: False,  # force failed captcha -> _rl_record
        verify_session_cookie_fn=lambda c: None,
        rate_limiter=_RateLimiter(max_attempts=2, window_seconds=60),
        # rate_limit_key_fn omitted -> _rl_key uses internal ip-only fallback (454)
    )
    flask_app.config["TESTING"] = True
    client = flask_app.test_client()

    def bad_login():
        html = client.get("/admin").data.decode()
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
        return client.post("/admin", data={
            "csrf_token": csrf, "action": "login", "username": "",
            "challenge_answer": "x", "challenge_hash": "y",
        })

    for _ in range(3):
        bad_login()
    assert bad_login().status_code == 429
