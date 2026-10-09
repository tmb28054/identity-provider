"""Security remediation tests — idp-2026-10-06 phase 3.

Finding 3 (Medium) — logout performed no server-side session revocation. The
logout handlers only deleted the cookies, leaving the surrendered stateless
``idp_session`` value a valid credential that could be replayed against the
session-reuse GET path to mint a fresh assertion. The fix bumps the user's
``session_epoch`` on logout, writes an audit record, and gates logout behind a
``csrf_token`` double-submit so a third party cannot force it.

Finding 7 (High) — the ADFS/LDAP bind ran with ldap3's ``CERT_NONE`` default.
A ``None`` TLS object made ldap3 substitute a non-validating ``Tls()``, so no
configuration enabled server-certificate validation. The fix builds a
validating ``Tls`` (``CERT_REQUIRED``) on the secure branch for both binds,
adds an optional ``ca_certs_file`` for private CAs, keeps ``skip_ssl_verify``
as the only route to ``CERT_NONE`` (logged at WARNING), and corrects the docs.
"""

from __future__ import annotations

import json
import re
import shutil
import ssl
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import bcrypt
import pytest

from identity_provider_server.adfs import authenticate_adfs, load_adfs_config
from identity_provider_server.app import create_app
from identity_provider_server.tokens import issue_session_token

DATA_SRC = Path(__file__).parent.parent / "data"
SECRET = "a" * 48
PW = "Str0ng-Passw0rd!"


def _hash(pw: str = PW) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=4)).decode()


def _app(tmp_path: Path):
    """Build a single-SP app whose /aws SAML route is session-reuse capable."""
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    users = [
        {"username": "bob", "password": _hash(), "roles": [
            {"account_id": "111111111111", "role": "Admin"},
        ], "claims": [], "session_epoch": 0},
    ]
    (tmp_path / "users.json").write_text(json.dumps(users))
    (tmp_path / "services.yaml").write_text(
        "saml:\n  aws: https://signin.aws.amazon.com/saml\n"
    )
    app = create_app(
        str(tmp_path), secret_key=SECRET,
        secure_cookies=False, trust_proxy=False,
    )
    app.config["TESTING"] = True
    return app


def _cookie(epoch: int = 0) -> str:
    return issue_session_token(
        SECRET, "bob", auth_time=int(time.time()), epoch=epoch,
    )


# --- Finding 3: logout revokes the session server-side ----------------------

def test_old_cookie_mints_assertion_before_logout(tmp_path):
    """Baseline: a valid session cookie mints a SAML assertion on GET /aws."""
    app = _app(tmp_path)
    client = app.test_client()
    client.set_cookie("idp_session", _cookie())
    resp = client.get("/aws")
    assert b"SAMLResponse" in resp.data


def test_logout_revokes_replayed_cookie(tmp_path):
    """After logout, replaying the OLD cookie no longer mints an assertion.

    The epoch bump makes the surrendered cookie fail verification, so the
    session-reuse short-circuit falls through to the login form.
    """
    app = _app(tmp_path)
    old_cookie = _cookie()

    # Log out carrying the double-submit token.
    logout_client = app.test_client()
    logout_client.set_cookie("idp_session", old_cookie)
    logout_client.set_cookie("csrf_token", "tok")
    assert logout_client.get("/aws/logout?csrf_token=tok").status_code == 200

    # The epoch was advanced and persisted.
    stored = json.loads((tmp_path / "users.json").read_text())
    assert stored[0]["session_epoch"] == 1

    # Replaying the old cookie now yields the login form, not an assertion.
    replay = app.test_client()
    replay.set_cookie("idp_session", old_cookie)
    resp = replay.get("/aws")
    assert b"SAMLResponse" not in resp.data


def test_logout_writes_audit_record(tmp_path):
    """Logout appends a session/logout success entry to the audit log."""
    app = _app(tmp_path)
    client = app.test_client()
    client.set_cookie("idp_session", _cookie())
    client.set_cookie("csrf_token", "tok")
    client.get("/aws/logout?csrf_token=tok")

    lines = (tmp_path / "audit.log").read_text().splitlines()
    entries = [json.loads(line) for line in lines]
    logout_entries = [
        e for e in entries
        if e.get("protocol") == "session" and e.get("reason") == "logout"
    ]
    assert logout_entries
    assert logout_entries[-1]["result"] == "success"
    assert logout_entries[-1]["username"] == "bob"


def test_logout_without_csrf_token_is_rejected(tmp_path):
    """A forged cross-site logout with no CSRF token is refused (403)."""
    app = _app(tmp_path)
    client = app.test_client()
    client.set_cookie("idp_session", _cookie())
    resp = client.get("/aws/logout")
    assert resp.status_code == 403
    # The session was NOT revoked, so the epoch is untouched.
    stored = json.loads((tmp_path / "users.json").read_text())
    assert stored[0]["session_epoch"] == 0


def test_logout_with_wrong_csrf_token_is_rejected(tmp_path):
    """A logout whose token does not match the cookie is refused (403)."""
    app = _app(tmp_path)
    client = app.test_client()
    client.set_cookie("idp_session", _cookie())
    client.set_cookie("csrf_token", "right")
    resp = client.get("/aws/logout?csrf_token=wrong")
    assert resp.status_code == 403


def test_logout_without_session_still_clears_and_audits(tmp_path):
    """Logout with no (valid) session cookie still succeeds and audits.

    No user resolves, so no epoch bump happens, but the cookies are cleared
    and the event is recorded with an empty username.
    """
    app = _app(tmp_path)
    client = app.test_client()
    client.set_cookie("csrf_token", "tok")
    resp = client.get("/aws/logout?csrf_token=tok")
    assert resp.status_code == 200
    entries = [
        json.loads(line)
        for line in (tmp_path / "audit.log").read_text().splitlines()
    ]
    assert any(
        e.get("reason") == "logout" and e.get("username") == ""
        for e in entries
    )


def test_logout_fallback_route_revokes(tmp_path):
    """The /aws fallback (no services.yaml) revokes the session too."""
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    (tmp_path / "users.json").write_text(json.dumps([
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "session_epoch": 0},
    ]))
    app = create_app(
        str(tmp_path), secret_key=SECRET,
        secure_cookies=False, trust_proxy=False,
    )
    app.config["TESTING"] = True
    client = app.test_client()
    client.set_cookie("idp_session", _cookie())
    client.set_cookie("csrf_token", "tok")
    assert client.get("/aws/logout?csrf_token=tok").status_code == 200
    stored = json.loads((tmp_path / "users.json").read_text())
    assert stored[0]["session_epoch"] == 1


# --- Finding 7: validating TLS on the LDAP bind -----------------------------

@pytest.fixture
def adfs_cfg():
    return {
        "host": "ldaps://dc.corp.com",
        "username": "CN=svc,DC=corp",
        "base_dn": "DC=corp,DC=com",
        "password": "svc-pass",
    }


def _ldap_mocks():
    entry = MagicMock()
    entry.distinguishedName = "CN=alice,OU=Users,DC=corp,DC=com"
    entry.memberOf = ["CN=AWS-Admins,OU=Groups,DC=corp,DC=com"]
    conn = MagicMock()
    conn.entries = [entry]
    user_conn = MagicMock()
    return conn, user_conn


def test_secure_default_builds_cert_required_tls(adfs_cfg):
    """skip_ssl_verify False + ldaps:// builds a CERT_REQUIRED Tls object."""
    conn, user_conn = _ldap_mocks()
    with patch("ldap3.Server") as mock_server, \
            patch("ldap3.Connection") as mock_conn, \
            patch("ldap3.Tls") as mock_tls:
        mock_conn.side_effect = [conn, user_conn]
        authenticate_adfs("alice", "pw", adfs_cfg)

    mock_tls.assert_called_once()
    assert mock_tls.call_args.kwargs["validate"] == ssl.CERT_REQUIRED
    # The validating server (hence tls) is shared by BOTH binds: the service
    # bind and the user-password bind reuse the one Server instance.
    assert mock_server.call_count == 1
    assert mock_conn.call_count == 2
    server_instance = mock_server.return_value
    for call in mock_conn.call_args_list:
        assert call.args[0] is server_instance


def test_ca_certs_file_flows_through(adfs_cfg):
    """A configured ca_certs_file is passed to the validating Tls."""
    adfs_cfg["ca_certs_file"] = "/etc/idp/internal-ca.pem"
    conn, user_conn = _ldap_mocks()
    with patch("ldap3.Server"), \
            patch("ldap3.Connection") as mock_conn, \
            patch("ldap3.Tls") as mock_tls:
        mock_conn.side_effect = [conn, user_conn]
        authenticate_adfs("alice", "pw", adfs_cfg)

    assert mock_tls.call_args.kwargs["ca_certs_file"] == "/etc/idp/internal-ca.pem"
    assert mock_tls.call_args.kwargs["validate"] == ssl.CERT_REQUIRED


def test_skip_ssl_verify_yields_cert_none_with_warning(adfs_cfg, caplog):
    """skip_ssl_verify True still builds CERT_NONE and logs a WARNING."""
    conn, user_conn = _ldap_mocks()
    with patch("ldap3.Server"), \
            patch("ldap3.Connection") as mock_conn, \
            patch("ldap3.Tls") as mock_tls:
        mock_conn.side_effect = [conn, user_conn]
        with caplog.at_level("WARNING"):
            authenticate_adfs("alice", "pw", adfs_cfg, skip_ssl_verify=True)

    assert mock_tls.call_args.kwargs["validate"] == ssl.CERT_NONE
    assert any(
        "verification DISABLED" in rec.message for rec in caplog.records
    )


def test_load_adfs_config_accepts_ca_certs_file(tmp_path):
    """load_adfs_config carries a string ca_certs_file through."""
    import yaml

    cfg = {
        "host": "ldaps://dc.corp.com",
        "username": "CN=svc,DC=corp",
        "base_dn": "DC=corp,DC=com",
        "password": "secret",
        "ca_certs_file": "/etc/idp/internal-ca.pem",
    }
    cfg_file = tmp_path / "adfs.yaml"
    cfg_file.write_text(yaml.dump(cfg))
    result = load_adfs_config(str(cfg_file))
    assert result["ca_certs_file"] == "/etc/idp/internal-ca.pem"


def test_load_adfs_config_rejects_non_string_ca_certs_file(tmp_path):
    """A non-string ca_certs_file is rejected at load time."""
    import yaml

    cfg = {
        "host": "ldaps://dc.corp.com",
        "username": "CN=svc,DC=corp",
        "base_dn": "DC=corp,DC=com",
        "password": "secret",
        "ca_certs_file": ["not", "a", "string"],
    }
    cfg_file = tmp_path / "adfs.yaml"
    cfg_file.write_text(yaml.dump(cfg))
    with pytest.raises(SystemExit):
        load_adfs_config(str(cfg_file))


# --- smoke ------------------------------------------------------------------

@pytest.mark.smoke
def test_phase3_smoke(tmp_path):
    """Happy path for both fixes: logout revokes, and a secure ADFS bind
    builds a CERT_REQUIRED Tls."""
    # F3: logout bumps the epoch and clears the cookie.
    app = _app(tmp_path)
    client = app.test_client()
    client.set_cookie("idp_session", _cookie())
    client.set_cookie("csrf_token", "tok")
    assert client.get("/aws/logout?csrf_token=tok").status_code == 200
    assert json.loads((tmp_path / "users.json").read_text())[0][
        "session_epoch"
    ] == 1

    # F7: the default ADFS bind validates the server certificate.
    cfg = {
        "host": "ldaps://dc.corp.com", "username": "CN=svc,DC=corp",
        "base_dn": "DC=corp,DC=com", "password": "svc-pass",
    }
    conn, user_conn = _ldap_mocks()
    with patch("ldap3.Server"), \
            patch("ldap3.Connection") as mock_conn, \
            patch("ldap3.Tls") as mock_tls:
        mock_conn.side_effect = [conn, user_conn]
        authenticate_adfs("alice", "pw", cfg)
    assert mock_tls.call_args.kwargs["validate"] == ssl.CERT_REQUIRED
