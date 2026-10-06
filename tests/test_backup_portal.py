"""Portal tests for the /admin/backups page.

Drives the Backups page through the Flask test client. The privileged
unit trigger (sudo systemctl / sudo backup_cli) is mocked so no real
system calls happen.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from unittest import mock

import bcrypt

from identity_provider_server import backup as bk
from identity_provider_server.app import create_app


def _make_app(tmp: Path):
    """Build an app with an admin user (idpadmin claim) and a session helper."""
    src = Path(__file__).parent.parent / "data"
    shutil.copy(src / "idp.crt", tmp / "idp.crt")
    shutil.copy(src / "idp.key", tmp / "idp.key")
    pw = bcrypt.hashpw(b"adminpass1", bcrypt.gensalt()).decode()
    # Restore now requires a fresh TOTP code, so the admin must have MFA enrolled.
    (tmp / "users.json").write_text(json.dumps([
        {
            "username": "admin",
            "password": pw,
            "roles": [],
            "claims": ["idpadmin"],
            "totp_secret": "JBSWY3DPEHPK3PXP",
        }
    ]))
    app = create_app(str(tmp), secret_key="testsecret-000000000000000000000000")
    app.config["TESTING"] = True
    return app


def _admin_session_cookie(app) -> str:
    """Mint a valid idp_session cookie for the admin user (new token scheme)."""
    import time as _time

    from identity_provider_server.tokens import issue_session_token

    return issue_session_token(
        app.secret_key, "admin", auth_time=int(_time.time()), epoch=0,
    )


def _client_with_session(app):
    client = app.test_client()
    client.set_cookie("idp_session", _admin_session_cookie(app), domain="localhost")
    return client


def test_backups_page_requires_session(tmp_path):
    """Without a valid session, /admin/backups redirects to /admin."""
    app = _make_app(tmp_path)
    client = app.test_client()
    resp = client.get("/admin/backups")
    assert resp.status_code in (301, 302)
    assert resp.headers["Location"].endswith("/admin")


def test_backups_page_loads_with_session(tmp_path):
    app = _make_app(tmp_path)
    client = _client_with_session(app)
    resp = client.get("/admin/backups")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "SMB Destination" in body
    assert "Restore" in body


def _get_csrf(client) -> tuple[str, str]:
    """GET the backups page and extract the csrf token (form + cookie)."""
    import re

    resp = client.get("/admin/backups")
    html = resp.data.decode()
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    return token, auth


def test_save_backup_config(tmp_path):
    app = _make_app(tmp_path)
    client = _client_with_session(app)
    token, auth = _get_csrf(client)

    resp = client.post("/admin/backups", data={
        "csrf_token": token,
        "auth_token": auth,
        "action": "save_backup_config",
        "server": "10.0.0.9",
        "share": "idp-backups",
        "username": "svc",
        "password": "hunter2",
        "subpath": "idp-backup",
        "daily_retention": "30",
        "weekly_retention": "52",
        "enabled": "1",
    })
    assert resp.status_code == 200
    assert "Backup settings saved" in resp.data.decode()

    cfg = bk.load_config(tmp_path)
    assert cfg.server == "10.0.0.9"
    assert cfg.username == "svc"
    assert cfg.password == "hunter2"
    assert cfg.enabled is True


def test_save_config_keeps_existing_password_when_blank(tmp_path):
    app = _make_app(tmp_path)
    # Pre-seed a config with a password.
    bk.save_config(tmp_path, bk.BackupConfig(
        server="s", share="sh", username="u", password="original",
    ))
    client = _client_with_session(app)
    token, auth = _get_csrf(client)
    client.post("/admin/backups", data={
        "csrf_token": token, "auth_token": auth,
        "action": "save_backup_config",
        "server": "s", "share": "sh", "username": "u",
        "password": "",  # blank -> keep existing
        "subpath": "idp-backup",
        "daily_retention": "30", "weekly_retention": "52",
    })
    assert bk.load_config(tmp_path).password == "original"


def test_run_backup_now_triggers_unit(tmp_path):
    app = _make_app(tmp_path)
    client = _client_with_session(app)
    token, auth = _get_csrf(client)

    fake = mock.Mock(returncode=0, stdout="", stderr="")
    with mock.patch("identity_provider_server.admin.subprocess.run", return_value=fake) as run:
        resp = client.post("/admin/backups", data={
            "csrf_token": token, "auth_token": auth,
            "action": "run_backup_now",
        })
    assert resp.status_code == 200
    assert "Backup started" in resp.data.decode()
    # The unit we started must be idp-backup.service via sudo systemctl.
    args = run.call_args[0][0]
    assert "systemctl" in " ".join(args)
    assert "idp-backup.service" in args


def test_run_backup_now_trigger_failure(tmp_path):
    app = _make_app(tmp_path)
    client = _client_with_session(app)
    token, auth = _get_csrf(client)

    fake = mock.Mock(returncode=1, stdout="", stderr="permission denied")
    with mock.patch("identity_provider_server.admin.subprocess.run", return_value=fake):
        resp = client.post("/admin/backups", data={
            "csrf_token": token, "auth_token": auth,
            "action": "run_backup_now",
        })
    assert "Could not start backup" in resp.data.decode()


def test_restore_requires_confirmation(tmp_path):
    """Restore with a wrong MFA code is aborted (no unit started)."""
    app = _make_app(tmp_path)
    # Make an archive available in the listing.
    bk.write_archive_listing(tmp_path, ["idp-20260101-000000.tar.gz"])
    client = _client_with_session(app)
    token, auth = _get_csrf(client)

    with (
        mock.patch("identity_provider_server.admin.subprocess.run") as run,
        mock.patch("identity_provider_server.admin.verify_code", return_value=False),
    ):
        resp = client.post("/admin/backups", data={
            "csrf_token": token, "auth_token": auth,
            "action": "restore_backup",
            "archive": "idp-20260101-000000.tar.gz",
            "confirm_answer": "000000",
        })
    assert "Confirmation failed" in resp.data.decode()
    run.assert_not_called()


def test_restore_with_valid_mfa_triggers_unit(tmp_path):
    app = _make_app(tmp_path)
    bk.write_archive_listing(tmp_path, ["idp-20260101-000000.tar.gz"])
    client = _client_with_session(app)
    token, auth = _get_csrf(client)

    # A valid, fresh TOTP code from the admin confirms the destructive restore.
    fake = mock.Mock(returncode=0, stdout="", stderr="")
    with (
        mock.patch("identity_provider_server.admin.subprocess.run", return_value=fake) as run,
        mock.patch("identity_provider_server.admin.verify_code", return_value=True),
    ):
        resp = client.post("/admin/backups", data={
            "csrf_token": token, "auth_token": auth,
            "action": "restore_backup",
            "archive": "idp-20260101-000000.tar.gz",
            "confirm_answer": "123456",
        })
    assert resp.status_code == 200
    assert "Restore" in resp.data.decode()
    started = " ".join(run.call_args[0][0])
    assert "idp-restore@idp-20260101-000000.tar.gz.service" in started


def test_restore_rejects_bad_archive_name(tmp_path):
    app = _make_app(tmp_path)
    bk.write_archive_listing(tmp_path, ["idp-20260101-000000.tar.gz"])
    client = _client_with_session(app)
    token, auth = _get_csrf(client)

    with (
        mock.patch("identity_provider_server.admin.subprocess.run") as run,
        mock.patch("identity_provider_server.admin.verify_code", return_value=True),
    ):
        resp = client.post("/admin/backups", data={
            "csrf_token": token, "auth_token": auth,
            "action": "restore_backup",
            "archive": "../../etc/passwd",
            "confirm_answer": "123456",
        })
    assert "Invalid archive name" in resp.data.decode()
    run.assert_not_called()


def test_failure_banner_shows_on_main_panel(tmp_path):
    app = _make_app(tmp_path)
    bk.save_status(tmp_path, bk.BackupStatus(
        result="failure", message="mount failed", consecutive_failures=2,
    ))
    client = _client_with_session(app)
    resp = client.get("/admin")
    assert resp.status_code == 200
    assert "last backup failed" in resp.data.decode().lower()
