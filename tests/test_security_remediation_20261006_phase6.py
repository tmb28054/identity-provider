"""Phase 2 security-remediation tests (idp-2026-10-06).

Covers the two Medium findings remediated in Phase 2:

* **Finding 3 (Medium)** — the gunicorn multi-worker startup guard only read
  ``WEB_CONCURRENCY``/``GUNICORN_WORKERS`` and only warned, so a documented
  ``-w 2`` invocation silently forked the per-process rate limiter and
  nonce/challenge stores. The app now detects the worker count from
  ``-w/--workers``, the env hints, and a ``-c`` gunicorn config ``workers = N``
  literal (parsed with ``ast``, never executed), and refuses to start with more
  than one worker unless ``IDP_ALLOW_MULTIWORKER`` is truthy. The ``run-idp``
  entry point enforces this authoritatively on the parsed ``--workers`` value;
  a gunicorn-scoped backstop in ``create_app`` covers direct ``gunicorn``
  invocations while leaving pytest/dev-server/embedding callers unaffected.

* **Finding 4 (Medium)** — ``force_password_change`` was never written and no
  password age was tracked. Admin ``add_user``/``reset_password`` now set the
  flag, every password write stamps ``password_changed_at``, and an optional
  ``IDP_PASSWORD_MAX_AGE_DAYS`` knob (default disabled) forces a rotation once a
  password is older than the window. Passwordless accounts and legacy records
  with no timestamp are exempt; a non-numeric knob is a fatal startup error.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
import time
from pathlib import Path
from unittest.mock import patch

import bcrypt
import pyotp
import pytest

from identity_provider_server import app as app_module
from identity_provider_server import run_gunicorn
from identity_provider_server.app import (
    _assert_single_worker,
    _detected_worker_count,
    _env_truthy,
    create_app,
)
from identity_provider_server.config import load_config
from identity_provider_server.tokens import PURPOSE_USER, issue_token

DATA_SRC = Path(__file__).parent.parent / "data"
SECRET = "phase6secret-00000000000000000000000"
PW = "AdminPass123!"
NEW_PW = "N3w-Passw0rd!!"
ADMIN_TOTP = pyotp.random_base32()


def _hash(pw: str = PW) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=4)).decode()


def _csrf(html: bytes) -> str:
    return re.search(rb'name="csrf_token" value="([^"]+)"', html).group(1).decode()


def _auth(html: bytes) -> str:
    return re.search(rb'name="auth_token" value="([^"]+)"', html).group(1).decode()


def _write_data(tmp_path: Path, users: list[dict]) -> Path:
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    (tmp_path / "users.json").write_text(json.dumps(users))
    (tmp_path / "claims.json").write_text(json.dumps(["idpadmin", "developer"]))
    (tmp_path / "services.yaml").write_text(
        "saml:\n  aws: https://signin.aws.amazon.com/saml\n"
    )
    return tmp_path


def _app(tmp_path: Path, users: list[dict], **kwargs):
    _write_data(tmp_path, users)
    app = create_app(
        str(tmp_path), secret_key=SECRET, secure_cookies=False, trust_proxy=False,
        **kwargs,
    )
    app.config["TESTING"] = True
    return app


def _persisted(tmp_path: Path, username: str) -> dict:
    for rec in json.loads((tmp_path / "users.json").read_text()):
        if rec["username"] == username:
            return rec
    raise KeyError(username)


def _admin_client(app):
    from identity_provider_server.tokens import issue_session_token

    client = app.test_client()
    client.set_cookie(
        "idp_session",
        issue_session_token(
            SECRET, "admin", auth_time=int(time.time()), epoch=0, mfa=True,
        ),
        domain="localhost",
    )
    return client


# ===========================================================================
# Finding 3 — gunicorn multi-worker startup guard
# ===========================================================================

def test_env_truthy_token_set():
    """``_env_truthy`` accepts 1/true/yes/on (trimmed, case-insensitive)."""
    for value in ("1", "true", "TRUE", "yes", " on ", "On"):
        assert _env_truthy(value) is True
    for value in (None, "", "0", "false", "no", "off", "maybe"):
        assert _env_truthy(value) is False


def test_worker_count_from_argv_flag(monkeypatch):
    """A ``-w``/``--workers`` token in argv is detected."""
    for argv, expected in (
        (["gunicorn", "-w", "2"], 2),
        (["gunicorn", "--workers=3"], 3),
        (["gunicorn", "-w=4"], 4),
        (["gunicorn", "--workers", "5"], 5),
    ):
        monkeypatch.setattr(sys, "argv", argv)
        assert _detected_worker_count() == expected


def test_worker_count_from_config_file(tmp_path, monkeypatch):
    """A top-level ``workers = N`` literal in a ``-c`` config is detected."""
    conf = tmp_path / "gunicorn.conf.py"
    conf.write_text("bind = '0.0.0.0:5000'\nworkers = 2\nloglevel = 'info'\n")
    monkeypatch.setattr(sys, "argv", ["gunicorn", "-c", str(conf)])
    assert _detected_worker_count() == 2


def test_worker_count_ignores_non_literal_workers(tmp_path, monkeypatch):
    """A computed ``workers`` value is conservatively ignored (stays 1)."""
    conf = tmp_path / "gunicorn.conf.py"
    conf.write_text("import os\nworkers = os.cpu_count()\n")
    monkeypatch.setattr(sys, "argv", ["gunicorn", "--config", str(conf)])
    assert _detected_worker_count() == 1


def test_worker_count_config_missing_file(tmp_path, monkeypatch):
    """A ``-c`` path that does not exist is ignored (count stays 1)."""
    monkeypatch.setattr(
        sys, "argv", ["gunicorn", "-c", str(tmp_path / "nope.py")]
    )
    assert _detected_worker_count() == 1


def test_worker_count_from_annotated_config(tmp_path, monkeypatch):
    """An annotated ``workers: int = N`` assignment is detected."""
    conf = tmp_path / "gunicorn.conf.py"
    conf.write_text("workers: int = 2\n")
    monkeypatch.setattr(sys, "argv", ["gunicorn", "-c", str(conf)])
    assert _detected_worker_count() == 2


def test_worker_count_annotation_without_value(tmp_path, monkeypatch):
    """A bare ``workers: int`` annotation (no value) is ignored (stays 1)."""
    conf = tmp_path / "gunicorn.conf.py"
    conf.write_text("workers: int\nbind = '0.0.0.0:5000'\n")
    monkeypatch.setattr(sys, "argv", ["gunicorn", "-c", str(conf)])
    assert _detected_worker_count() == 1


def test_worker_count_from_env_hint(monkeypatch):
    """A numeric ``WEB_CONCURRENCY`` env hint is folded into the count."""
    monkeypatch.setattr(sys, "argv", ["gunicorn"])
    monkeypatch.setenv("WEB_CONCURRENCY", "3")
    assert _detected_worker_count() == 3


def test_assert_single_worker_refuses_and_allows(monkeypatch, caplog):
    """The shared helper refuses >1, honours the opt-out, allows 1."""
    monkeypatch.delenv("IDP_ALLOW_MULTIWORKER", raising=False)
    with pytest.raises(RuntimeError):
        _assert_single_worker(2)
    monkeypatch.setenv("IDP_ALLOW_MULTIWORKER", "1")
    with caplog.at_level("WARNING"):
        _assert_single_worker(2)  # opt-out: warns, does not raise
    assert any("overridden" in r.message for r in caplog.records)
    monkeypatch.delenv("IDP_ALLOW_MULTIWORKER", raising=False)
    _assert_single_worker(1)  # single worker: silent


def test_create_app_refuses_multiworker(tmp_path, monkeypatch):
    """A gunicorn argv[0] with ``-w 2`` makes ``create_app`` refuse."""
    monkeypatch.delenv("IDP_ALLOW_MULTIWORKER", raising=False)
    monkeypatch.setattr(
        sys, "argv", ["/usr/local/bin/gunicorn", "-w", "2", "app:create_app()"]
    )
    _write_data(tmp_path, [{"username": "admin", "password": _hash()}])
    with pytest.raises(RuntimeError):
        create_app(str(tmp_path), secret_key=SECRET)


def test_create_app_allows_multiworker_with_optout(tmp_path, monkeypatch, caplog):
    """The opt-out lets a gunicorn multi-worker start, logging a warning."""
    monkeypatch.setenv("IDP_ALLOW_MULTIWORKER", "1")
    monkeypatch.setattr(
        sys, "argv", ["/usr/local/bin/gunicorn", "-w", "2", "app:create_app()"]
    )
    _write_data(tmp_path, [{"username": "admin", "password": _hash()}])
    with caplog.at_level("WARNING"):
        app = create_app(str(tmp_path), secret_key=SECRET)
    assert app is not None
    assert any("overridden" in r.message for r in caplog.records)


def test_create_app_does_not_refuse_under_pytest_argv(tmp_path, monkeypatch):
    """A non-gunicorn argv[0] with ``--workers 4`` must NOT make create_app refuse.

    This is the regression guarding the shared factory under pytest, the Flask
    dev server, and embedding callers (design-review fix F3).
    """
    monkeypatch.delenv("IDP_ALLOW_MULTIWORKER", raising=False)
    monkeypatch.setattr(sys, "argv", ["pytest", "--workers", "4"])
    _write_data(tmp_path, [{"username": "admin", "password": _hash()}])
    app = create_app(str(tmp_path), secret_key=SECRET)  # must not raise
    assert app is not None


def _run_gunicorn(monkeypatch, argv, data_dir):
    """Invoke ``run_gunicorn.main`` with ``create_app``/gunicorn stubbed out."""
    calls: dict[str, object] = {}

    def _fake_create_app(path, **kwargs):  # noqa: ANN001, ANN003
        calls["created"] = True
        return object()

    class _FakeApp:
        def __init__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            calls["built"] = True

        def run(self):
            calls["ran"] = True

    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(app_module, "create_app", _fake_create_app)
    import gunicorn.app.base as gbase

    monkeypatch.setattr(gbase, "BaseApplication", _FakeApp)
    _ = data_dir  # real load_config reads the seeded data dir
    run_gunicorn.main()
    return calls


def test_run_gunicorn_refuses_multiworker_args(tmp_path, monkeypatch):
    """``run-idp --workers 2`` refuses BEFORE the app is built (authoritative)."""
    monkeypatch.delenv("IDP_ALLOW_MULTIWORKER", raising=False)
    _write_data(tmp_path, [{"username": "admin", "password": _hash()}])
    with pytest.raises(RuntimeError):
        _run_gunicorn(
            monkeypatch,
            ["run-idp", "--data-dir", str(tmp_path), "--workers", "2"],
            str(tmp_path),
        )


def test_run_gunicorn_allows_single_worker(tmp_path, monkeypatch):
    """``run-idp --workers 1`` reaches the gunicorn application run()."""
    monkeypatch.delenv("IDP_ALLOW_MULTIWORKER", raising=False)
    _write_data(tmp_path, [{"username": "admin", "password": _hash()}])
    calls = _run_gunicorn(
        monkeypatch,
        ["run-idp", "--data-dir", str(tmp_path), "--workers", "1"],
        str(tmp_path),
    )
    assert calls.get("ran") is True


def test_run_gunicorn_env_hint_refused(tmp_path, monkeypatch):
    """A ``WEB_CONCURRENCY`` env hint is folded into the authoritative check."""
    monkeypatch.delenv("IDP_ALLOW_MULTIWORKER", raising=False)
    monkeypatch.setenv("WEB_CONCURRENCY", "3")
    _write_data(tmp_path, [{"username": "admin", "password": _hash()}])
    with pytest.raises(RuntimeError):
        _run_gunicorn(
            monkeypatch,
            ["run-idp", "--data-dir", str(tmp_path), "--workers", "1"],
            str(tmp_path),
        )


def test_single_worker_starts_clean(tmp_path, monkeypatch):
    """Default (single-worker) argv constructs the app without refusing."""
    monkeypatch.setattr(sys, "argv", ["pytest"])
    app = _app(tmp_path, [{"username": "admin", "password": _hash()}])
    assert app is not None


@pytest.mark.smoke
def test_single_worker_app_boots(tmp_path, monkeypatch):
    """Smoke: a single-worker app boots and ``/health`` returns 200."""
    monkeypatch.setattr(sys, "argv", ["/usr/local/bin/gunicorn", "-w", "1"])
    app = _app(tmp_path, [{"username": "admin", "password": _hash()}])
    resp = app.test_client().get("/health")
    assert resp.status_code == 200


# ===========================================================================
# Finding 4 — force_password_change wiring + password-age tracking
# ===========================================================================

def test_add_user_sets_force_password_change(tmp_path):
    """A newly added user is flagged for a forced change with a stamp."""
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "roles": [],
         "claims": ["idpadmin"], "totp_secret": ADMIN_TOTP},
    ])
    client = _admin_client(app)
    html = client.get("/admin").data
    resp = client.post("/admin", data={
        "csrf_token": _csrf(html), "auth_token": _auth(html),
        "action": "add_user", "new_username": "carol",
        "new_user_password": NEW_PW, "new_user_claims": "developer",
    })
    assert resp.status_code == 200
    carol = _persisted(tmp_path, "carol")
    assert carol["force_password_change"] is True
    assert isinstance(carol["password_changed_at"], int)


def test_admin_reset_password_sets_force_change(tmp_path):
    """An admin reset flags the target and stamps the change time."""
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "roles": [],
         "claims": ["idpadmin"], "totp_secret": ADMIN_TOTP},
        {"username": "dave", "password": _hash(), "roles": [],
         "claims": ["developer"]},
    ])
    client = _admin_client(app)
    html = client.get("/admin").data
    resp = client.post("/admin", data={
        "csrf_token": _csrf(html), "auth_token": _auth(html),
        "action": "reset_password", "target_user": "dave", "new_pw": NEW_PW,
    })
    assert resp.status_code == 200
    dave = _persisted(tmp_path, "dave")
    assert dave["force_password_change"] is True
    assert isinstance(dave["password_changed_at"], int)


def test_must_set_password_marker_untouched(tmp_path):
    """Provisioning/reset never adds or removes ``must_set_password``."""
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "roles": [],
         "claims": ["idpadmin"], "totp_secret": ADMIN_TOTP},
        {"username": "seed", "password": _hash(), "roles": [],
         "claims": ["developer"], "must_set_password": True},
    ])
    client = _admin_client(app)
    html = client.get("/admin").data
    # add_user must not introduce must_set_password.
    client.post("/admin", data={
        "csrf_token": _csrf(html), "auth_token": _auth(html),
        "action": "add_user", "new_username": "fresh",
        "new_user_password": NEW_PW, "new_user_claims": "developer",
    })
    assert "must_set_password" not in _persisted(tmp_path, "fresh")
    # reset_password must leave an existing marker alone.
    html = client.get("/admin").data
    client.post("/admin", data={
        "csrf_token": _csrf(html), "auth_token": _auth(html),
        "action": "reset_password", "target_user": "seed", "new_pw": NEW_PW,
    })
    assert _persisted(tmp_path, "seed").get("must_set_password") is True


def _force_change(client, username: str, current: str, new: str):
    """Drive the forced-change completion POST on ``/user``."""
    auth_token = issue_token(SECRET, username, PURPOSE_USER)
    client.set_cookie("csrf_token", "tok", domain="localhost")
    return client.post("/user", data={
        "csrf_token": "tok", "action": "force_change", "auth_token": auth_token,
        "current_password": current, "new_password": new, "confirm_password": new,
    })


def test_password_write_stamps_changed_at(tmp_path):
    """Each password-write path records a fresh ``password_changed_at``.

    Exercises the forced-change and recovery paths through the app, and the
    self-service path by asserting the shared stamping helper runs on the
    forced-change completion (the three sites share ``_stamp_password_change``).
    """
    secret = pyotp.random_base32()
    app = _app(tmp_path, [
        {"username": "erin", "password": _hash(), "roles": [],
         "claims": ["developer"], "totp_secret": secret,
         "force_password_change": True, "password_changed_at": 1},
    ])
    client = app.test_client()
    with patch("identity_provider_server.app.time.time", return_value=5_000.0):
        resp = _force_change(client, "erin", PW, NEW_PW)
    assert resp.status_code == 200
    erin = _persisted(tmp_path, "erin")
    assert erin["password_changed_at"] == 5000
    assert "force_password_change" not in erin

    # Recovery path stamps too.
    secret2 = pyotp.random_base32()
    app2 = _app(tmp_path, [
        {"username": "fred", "password": _hash(), "roles": [],
         "claims": ["developer"], "totp_secret": secret2},
    ])
    token = "tok-" + "0" * 40
    (tmp_path / "recovery_tokens.json").write_text(json.dumps({
        token: {"username": "fred", "created": time.time(),
                "expires": time.time() + 3600},
    }))
    rc = app2.test_client()
    get = rc.get(f"/recover/{token}")
    with patch("identity_provider_server.app.time.time", return_value=6_000.0):
        rc.post(f"/recover/{token}", data={
            "csrf_token": _csrf(get.data),
            "new_password": NEW_PW, "confirm_password": NEW_PW,
            "totp_code": pyotp.TOTP(secret2).now(),
        })
    assert _persisted(tmp_path, "fred")["password_changed_at"] == 6000


def test_age_rotation_disabled_by_default(tmp_path, monkeypatch):
    """With the knob at 0, an old stamp does not force a change on login."""
    monkeypatch.setattr(sys, "argv", ["pytest"])
    now = 1_000_000_000
    old = now - 400 * 86400
    secret = pyotp.random_base32()
    app = _app(tmp_path, [
        {"username": "gail", "password": _hash(), "roles": [],
         "claims": ["developer"], "totp_secret": secret,
         "password_changed_at": old},
    ])
    client = app.test_client()
    with patch("identity_provider_server.app.time.time", return_value=float(now)):
        resp = _login_sp(client, "gail", PW, secret)
    assert b"Password change required" not in resp.data


def test_age_rotation_disabled_for_negative_max_age(tmp_path, monkeypatch):
    """A negative ``IDP_PASSWORD_MAX_AGE_DAYS`` disables the feature."""
    monkeypatch.setenv("IDP_PASSWORD_MAX_AGE_DAYS", "-5")
    monkeypatch.setattr(sys, "argv", ["pytest"])
    now = 1_000_000_000
    old = now - 400 * 86400
    secret = pyotp.random_base32()
    app = _app(tmp_path, [
        {"username": "hank", "password": _hash(), "roles": [],
         "claims": ["developer"], "totp_secret": secret,
         "password_changed_at": old},
    ])
    client = app.test_client()
    with patch("identity_provider_server.app.time.time", return_value=float(now)):
        resp = _login_sp(client, "hank", PW, secret)
    assert b"Password change required" not in resp.data
    monkeypatch.delenv("IDP_PASSWORD_MAX_AGE_DAYS", raising=False)


def test_password_max_age_days_non_numeric_env_is_fatal(tmp_path, monkeypatch):
    """A non-numeric knob is a fatal startup error (fail loud)."""
    monkeypatch.setenv("IDP_PASSWORD_MAX_AGE_DAYS", "abc")
    _write_data(tmp_path, [{"username": "admin", "password": _hash()}])
    with pytest.raises(ValueError):
        load_config(str(tmp_path))
    with pytest.raises(ValueError):
        create_app(str(tmp_path), secret_key=SECRET)
    monkeypatch.delenv("IDP_PASSWORD_MAX_AGE_DAYS", raising=False)


def _login_sp(client, username: str, password: str, secret: str):
    """Drive a full SP password+MFA login, returning the final response."""
    get = client.get("/aws")
    html = get.data
    q = re.search(rb"What is (\d+) (.+?) (\d+)\?", html)
    a, op, b = int(q.group(1)), q.group(2), int(q.group(3))
    ans = a + b if op == b"+" else a - b if op == b"-" else a * b
    ch = re.search(rb'name="challenge_hash" value="([^"]+)"', html).group(1).decode()
    resp = client.post("/aws", data={
        "csrf_token": _csrf(html), "action": "login", "username": username,
        "password": password, "challenge_answer": str(ans), "challenge_hash": ch,
    })
    ticket = re.search(rb'name="mfa_ticket" value="([^"]+)"', resp.data)
    if not ticket:
        return resp
    return client.post("/aws", data={
        "csrf_token": _csrf(resp.data), "totp_step": "1", "service_path": "aws",
        "mfa_ticket": ticket.group(1).decode(),
        "totp_code": pyotp.TOTP(secret).now(),
    })


def test_age_rotation_forces_change_when_expired(tmp_path, monkeypatch):
    """An expired password routes an SP login to the forced-change page."""
    monkeypatch.setenv("IDP_PASSWORD_MAX_AGE_DAYS", "90")
    monkeypatch.setattr(sys, "argv", ["pytest"])
    now = 1_000_000_000
    old = now - 100 * 86400
    secret = pyotp.random_base32()
    app = _app(tmp_path, [
        {"username": "iris", "password": _hash(), "roles": [],
         "claims": ["developer"], "totp_secret": secret,
         "password_changed_at": old},
    ])
    client = app.test_client()
    with patch("identity_provider_server.app.time.time", return_value=float(now)):
        resp = _login_sp(client, "iris", PW, secret)
    assert b"Password change required" in resp.data
    monkeypatch.delenv("IDP_PASSWORD_MAX_AGE_DAYS", raising=False)


def test_age_rotation_skips_passwordless(tmp_path, monkeypatch):
    """A passwordless account past max age is not forced to change on login.

    The account retains a password and TOTP (so it can still log in via the
    password path and satisfies the passwordless minimum-factor policy) plus a
    registered passkey and the passwordless flag, so ``wf.is_passwordless`` is
    True and the age branch returns False.
    """
    monkeypatch.setenv("IDP_PASSWORD_MAX_AGE_DAYS", "90")
    monkeypatch.setattr(sys, "argv", ["pytest"])
    now = 1_000_000_000
    old = now - 100 * 86400
    secret = pyotp.random_base32()
    app = _app(tmp_path, [
        {"username": "jade", "password": _hash(), "roles": [],
         "claims": ["developer"], "totp_secret": secret,
         "passwordless": True, "password_changed_at": old,
         "webauthn_credentials": [{"id": "x", "public_key": "y",
                                   "sign_count": 0}]},
    ])
    client = app.test_client()
    with patch("identity_provider_server.app.time.time", return_value=float(now)):
        resp = _login_sp(client, "jade", PW, secret)
    assert b"Password change required" not in resp.data
    monkeypatch.delenv("IDP_PASSWORD_MAX_AGE_DAYS", raising=False)


def test_age_rotation_skips_records_without_timestamp(tmp_path, monkeypatch):
    """An enabled knob does not force-expire a record with no stamp."""
    monkeypatch.setenv("IDP_PASSWORD_MAX_AGE_DAYS", "90")
    monkeypatch.setattr(sys, "argv", ["pytest"])
    secret = pyotp.random_base32()
    app = _app(tmp_path, [
        {"username": "kyle", "password": _hash(), "roles": [],
         "claims": ["developer"], "totp_secret": secret},
    ])
    client = app.test_client()
    resp = _login_sp(client, "kyle", PW, secret)
    # No password_changed_at => not force-expired => a SAML response is issued.
    assert b"Change Your Password" not in resp.data
    monkeypatch.delenv("IDP_PASSWORD_MAX_AGE_DAYS", raising=False)


@pytest.mark.smoke
def test_force_change_roundtrip(tmp_path, monkeypatch):
    """Smoke: admin adds a user, that user completes a forced change.

    The admin-provisioned account is flagged ``force_password_change``; the
    user completes the forced-change page, the flag clears, and a fresh
    ``password_changed_at`` is stamped. < 2 s, no network.
    """
    monkeypatch.setattr(sys, "argv", ["pytest"])
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "roles": [],
         "claims": ["idpadmin"], "totp_secret": ADMIN_TOTP},
    ])
    admin = _admin_client(app)
    html = admin.get("/admin").data
    admin.post("/admin", data={
        "csrf_token": _csrf(html), "auth_token": _auth(html),
        "action": "add_user", "new_username": "newbie",
        "new_user_password": PW, "new_user_claims": "developer",
    })
    assert _persisted(tmp_path, "newbie")["force_password_change"] is True

    user = app.test_client()
    with patch("identity_provider_server.app.time.time", return_value=7_000.0):
        resp = _force_change(user, "newbie", PW, NEW_PW)
    assert resp.status_code == 200
    rec = _persisted(tmp_path, "newbie")
    assert "force_password_change" not in rec
    assert rec["password_changed_at"] == 7000
