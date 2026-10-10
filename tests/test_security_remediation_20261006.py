"""Security remediation tests for the idp-2026-10-06 review.

Finding 5 (Medium) — session cookie resurrection. A stale session cookie from
a deleted-then-recreated username must not re-authenticate as the new
principal. The fix gives new users a non-zero ``session_epoch`` floor and, on
delete, persists a ``deleted_epochs.json`` tombstone that the session verifier
uses to floor a recreated username's epoch.
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
from identity_provider_server.tokens import issue_session_token

DATA_SRC = Path(__file__).parent.parent / "data"
GOOD_SECRET = "a" * 48
NEW_PW = "Str0ng-Passw0rd!"


def _hash(pw: str = NEW_PW) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=4)).decode()


def _admin_app(tmp_path: Path):
    """Build an app with an idpadmin account and a session-cookie admin login."""
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    users = [
        {"username": "admin", "password": _hash(), "claims": ["idpadmin"],
         "roles": [], "totp_secret": pyotp.random_base32(), "session_epoch": 0},
    ]
    (tmp_path / "users.json").write_text(json.dumps(users))
    (tmp_path / "claims.json").write_text(json.dumps(["idpadmin", "developer"]))
    (tmp_path / "services.yaml").write_text(
        "saml:\n  aws: https://signin.aws.amazon.com/saml\n"
    )
    app = create_app(
        str(tmp_path),
        secret_key=GOOD_SECRET,
        secure_cookies=False,
        trust_proxy=False,
    )
    app.config["TESTING"] = True
    return app


def _admin_client(app):
    client = app.test_client()
    client.set_cookie(
        "idp_session",
        # Admin panel entry requires a two-factor session (finding
        # idp-2026-10-06 F6); simulate a password+TOTP admin login.
        issue_session_token(
            GOOD_SECRET, "admin", auth_time=int(time.time()), epoch=0, mfa=True,
        ),
        domain="localhost",
    )
    return client


def _tokens(client):
    html = client.get("/admin").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', html).group(1)
    return csrf, auth


def _post(client, data):
    csrf, auth = _tokens(client)
    body = {"csrf_token": csrf, "auth_token": auth}
    body.update(data)
    return client.post("/admin", data=body)


def _add_user(client, username: str):
    return _post(client, {
        "action": "add_user",
        "new_username": username,
        "new_user_password": NEW_PW,
        "new_user_claims": "",
    })


def _delete_user(client, username: str):
    return _post(client, {"action": "delete_user", "target_user": username})


# --- (a) add_user writes a non-zero session_epoch ---------------------------

def test_add_user_sets_nonzero_session_epoch(tmp_path):
    app = _admin_app(tmp_path)
    client = _admin_client(app)
    before = int(time.time())
    assert b"created" in _add_user(client, "carol").data

    stored = json.loads((tmp_path / "users.json").read_text())
    carol = next(u for u in stored if u["username"] == "carol")
    assert carol["session_epoch"] > 0
    assert carol["session_epoch"] >= before


# --- (b) delete persists tombstone; recreated epoch-0 cookie is rejected -----

def test_delete_writes_tombstone_and_rejects_resurrected_cookie(tmp_path):
    app = _admin_app(tmp_path)
    client = _admin_client(app)

    # Create carol, then delete her — this must persist a tombstone epoch.
    assert b"created" in _add_user(client, "carol").data
    assert b"deleted" in _delete_user(client, "carol").data

    tombstones = json.loads((tmp_path / "deleted_epochs.json").read_text())
    assert tombstones["carol"] > 0

    # Recreate the same username. add_user gives a fresh floor, but even a
    # cookie minted at epoch 0 for carol must be rejected.
    assert b"created" in _add_user(client, "carol").data

    user_client = app.test_client()
    user_client.set_cookie(
        "idp_session",
        issue_session_token(GOOD_SECRET, "carol", auth_time=int(time.time()), epoch=0),
        domain="localhost",
    )
    resp = user_client.get("/aws")
    # A rejected cookie yields the login form, not a minted SAML assertion.
    assert b"SAMLResponse" not in resp.data


def test_tombstone_floor_only_grows(tmp_path):
    """Re-deleting a recreated username keeps the max tombstone epoch."""
    app = _admin_app(tmp_path)
    client = _admin_client(app)

    _add_user(client, "carol")
    _delete_user(client, "carol")
    first = json.loads((tmp_path / "deleted_epochs.json").read_text())["carol"]

    _add_user(client, "carol")
    _delete_user(client, "carol")
    second = json.loads((tmp_path / "deleted_epochs.json").read_text())["carol"]

    assert second >= first


def test_corrupt_tombstone_value_is_ignored(tmp_path):
    """A non-integer tombstone entry falls back to epoch 0, not a crash."""
    app = _admin_app(tmp_path)
    # Live user whose tombstone holds a non-int value (hand-corrupted file).
    _add_user(_admin_client(app), "erin")
    (tmp_path / "deleted_epochs.json").write_text(json.dumps({"erin": "not-an-int"}))

    # Admin-provisioned users are now flagged for a forced password change
    # (idp-2026-10-06 F4); clear it here so this test exercises only the corrupt
    # tombstone fallback (not the forced-change reroute).
    stored = json.loads((tmp_path / "users.json").read_text())
    for rec in stored:
        if rec["username"] == "erin":
            rec.pop("force_password_change", None)
    (tmp_path / "users.json").write_text(json.dumps(stored))

    # A cookie minted at the account's real epoch still verifies: the corrupt
    # tombstone is treated as 0, so the record epoch wins.
    erin_epoch = next(u for u in stored if u["username"] == "erin")["session_epoch"]
    client = app.test_client()
    client.set_cookie(
        "idp_session",
        issue_session_token(
            GOOD_SECRET, "erin", auth_time=int(time.time()), epoch=erin_epoch
        ),
        domain="localhost",
    )
    resp = client.get("/aws")
    assert b"SAMLResponse" in resp.data


# --- (c) smoke: delete-then-recreate happy path -----------------------------

@pytest.mark.smoke
def test_delete_then_recreate_happy_path(tmp_path):
    app = _admin_app(tmp_path)
    client = _admin_client(app)

    assert b"created" in _add_user(client, "dave").data
    assert b"deleted" in _delete_user(client, "dave").data
    assert (tmp_path / "deleted_epochs.json").exists()
    assert b"created" in _add_user(client, "dave").data

    stored = json.loads((tmp_path / "users.json").read_text())
    dave = next(u for u in stored if u["username"] == "dave")
    assert dave["session_epoch"] > 0
    tombstone = json.loads((tmp_path / "deleted_epochs.json").read_text())["dave"]
    assert tombstone > 0
    # The recreated account's live record epoch may legitimately trail the
    # tombstone by a second (the delete path bumps the old epoch), which is
    # exactly why the tombstone floor exists. A cookie minted at epoch 0 for
    # the recreated username is still rejected.
    user_client = app.test_client()
    user_client.set_cookie(
        "idp_session",
        issue_session_token(GOOD_SECRET, "dave", auth_time=int(time.time()), epoch=0),
        domain="localhost",
    )
    assert b"SAMLResponse" not in user_client.get("/aws").data
