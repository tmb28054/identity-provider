"""Phase 1 security-remediation tests (idp-2026-10-06).

Covers the two High findings remediated in Phase 1:

* **Finding 1 (High)** — a self-sustaining unauthenticated admin lockout. The
  admin login throttle gate used to call ``_register_auth_failure`` on EVERY
  throttled request, including those triggered solely by an already-live
  durable lock, so an anonymous caller could hold the sole admin locked
  forever. The gate now checks the durable lock first and returns 429 WITHOUT
  re-arming it, neither throttle branch advances the durable counter,
  ``_register_auth_failure`` stamps ``locked_until`` exactly once at the
  threshold crossing, the recovery route no longer pre-empts a valid
  single-use recovery token plus MFA with a lockout 429, and a new admin-UI
  ``clear_lockout`` action lets a second admin clear a peer's lock.

* **Finding 2 (High)** — backup create/restore staged plaintext secrets on the
  untrusted SMB share and re-read them (TOCTOU). Both paths now build/extract
  the tarball entirely in memory (``io.BytesIO``), the restore digest sidecar
  is mandatory (fail closed), restore enforces a ``BACKUP_FILES`` member
  allowlist, and the admin form validates the SMB server/share values.
"""

from __future__ import annotations

import io
import json
import re
import shutil
import tarfile
import time
from pathlib import Path
from unittest.mock import patch

import bcrypt
import pyotp
import pytest
from cryptography.fernet import Fernet

from identity_provider_server import backup as bk
from identity_provider_server.app import (
    LOCKOUT_DURATION_SECONDS,
    LOCKOUT_THRESHOLD,
    create_app,
)
from identity_provider_server.tokens import issue_session_token

DATA_SRC = Path(__file__).parent.parent / "data"
SECRET = "phase5secret-00000000000000000000000"
PW = "AdminPass123!"
ADMIN_TOTP = pyotp.random_base32()


def _hash(pw: str = PW) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=4)).decode()


def _csrf(html: bytes) -> str:
    return re.search(rb'name="csrf_token" value="([^"]+)"', html).group(1).decode()


def _auth(html: bytes) -> str:
    return re.search(rb'name="auth_token" value="([^"]+)"', html).group(1).decode()


def _session_cookie(secret: str, username: str) -> str:
    return issue_session_token(
        secret, username, auth_time=int(time.time()), epoch=0, mfa=True,
    )


def _app(tmp_path: Path, users: list[dict]):
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    (tmp_path / "users.json").write_text(json.dumps(users))
    (tmp_path / "claims.json").write_text(json.dumps(["idpadmin", "developer"]))
    (tmp_path / "services.yaml").write_text(
        "saml:\n  aws: https://signin.aws.amazon.com/saml\n"
    )
    app = create_app(
        str(tmp_path), secret_key=SECRET, secure_cookies=False, trust_proxy=False,
    )
    app.config["TESTING"] = True
    return app


def _persisted(tmp_path: Path, username: str) -> dict:
    """Return the persisted user record from users.json."""
    for rec in json.loads((tmp_path / "users.json").read_text()):
        if rec["username"] == username:
            return rec
    raise KeyError(username)


def _audit_records(tmp_path: Path) -> list[dict]:
    path = tmp_path / "audit.log"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _admin_client(app):
    client = app.test_client()
    client.set_cookie(
        "idp_session", _session_cookie(SECRET, "admin"), domain="localhost",
    )
    return client


# ===========================================================================
# Finding 1 — self-sustaining admin lockout
# ===========================================================================

def test_admin_locked_account_returns_429_without_registering_failure(tmp_path):
    """A locked admin account 429s the login gate without re-arming the lock."""
    locked_at = time.time() + LOCKOUT_DURATION_SECONDS
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "roles": [],
         "claims": ["idpadmin"], "totp_secret": ADMIN_TOTP,
         "failed_count": LOCKOUT_THRESHOLD, "locked_until": locked_at},
    ])
    client = app.test_client()
    html = client.get("/admin").data
    resp = client.post("/admin", data={
        "csrf_token": _csrf(html), "action": "login", "username": "admin",
        "password": "wrong", "totp_code": "000000",
        "challenge_answer": "0", "challenge_hash": "bogus",
    })
    assert resp.status_code == 429
    rec = _persisted(tmp_path, "admin")
    # The durable counters must be UNCHANGED — no self-refresh (F1 regression).
    assert rec["failed_count"] == LOCKOUT_THRESHOLD
    assert rec["locked_until"] == locked_at
    reasons = [r.get("reason") for r in _audit_records(tmp_path)]
    assert "account_locked" in reasons


def test_admin_throttle_branch_does_not_advance_durable_counter(tmp_path):
    """A sliding-window throttle 429s but must not advance the durable counter."""
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "roles": [],
         "claims": ["idpadmin"], "totp_secret": ADMIN_TOTP},
    ])
    client = app.test_client()
    with patch(
        "identity_provider_server.app._RateLimiter.is_limited", return_value=True,
    ):
        html = client.get("/admin").data
        resp = client.post("/admin", data={
            "csrf_token": _csrf(html), "action": "login", "username": "admin",
            "password": "wrong", "totp_code": "000000",
            "challenge_answer": "0", "challenge_hash": "bogus",
        })
    assert resp.status_code == 429
    rec = _persisted(tmp_path, "admin")
    assert "failed_count" not in rec
    assert "locked_until" not in rec
    reasons = [r.get("reason") for r in _audit_records(tmp_path)]
    assert "rate_limited" in reasons


def _solve_captcha(html: bytes) -> tuple[str, str]:
    q = re.search(rb"What is (\d+) (.+?) (\d+)\?", html)
    a, op, b = int(q.group(1)), q.group(2), int(q.group(3))
    ans = a + b if op == b"+" else a - b if op == b"-" else a * b
    ch = re.search(rb'name="challenge_hash" value="([^"]+)"', html).group(1)
    return str(ans), ch.decode()


def _failed_admin_login(client) -> None:
    """Drive one real credential failure through the admin login path."""
    html = client.get("/admin").data
    ans, ch = _solve_captcha(html)
    client.post("/admin", data={
        "csrf_token": _csrf(html), "action": "login", "username": "admin",
        "password": "wrong-password", "totp_code": "000000",
        "challenge_answer": ans, "challenge_hash": ch,
    })


def test_register_auth_failure_stamps_locked_until_once(tmp_path):
    """``locked_until`` is pinned at the crossing, not slid on later failures.

    Drives ``_register_auth_failure`` through the public admin login path (real
    credential failures) under a frozen clock, mirroring the design's test.
    """
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "roles": [],
         "claims": ["idpadmin"], "totp_secret": ADMIN_TOTP},
    ])
    client = app.test_client()
    # Keep the sliding-window throttle out of the way so each attempt reaches
    # the real credential check and advances the durable counter.
    with (
        patch("identity_provider_server.app._RateLimiter.is_limited",
              return_value=False),
        patch("identity_provider_server.app.time.time", return_value=1_000.0),
    ):
        for _ in range(LOCKOUT_THRESHOLD):
            _failed_admin_login(client)
        stamped = _persisted(tmp_path, "admin")["locked_until"]
        assert stamped == 1_000.0 + LOCKOUT_DURATION_SECONDS
        # A later credential failure past the threshold (clock advanced) must
        # NOT move the timestamp forward: it is stamped only on count ==
        # LOCKOUT_THRESHOLD (F1). The gate 429s on the durable lock first and
        # does not re-arm, so the counter also does not advance here.
    with (
        patch("identity_provider_server.app._RateLimiter.is_limited",
              return_value=False),
        patch("identity_provider_server.app.time.time", return_value=5_000.0),
    ):
        _failed_admin_login(client)
    assert _persisted(tmp_path, "admin")["locked_until"] == stamped


def test_admin_clear_lockout_action(tmp_path):
    """An admin clears a peer's lock; counters and audit reflect it."""
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "roles": [],
         "claims": ["idpadmin"], "totp_secret": ADMIN_TOTP},
        {"username": "bob", "password": _hash(), "roles": [],
         "claims": ["developer"], "failed_count": LOCKOUT_THRESHOLD,
         "locked_until": time.time() + LOCKOUT_DURATION_SECONDS,
         "must_set_password": True},
    ])
    client = _admin_client(app)
    html = client.get("/admin").data
    resp = client.post("/admin", data={
        "csrf_token": _csrf(html), "auth_token": _auth(html),
        "action": "clear_lockout", "target_user": "bob",
    })
    assert resp.status_code == 200
    assert b"Lockout cleared" in resp.data
    bob = _persisted(tmp_path, "bob")
    assert "failed_count" not in bob
    assert "locked_until" not in bob
    # clear_lockout must NOT touch the must_set_password marker.
    assert bob.get("must_set_password") is True
    reasons = [r.get("reason") for r in _audit_records(tmp_path)]
    assert any(r == "clear_lockout:bob" for r in reasons)


def test_clear_lockout_unknown_target(tmp_path):
    """Clearing an unknown target renders the not-found error."""
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "roles": [],
         "claims": ["idpadmin"], "totp_secret": ADMIN_TOTP},
    ])
    client = _admin_client(app)
    html = client.get("/admin").data
    resp = client.post("/admin", data={
        "csrf_token": _csrf(html), "auth_token": _auth(html),
        "action": "clear_lockout", "target_user": "ghost",
    })
    assert resp.status_code == 200
    assert b"not found" in resp.data


def _mint_recovery(tmp_path: Path, username: str) -> str:
    token = "tok-" + "0" * 40
    (tmp_path / "recovery_tokens.json").write_text(json.dumps({
        token: {
            "username": username,
            "created": time.time(),
            "expires": time.time() + 3600,
        },
    }))
    return token


def test_recovery_succeeds_for_locked_account(tmp_path):
    """A valid recovery token + correct MFA clears a durable lock (F1)."""
    secret = pyotp.random_base32()
    app = _app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [],
         "claims": ["developer"], "totp_secret": secret,
         "failed_count": LOCKOUT_THRESHOLD,
         "locked_until": time.time() + LOCKOUT_DURATION_SECONDS},
    ])
    client = app.test_client()
    token = _mint_recovery(tmp_path, "bob")
    get = client.get(f"/recover/{token}")
    assert get.status_code == 200
    resp = client.post(f"/recover/{token}", data={
        "csrf_token": _csrf(get.data),
        "new_password": "N3w-Passw0rd!!", "confirm_password": "N3w-Passw0rd!!",
        "totp_code": pyotp.TOTP(secret).now(),
    })
    assert resp.status_code == 200
    assert b"Password updated successfully" in resp.data
    bob = _persisted(tmp_path, "bob")
    assert "failed_count" not in bob
    assert "locked_until" not in bob


def test_recovery_locked_wrong_mfa_still_counts(tmp_path):
    """A wrong MFA code on recovery is rejected and still counts the failure."""
    secret = pyotp.random_base32()
    app = _app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [],
         "claims": ["developer"], "totp_secret": secret,
         "failed_count": LOCKOUT_THRESHOLD,
         "locked_until": time.time() + LOCKOUT_DURATION_SECONDS},
    ])
    client = app.test_client()
    token = _mint_recovery(tmp_path, "bob")
    get = client.get(f"/recover/{token}")
    assert get.status_code == 200
    before = _persisted(tmp_path, "bob")["failed_count"]
    resp = client.post(f"/recover/{token}", data={
        "csrf_token": _csrf(get.data),
        "new_password": "N3w-Passw0rd!!", "confirm_password": "N3w-Passw0rd!!",
        "totp_code": "000000",
    })
    assert resp.status_code == 200
    assert b"Invalid MFA code" in resp.data
    # The per-attempt durable counter still advanced (pre-check removal did not
    # disable the MFA-failure counter).
    assert _persisted(tmp_path, "bob")["failed_count"] == before + 1


@pytest.mark.smoke
def test_admin_locked_account_not_self_sustaining(tmp_path):
    """Smoke: a lock expires on schedule despite an intervening throttled spray.

    A frozen clock avoids any real sleep; the point is that a wrong-captcha
    spray against a locked account does not extend ``locked_until`` (F1).
    """
    start = 1_000.0
    locked_until = start + LOCKOUT_DURATION_SECONDS
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "roles": [],
         "claims": ["idpadmin"], "totp_secret": ADMIN_TOTP,
         "failed_count": LOCKOUT_THRESHOLD, "locked_until": locked_until},
    ])
    client = app.test_client()
    # A throttled spray while still locked must not re-arm the hold.
    with patch("identity_provider_server.app.time.time", return_value=start + 60):
        html = client.get("/admin").data
        resp = client.post("/admin", data={
            "csrf_token": _csrf(html), "action": "login", "username": "admin",
            "password": "wrong", "totp_code": "000000",
            "challenge_answer": "0", "challenge_hash": "bogus",
        })
    assert resp.status_code == 429
    assert _persisted(tmp_path, "admin")["locked_until"] == locked_until


# ===========================================================================
# Finding 2 — backup plaintext staging / TOCTOU
# ===========================================================================

def _seed_data(tmp_path: Path) -> Path:
    data = tmp_path / "data"
    data.mkdir()
    (data / "idp.key").write_text("PRIVATE-KEY-MATERIAL")
    (data / "users.json").write_text('[{"username": "a"}]')
    return data


def test_create_encrypted_archive_leaves_no_plaintext_on_share(tmp_path):
    """Only ciphertext + digest reach the share; no plaintext tarball."""
    data = _seed_data(tmp_path)
    key = Fernet.generate_key()
    share = tmp_path / "share"
    share.mkdir()
    dest = share / "idp-20260101-000000.tar.gz"
    bk.create_encrypted_archive(data, dest, key)
    names = sorted(p.name for p in share.iterdir())
    assert names == [
        "idp-20260101-000000.tar.gz.enc",
        "idp-20260101-000000.tar.gz.enc.sha256",
    ]
    # No *.plain.tmp was ever written, and the plaintext key never hit the share.
    assert not list(share.glob("*.plain.tmp"))
    for p in share.iterdir():
        assert b"PRIVATE-KEY-MATERIAL" not in p.read_bytes()


def test_restore_requires_digest_sidecar(tmp_path):
    """A missing .sha256 sidecar fails closed."""
    data = _seed_data(tmp_path)
    key = Fernet.generate_key()
    dest = tmp_path / "idp-x.tar.gz"
    bk.create_encrypted_archive(data, dest, key)
    enc = Path(str(dest) + bk.ENCRYPTED_SUFFIX)
    Path(str(enc) + bk.DIGEST_SUFFIX).unlink()
    with pytest.raises(ValueError, match="digest sidecar missing"):
        bk.restore_encrypted_archive(enc, tmp_path / "restored", key)


def test_restore_rejects_digest_mismatch(tmp_path):
    """A corrupted sidecar digest is rejected."""
    data = _seed_data(tmp_path)
    key = Fernet.generate_key()
    dest = tmp_path / "idp-x.tar.gz"
    bk.create_encrypted_archive(data, dest, key)
    enc = Path(str(dest) + bk.ENCRYPTED_SUFFIX)
    Path(str(enc) + bk.DIGEST_SUFFIX).write_text("deadbeef\n")
    with pytest.raises(ValueError, match="digest mismatch"):
        bk.restore_encrypted_archive(enc, tmp_path / "restored", key)


def _encrypt_archive_with_member(tmp_path: Path, name: str, key: bytes) -> Path:
    """Build an encrypted archive containing a single ``name`` member."""
    from cryptography.fernet import Fernet

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        payload = b"x"
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        info.mode = 0o600
        tar.addfile(info, io.BytesIO(payload))
    token = Fernet(key).encrypt(buf.getvalue())
    enc = tmp_path / "crafted.tar.gz.enc"
    enc.write_bytes(token)
    Path(str(enc) + bk.DIGEST_SUFFIX).write_text(bk._sha256_hex(token) + "\n")
    return enc


@pytest.mark.parametrize("member", ["audit.log", "audit_chain.key"])
def test_restore_rejects_non_allowlisted_member(tmp_path, member):
    """A member absent from BACKUP_FILES is rejected by the allowlist."""
    key = Fernet.generate_key()
    enc = _encrypt_archive_with_member(tmp_path, member, key)
    assert member not in bk.BACKUP_FILES  # the allowlist is the gate, not EXCLUDED
    with pytest.raises(ValueError, match="not in backup allowlist"):
        bk.restore_encrypted_archive(enc, tmp_path / "restored", key)


def test_restore_is_single_read_in_memory(tmp_path):
    """The on-share ciphertext is read once and no temp file is staged."""
    data = _seed_data(tmp_path)
    key = Fernet.generate_key()
    dest = tmp_path / "idp-x.tar.gz"
    bk.create_encrypted_archive(data, dest, key)
    enc = Path(str(dest) + bk.ENCRYPTED_SUFFIX)
    restored = tmp_path / "restored"

    real_read_bytes = Path.read_bytes
    reads: list[str] = []

    def _tracking_read_bytes(self):
        reads.append(str(self))
        return real_read_bytes(self)

    with patch.object(Path, "read_bytes", _tracking_read_bytes):
        bk.restore_encrypted_archive(enc, restored, key)
    # The ciphertext path is read exactly once.
    assert reads.count(str(enc)) == 1
    # No temp file was staged next to the on-share archive.
    assert not list(enc.parent.glob("*.plain.tmp"))
    assert (restored / "idp.key").read_text() == "PRIVATE-KEY-MATERIAL"


@pytest.mark.parametrize(
    "bad", ["../x", "a/b", "a\\b", "has space", "ctrl\x01char", ""],
)
def test_validate_server_rejects_unsafe(bad):
    """Unsafe SMB server values raise InvalidServerError."""
    with pytest.raises(bk.InvalidServerError):
        bk.validate_server(bad)


@pytest.mark.parametrize("good", ["fileserver.local", "192.168.101.20", "host-1"])
def test_validate_server_accepts_good(good):
    """Hostnames and IPv4 literals pass."""
    assert bk.validate_server(good) == good


@pytest.mark.parametrize(
    "bad", ["../x", "a/b", "a\\b", "has space", "ctrl\x01char", ""],
)
def test_validate_share_rejects_unsafe(bad):
    """Unsafe SMB share values raise InvalidShareError."""
    with pytest.raises(bk.InvalidShareError):
        bk.validate_share(bad)


def test_validate_share_accepts_good():
    """A simple share segment passes."""
    assert bk.validate_share("idp-backups") == "idp-backups"


def test_save_backup_config_rejects_unsafe_server_share(tmp_path):
    """A bad server/share re-renders with an error and persists nothing."""
    app = _app(tmp_path, [
        {"username": "admin", "password": _hash(), "roles": [],
         "claims": ["idpadmin"], "totp_secret": ADMIN_TOTP},
    ])
    client = _admin_client(app)
    html = client.get("/admin/backups").data
    resp = client.post("/admin/backups", data={
        "csrf_token": _csrf(html), "auth_token": _auth(html),
        "action": "save_backup_config",
        "server": "../evil", "share": "ok", "username": "u",
        "subpath": "idp-backup", "daily_retention": "1", "weekly_retention": "1",
    })
    assert resp.status_code == 200
    assert b"Invalid backup server" in resp.data
    assert not (tmp_path / "backup_config.json").is_file()

    html = client.get("/admin/backups").data
    resp = client.post("/admin/backups", data={
        "csrf_token": _csrf(html), "auth_token": _auth(html),
        "action": "save_backup_config",
        "server": "fileserver.local", "share": "bad/share", "username": "u",
        "subpath": "idp-backup", "daily_retention": "1", "weekly_retention": "1",
    })
    assert resp.status_code == 200
    assert b"Invalid backup share" in resp.data
    assert not (tmp_path / "backup_config.json").is_file()


@pytest.mark.smoke
def test_backup_roundtrip_in_memory(tmp_path):
    """Smoke: encrypt from a seeded dir and restore into a fresh dir."""
    data = _seed_data(tmp_path)
    key = Fernet.generate_key()
    share = tmp_path / "share"
    share.mkdir()
    dest = share / "idp-20260101-000000.tar.gz"
    bk.create_encrypted_archive(data, dest, key)
    assert not list(share.glob("*.plain.tmp"))
    enc = Path(str(dest) + bk.ENCRYPTED_SUFFIX)
    restored = tmp_path / "restored"
    bk.restore_encrypted_archive(enc, restored, key)
    assert (restored / "idp.key").read_text() == "PRIVATE-KEY-MATERIAL"
    assert (restored / "users.json").read_text() == '[{"username": "a"}]'
