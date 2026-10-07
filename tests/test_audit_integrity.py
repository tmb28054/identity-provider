"""Audit-log integrity and retention tests (finding idp-2026-10-06 F4).

Covers the FEAT-004 remediation:

* the hash chain is keyed by a dedicated ``IDP_AUDIT_CHAIN_KEY`` / stable
  ``data/audit_chain.key``, independent of ``app.secret_key``;
* ``verify_chain`` runs at startup (notify on failure) and on each admin
  audit-log render (integrity banner on failure);
* the stdout mirror redacts the full User-Agent and truncates the username,
  while the on-disk record keeps full values and still verifies.
"""

from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path
from unittest import mock

import bcrypt
import pytest

from identity_provider_server import app as app_module
from identity_provider_server.app import (
    AuditChainKeyError,
    _resolve_audit_chain_key,
    create_app,
)
from identity_provider_server.audit import AuditLogger
from identity_provider_server.tokens import issue_session_token

DATA_SRC = Path(__file__).parent.parent / "data"
GOOD_SECRET = "a" * 48
OTHER_SECRET = "b" * 48
CHAIN_KEY = "c" * 48


def _seed(tmp_path: Path) -> None:
    """Copy the signing material + a minimal admin user into ``tmp_path``."""
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    pw = bcrypt.hashpw(b"AdminPass123!", bcrypt.gensalt(rounds=4)).decode()
    users = [
        {"username": "admin", "password": pw, "roles": [], "claims": ["idpadmin"]},
    ]
    (tmp_path / "users.json").write_text(json.dumps(users))


def _admin_client(app):
    """Return a test client carrying a minted admin session cookie."""
    client = app.test_client()
    client.set_cookie(
        "idp_session",
        issue_session_token(GOOD_SECRET, "admin", auth_time=int(time.time()), epoch=0),
        domain="localhost",
    )
    return client


# --- chain-key resolution ----------------------------------------------------


@pytest.mark.smoke
def test_chain_key_resolution_and_clean_verify(tmp_path):
    """Smoke: an app resolves a stable chain key and verifies a clean log."""
    _seed(tmp_path)
    app = create_app(str(tmp_path), secret_key=GOOD_SECRET, secure_cookies=False)
    # A persistent key file is created and the fresh log verifies cleanly.
    assert (tmp_path / "audit_chain.key").exists()
    audit = AuditLogger(str(tmp_path), chain_key=(tmp_path / "audit_chain.key").read_text())
    audit.log(username="alice", ip="10.0.0.1", service="aws", result="success")
    assert audit.verify_chain() is True
    assert app is not None


def test_explicit_chain_key_is_used_verbatim(tmp_path):
    """An explicitly provided key wins over the on-disk file."""
    key = _resolve_audit_chain_key(CHAIN_KEY, tmp_path)
    assert key == CHAIN_KEY
    # No key file is created when one is supplied.
    assert not (tmp_path / "audit_chain.key").exists()


def test_env_chain_key_is_used(tmp_path, monkeypatch):
    """IDP_AUDIT_CHAIN_KEY is honoured when no argument is supplied."""
    monkeypatch.setenv("IDP_AUDIT_CHAIN_KEY", "env-chain-key")
    assert _resolve_audit_chain_key("", tmp_path) == "env-chain-key"


def test_stable_key_persists_across_calls(tmp_path):
    """The generated key file is reused rather than regenerated each start."""
    first = _resolve_audit_chain_key("", tmp_path)
    second = _resolve_audit_chain_key("", tmp_path)
    assert first == second
    assert (tmp_path / "audit_chain.key").read_text().strip() == first
    # The key file must be owner-only.
    assert (tmp_path / "audit_chain.key").stat().st_mode & 0o777 == 0o600


def test_chain_key_fails_closed_when_undeliverable(tmp_path, monkeypatch):
    """A non-writable data dir raises rather than auditing on an ephemeral key."""
    def _boom(*_args, **_kwargs):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(app_module.os, "open", _boom)
    with pytest.raises(AuditChainKeyError):
        _resolve_audit_chain_key("", tmp_path)


def test_chain_independent_of_secret_key(tmp_path):
    """Two apps sharing a chain key but differing secret keys verify each other.

    And a log keyed with the chain key does NOT verify under app.secret_key —
    proving the chain is bound to the dedicated key, not the Flask secret.
    """
    _seed(tmp_path)
    # Both apps use the same chain key but different Flask secrets.
    create_app(
        str(tmp_path), secret_key=GOOD_SECRET, audit_chain_key=CHAIN_KEY,
        secure_cookies=False,
    )
    audit_a = AuditLogger(str(tmp_path), chain_key=CHAIN_KEY)
    audit_a.log(username="alice", ip="10.0.0.1", service="aws", result="success")

    # A second logger with the same chain key (even if a different app used a
    # different secret_key) verifies the on-disk chain.
    audit_b = AuditLogger(str(tmp_path), chain_key=CHAIN_KEY)
    assert audit_b.verify_chain() is True

    # The same log keyed under the Flask secret does NOT verify.
    audit_secret = AuditLogger(str(tmp_path), chain_key=GOOD_SECRET)
    assert audit_secret.verify_chain() is False


# --- startup verification ----------------------------------------------------


def test_startup_notifies_on_tampered_log(tmp_path):
    """A tampered audit.log triggers the critical notify path at startup."""
    _seed(tmp_path)
    # Pre-seed a chain, then tamper with it in place.
    audit = AuditLogger(str(tmp_path), chain_key=CHAIN_KEY)
    audit.log(username="alice", ip="10.0.0.1", service="aws", result="success")
    log_path = tmp_path / "audit.log"
    rec = json.loads(log_path.read_text().strip())
    rec["username"] = "mallory"  # rewrite without recomputing the hash
    log_path.write_text(json.dumps(rec, separators=(",", ":")) + "\n")

    with mock.patch("identity_provider_server.notify.notify") as notify_fn:
        notify_fn.return_value = True
        create_app(
            str(tmp_path), secret_key=GOOD_SECRET, audit_chain_key=CHAIN_KEY,
            secure_cookies=False,
        )
    assert notify_fn.called
    event = notify_fn.call_args.args[0]
    assert event == "audit_chain_invalid"
    assert notify_fn.call_args.kwargs["severity"] == "critical"


# --- per-render banner -------------------------------------------------------


def test_audit_render_shows_banner_when_chain_invalid(tmp_path):
    """The admin audit-log render shows an integrity banner when verify fails."""
    _seed(tmp_path)
    app = create_app(
        str(tmp_path), secret_key=GOOD_SECRET, audit_chain_key=CHAIN_KEY,
        secure_cookies=False,
    )
    app.config["TESTING"] = True
    client = _admin_client(app)
    panel = client.get("/admin").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', panel).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', panel).group(1)

    # Force the chain check to report failure for this render only.
    with mock.patch(
        "identity_provider_server.audit.AuditLogger.verify_chain",
        return_value=False,
    ):
        resp = client.post(
            "/admin/audit-log", data={"csrf_token": csrf, "auth_token": auth}
        )
    assert resp.status_code == 200
    assert b"integrity check FAILED" in resp.data


def test_audit_render_no_banner_when_chain_ok(tmp_path):
    """A clean chain renders the audit log without the integrity banner."""
    _seed(tmp_path)
    app = create_app(
        str(tmp_path), secret_key=GOOD_SECRET, audit_chain_key=CHAIN_KEY,
        secure_cookies=False,
    )
    app.config["TESTING"] = True
    client = _admin_client(app)
    panel = client.get("/admin").data.decode()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', panel).group(1)
    auth = re.search(r'name="auth_token" value="([^"]+)"', panel).group(1)
    resp = client.post(
        "/admin/audit-log", data={"csrf_token": csrf, "auth_token": auth}
    )
    assert resp.status_code == 200
    assert b"integrity check FAILED" not in resp.data


# --- stdout mirror redaction -------------------------------------------------


def test_stdout_mirror_redacts_pii_but_disk_record_is_full(tmp_path, capsys):
    """The stdout mirror hashes the UA and truncates the username; disk is full."""
    _seed(tmp_path)
    audit = AuditLogger(str(tmp_path), chain_key=CHAIN_KEY)
    full_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"
    audit.log(
        username="alice-wonderland",
        ip="10.0.0.1",
        service="aws",
        result="success",
        user_agent=full_ua,
    )
    out = capsys.readouterr().out
    mirror = json.loads(out.split("AUDIT ", 1)[1].strip())
    # Mirror is redacted.
    assert mirror["user_agent"].startswith("sha256:")
    assert full_ua not in out
    assert mirror["username"] != "alice-wonderland"
    assert mirror["username"].startswith("ali")
    assert "alice-wonderland" not in out

    # On-disk record keeps the full values and still verifies.
    rec = json.loads((tmp_path / "audit.log").read_text().strip())
    assert rec["username"] == "alice-wonderland"
    assert rec["user_agent"] == full_ua
    assert AuditLogger(str(tmp_path), chain_key=CHAIN_KEY).verify_chain() is True
