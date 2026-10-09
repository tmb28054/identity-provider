"""Phase 4 security remediation tests (review idp-2026-10-06).

Covers two findings:

* **Finding 4 (Low)** — no maximum password length. The pinned ``bcrypt==5.0.0``
  raises ``ValueError`` on inputs over 72 bytes instead of truncating, so an
  anonymous login POST naming an existing, enabled account with a 73+-byte
  password reached ``bcrypt.checkpw`` and raised. The catch-all handler
  returned a generic 500 but unwound BEFORE the three ``rate_limiter.record``
  calls and ``_register_auth_failure``, so the probe was never counted toward
  any rate-limit bucket or the durable lockout. The fix caps the password at
  ``MAX_PASSWORD_BYTES`` in the policy check (covering enrollment, recovery,
  and the admin set/reset paths), refuses an over-long candidate in
  ``_check_password`` while still spending a dummy ``bcrypt.checkpw`` so no
  ``ValueError`` can propagate, and wraps the SP-login credential check so the
  failure bookkeeping runs even if authentication raises.

* **Finding 5 (Low)** — the durable-lockout response text disclosed account
  existence. A durable lockout is only ever entered by an account that EXISTS,
  and the SP-login lockout branch returned a response ("Account temporarily
  locked. Try again later." / 429) no other path produced, letting an attacker
  confirm a valid username. The fix makes the locked branch return the SAME
  body and status as the generic sliding-window branch, keeping the true
  ``account_locked`` reason only in the audit record.
"""

from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path
from unittest.mock import patch

import bcrypt
import pytest

from identity_provider_server import app as app_module
from identity_provider_server.app import (
    MAX_PASSWORD_BYTES,
    _check_password,
    _password_policy_error,
    create_app,
)

DATA_SRC = Path(__file__).parent.parent / "data"
SECRET = "phase4secret-00000000000000000000000"
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


def _app(tmp_path: Path, users: list[dict]):
    shutil.copy(DATA_SRC / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(DATA_SRC / "idp.key", tmp_path / "idp.key")
    (tmp_path / "users.json").write_text(json.dumps(users))
    (tmp_path / "claims.json").write_text(json.dumps(["idpadmin"]))
    (tmp_path / "services.yaml").write_text(
        "saml:\n  aws: https://signin.aws.amazon.com/saml\n"
    )
    app = create_app(
        str(tmp_path), secret_key=SECRET, secure_cookies=False, trust_proxy=False,
    )
    app.config["TESTING"] = True
    return app


def _audit_records(tmp_path: Path) -> list[dict]:
    path = tmp_path / "audit.log"
    if not path.is_file():
        return []
    return [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.strip()
    ]


# ===========================================================================
# Finding 4 — maximum password length
# ===========================================================================

def test_policy_rejects_overlong_password():
    """A 73+-byte password is rejected with the max-length message."""
    overlong = "A1!" + "a" * 70  # 73 bytes of ASCII
    assert len(overlong.encode("utf-8")) > MAX_PASSWORD_BYTES
    err = _password_policy_error(overlong)
    assert err == f"Password must be at most {MAX_PASSWORD_BYTES} bytes."


def test_policy_counts_bytes_not_code_points():
    """The cap is measured on the UTF-8 encoding, not the character count."""
    # 37 multi-byte characters = 74 bytes but only 37 code points.
    multibyte = "é" * 37
    assert len(multibyte) <= MAX_PASSWORD_BYTES < len(multibyte.encode("utf-8"))
    assert _password_policy_error(multibyte) == (
        f"Password must be at most {MAX_PASSWORD_BYTES} bytes."
    )


def test_policy_accepts_exactly_72_bytes():
    """A password exactly at the 72-byte cap is still accepted by the length rule."""
    at_cap = "Aa1!" + "b" * 68  # 72 bytes, mixes >=3 classes
    assert len(at_cap.encode("utf-8")) == MAX_PASSWORD_BYTES
    assert _password_policy_error(at_cap) is None


def test_check_password_rejects_overlong_without_exception():
    """``_check_password`` returns False (no ValueError) for an over-long value
    AND still spends one dummy ``bcrypt.checkpw`` so timing is unchanged."""
    stored = _hash("Str0ng-Passw0rd!")
    overlong = "x" * 100  # 100 bytes > 72
    with patch("bcrypt.checkpw", wraps=bcrypt.checkpw) as spy:
        result = _check_password(stored, overlong)
    assert result is False
    # Exactly one dummy check was performed, and it used the short dummy input
    # (never the raw over-long value), so bcrypt itself cannot raise.
    assert spy.call_count == 1
    called_pw = spy.call_args.args[0]
    assert len(called_pw) <= MAX_PASSWORD_BYTES


def test_check_password_normal_path_unaffected():
    """A correct password of normal length still verifies."""
    stored = _hash("Str0ng-Passw0rd!")
    assert _check_password(stored, "Str0ng-Passw0rd!") is True
    assert _check_password(stored, "wrong-password") is False


def _overlong_login(client, tmp_path, username: str):
    """Drive a full SP login POST with a 73+-byte password for ``username``."""
    form = client.get("/aws")
    ans, ch = _solve(form.data)
    return client.post("/aws", data={
        "username": username,
        "password": "A1!" + "z" * 100,  # 103 bytes
        "csrf_token": _csrf(form.data),
        "challenge_answer": ans,
        "challenge_hash": ch,
    })


def test_overlong_login_is_not_500_and_counts_failure(tmp_path):
    """An anonymous login POST with a 73+-byte password for an existing, enabled
    account returns the normal invalid-credentials flow (NOT a 500) AND records
    the failure toward the durable lockout counter."""
    app = _app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "session_epoch": 0},
    ])
    client = app.test_client()
    resp = _overlong_login(client, tmp_path, "bob")

    # Normal invalid-credentials flow, not an unhandled 500.
    assert resp.status_code == 401
    assert b"Invalid credentials" in resp.data

    # The failure was counted toward the durable lockout (bookkeeping ran).
    stored = json.loads((tmp_path / "users.json").read_text())
    assert stored[0]["failed_count"] == 1

    # No unhandled_exception audit record was written for this probe.
    reasons = [e.get("reason") for e in _audit_records(tmp_path)]
    assert "unhandled_exception" not in reasons
    assert "invalid_credentials" in reasons


def test_login_bookkeeping_runs_even_if_auth_raises(tmp_path):
    """If the credential check itself raises, the per-IP/per-account records and
    the durable lockout counter still run before the 500 propagates.

    ``_authenticate_user`` is a closure, so the exception is injected one layer
    down: ``bcrypt.checkpw`` (called by ``_check_password`` for the user's valid
    stored hash) is patched to raise, which bubbles up through
    ``_authenticate_user`` into the handler's try/except.
    """
    app = _app(tmp_path, [
        {"username": "bob", "password": _hash(), "roles": [], "claims": [],
         "session_epoch": 0},
    ])
    client = app.test_client()
    form = client.get("/aws")
    ans, ch = _solve(form.data)

    with patch("bcrypt.checkpw", side_effect=RuntimeError("auth exploded")):
        resp = client.post("/aws", data={
            "username": "bob", "password": PW,
            "csrf_token": _csrf(form.data),
            "challenge_answer": ans, "challenge_hash": ch,
        })

    # Even though auth raised, the durable lockout counter advanced.
    stored = json.loads((tmp_path / "users.json").read_text())
    assert stored[0]["failed_count"] == 1
    assert resp.status_code == 500


def test_recovery_rejects_overlong_password(tmp_path):
    """The anonymous recovery POST rejects an over-long new password up front,
    before any ``bcrypt.hashpw`` call."""
    original_hash = _hash()
    app = _app(tmp_path, [
        {"username": "bob", "password": original_hash, "roles": [], "claims": [],
         "session_epoch": 0},
    ])
    # Mint a recovery token by writing the store the recovery route reads (the
    # generator is a closure; the route resolves tokens from this file).
    token = "tok-" + "0" * 40
    (tmp_path / "recovery_tokens.json").write_text(json.dumps({
        token: {
            "username": "bob", "created": time.time(),
            "expires": time.time() + 3600,
        },
    }))

    client = app.test_client()
    get = client.get(f"/recover/{token}")
    csrf = _csrf(get.data)
    resp = client.post(f"/recover/{token}", data={
        "csrf_token": csrf,
        "new_password": "A1!" + "y" * 100,  # 103 bytes
        "confirm_password": "A1!" + "y" * 100,
    })
    assert resp.status_code == 200
    assert f"at most {MAX_PASSWORD_BYTES} bytes".encode() in resp.data
    # The stored password is unchanged (no hashpw happened).
    stored = json.loads((tmp_path / "users.json").read_text())
    assert stored[0]["password"] == original_hash


def test_admin_add_user_rejects_overlong_password(tmp_path):
    """The admin add-user path rejects an over-long password via the policy."""
    err = _password_policy_error("A1!" + "q" * 100)
    assert err == f"Password must be at most {MAX_PASSWORD_BYTES} bytes."


# ===========================================================================
# Finding 5 — durable-lockout response no longer discloses account existence
# ===========================================================================

def _deterministic_rng():
    """Patch the two sources of per-response randomness so form bodies are
    byte-reproducible: the CSRF token hex and the math challenge."""
    return (
        patch.object(app_module.secrets, "token_hex", return_value="f" * 64),
        patch.object(
            app_module, "_generate_challenge",
            return_value=("What is 2 + 2?", "4", "nonce:0:deadbeef"),
        ),
    )


def _locked_user(username: str = "bob") -> dict:
    return {
        "username": username, "password": _hash(), "roles": [], "claims": [],
        "session_epoch": 0, "locked_until": time.time() + 3600,
    }


def test_locked_real_account_and_unknown_user_are_indistinguishable(tmp_path):
    """On the SP login POST, a locked REAL account and an unknown username
    produce byte-identical response bodies and the same status, while the audit
    record for the locked case still carries reason="account_locked"."""
    app = _app(tmp_path, [_locked_user("bob")])
    hex_patch, chal_patch = _deterministic_rng()

    with hex_patch, chal_patch:
        # Locked real account: hits the durable-lockout branch.
        locked_client = app.test_client()
        locked_client.set_cookie("csrf_token", "f" * 64)
        locked_resp = locked_client.post("/aws", data={
            "username": "bob", "password": PW,
            "csrf_token": "f" * 64,
            "challenge_answer": "4", "challenge_hash": "nonce:0:deadbeef",
        })

        # Unknown username: drive it to the per-account sliding-window 429 by
        # exhausting the window with full failed login POSTs, then one more.
        unknown_client = app.test_client()
        for _ in range(5):
            unknown_client.set_cookie("csrf_token", "f" * 64)
            unknown_client.post("/aws", data={
                "username": "ghost", "password": PW,
                "csrf_token": "f" * 64,
                "challenge_answer": "4", "challenge_hash": "nonce:0:deadbeef",
            })
        unknown_client.set_cookie("csrf_token", "f" * 64)
        unknown_resp = unknown_client.post("/aws", data={
            "username": "ghost", "password": PW,
            "csrf_token": "f" * 64,
            "challenge_answer": "4", "challenge_hash": "nonce:0:deadbeef",
        })

    assert locked_resp.status_code == unknown_resp.status_code == 429
    assert locked_resp.data == unknown_resp.data
    assert b"Too many attempts. Try again later." in locked_resp.data
    assert b"Account temporarily locked" not in locked_resp.data

    # The audit log still records the TRUE cause for the locked account.
    reasons = [e.get("reason") for e in _audit_records(tmp_path)]
    assert "account_locked" in reasons


@pytest.mark.smoke
def test_smoke_phase4_password_cap_and_no_enumeration(tmp_path):
    """Smoke: over-long passwords are rejected cleanly and a locked account's
    response matches the generic rate-limit response."""
    # F4: policy and _check_password both refuse an over-long value cleanly.
    overlong = "A1!" + "a" * 100
    assert _password_policy_error(overlong) == (
        f"Password must be at most {MAX_PASSWORD_BYTES} bytes."
    )
    assert _check_password(_hash(), overlong) is False

    # F5: a locked real account returns the generic 429 body, not the
    # account-existence-disclosing text.
    app = _app(tmp_path, [_locked_user("bob")])
    hex_patch, chal_patch = _deterministic_rng()
    with hex_patch, chal_patch:
        client = app.test_client()
        client.set_cookie("csrf_token", "f" * 64)
        resp = client.post("/aws", data={
            "username": "bob", "password": PW,
            "csrf_token": "f" * 64,
            "challenge_answer": "4", "challenge_hash": "nonce:0:deadbeef",
        })
    assert resp.status_code == 429
    assert b"Too many attempts. Try again later." in resp.data
    assert b"Account temporarily locked" not in resp.data
