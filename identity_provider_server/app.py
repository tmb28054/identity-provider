from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import random
import secrets
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from flask import Flask, redirect, render_template_string, request

from .oauth_builder import build_oauth_token
from .saml_builder import ACS_URL, build_saml_response
from .services import ServiceProvider, load_services
from .totp import generate_secret, provisioning_uri, qr_code_data_uri, verify_code

logger = logging.getLogger(__name__)

LOGIN_FORM = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ service_title }} Login</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f4f6f9;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .card {
      background: #fff;
      border-radius: 8px;
      box-shadow: 0 2px 12px rgba(0,0,0,0.08);
      padding: 2rem;
      width: 100%;
      max-width: 380px;
    }
    h1 { font-size: 1.4rem; margin-bottom: 1.5rem; color: #232f3e; }
    label { display: block; font-size: 0.85rem; color: #555; margin-bottom: 0.3rem; }
    input[type="text"], input[type="password"] {
      width: 100%;
      padding: 0.6rem 0.75rem;
      border: 1px solid #ccc;
      border-radius: 4px;
      font-size: 0.95rem;
      margin-bottom: 1rem;
    }
    input:focus { outline: none; border-color: #0073bb; box-shadow: 0 0 0 2px rgba(0,115,187,0.2); }
    .challenge {
      background: #f0f4f8;
      border: 1px solid #d5dce6;
      border-radius: 4px;
      padding: 0.75rem;
      margin-bottom: 1rem;
      text-align: center;
    }
    .challenge-question {
      font-size: 1.1rem;
      font-weight: 600;
      color: #232f3e;
      margin-bottom: 0.5rem;
    }
    .challenge-label {
      font-size: 0.75rem;
      color: #666;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    button {
      width: 100%;
      padding: 0.7rem;
      background: #0073bb;
      color: #fff;
      border: none;
      border-radius: 4px;
      font-size: 1rem;
      cursor: pointer;
    }
    button:hover { background: #005a94; }
    .error { color: #d13212; font-size: 0.85rem; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>{{ service_title }} Login</h1>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="hidden" name="challenge_hash" value="{{ challenge_hash }}">

      <label for="username">Username</label>
      <input type="text" id="username" name="username" required autofocus>

      <label for="password">Password</label>
      <input type="password" id="password" name="password" required>

      <div class="challenge">
        <div class="challenge-label">Human verification</div>
        <div class="challenge-question">{{ challenge_question }}</div>
      </div>
      <label for="challenge_answer">Your answer</label>
      <input type="text" id="challenge_answer" name="challenge_answer"
             placeholder="Type the answer" required autocomplete="off">

      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>
"""

SAML_POST = """
<!doctype html><title>Redirecting…</title>
<body onload="document.forms[0].submit()">
<form method="post" action="{{ acs }}">
  <input type="hidden" name="SAMLResponse" value="{{ saml }}">
  <input type="hidden" name="RelayState" value="">
</form></body>
"""

LOGOUT_PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Logged Out</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f4f6f9; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #fff; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,0.08);
      padding: 2rem; width: 100%; max-width: 380px; text-align: center; }
    h1 { font-size: 1.4rem; margin-bottom: 1rem; color: #232f3e; }
    p { font-size: 0.9rem; color: #555; margin-bottom: 1.5rem; }
    a { display: inline-block; padding: 0.6rem 1.5rem; background: #0073bb; color: #fff;
      border-radius: 4px; text-decoration: none; font-size: 0.95rem; }
    a:hover { background: #005a94; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Logged Out</h1>
    <p>Your session has been cleared.</p>
    <a href="/{{ service_path }}">Sign in again</a>
  </div>
</body>
</html>
"""

RECOVERY_PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Account Recovery</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f4f6f9; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #fff; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,0.08);
      padding: 2rem; width: 100%; max-width: 420px; }
    h1 { font-size: 1.4rem; margin-bottom: 0.5rem; color: #232f3e; }
    .subtitle { font-size: 0.9rem; color: #555; margin-bottom: 1.5rem; }
    h2 { font-size: 1.1rem; color: #232f3e; margin: 1.5rem 0 0.75rem; border-top: 1px solid #eee; padding-top: 1rem; }
    label { display: block; font-size: 0.85rem; color: #555; margin-bottom: 0.3rem; }
    input[type="text"], input[type="password"] { width: 100%; padding: 0.6rem 0.75rem;
      border: 1px solid #ccc; border-radius: 4px; font-size: 0.95rem; margin-bottom: 1rem; }
    button { width: 100%; padding: 0.7rem; background: #0073bb; color: #fff; border: none;
      border-radius: 4px; font-size: 1rem; cursor: pointer; }
    button:hover { background: #005a94; }
    .error { color: #d13212; font-size: 0.85rem; margin-bottom: 1rem; }
    .success { color: #1d8102; font-size: 0.9rem; margin-bottom: 1rem; }
    .qr { text-align: center; margin: 1rem 0; }
    .qr img { border: 4px solid #eee; border-radius: 8px; }
    .secret-code { background: #f0f4f8; border: 1px solid #d5dce6; border-radius: 4px;
      padding: 0.5rem; text-align: center; font-family: monospace; font-size: 0.9rem;
      letter-spacing: 2px; margin-bottom: 1rem; word-break: break-all; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Account Recovery</h1>
    <p class="subtitle">Hello, {{ username }}. Set your new password{% if qr_data_uri %} and enable MFA{% endif %}.</p>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
    {% if success %}<p class="success">{{ success }}</p>{% endif %}

    {% if not success %}
    <form method="post">
      <input type="hidden" name="recovery_token" value="{{ recovery_token }}">

      <label for="new_password">New password (min 8 characters)</label>
      <input type="password" id="new_password" name="new_password" required minlength="8">
      <label for="confirm_password">Confirm password</label>
      <input type="password" id="confirm_password" name="confirm_password" required minlength="8">

      {% if qr_data_uri %}
      <h2 style="border-top:none;margin-top:1rem;padding-top:0;">Set up MFA (optional)</h2>
      <p style="font-size:0.85rem;color:#555;margin-bottom:0.75rem;">Scan with your authenticator app:</p>
      <div class="qr"><img src="{{ qr_data_uri }}" alt="QR Code" width="180" height="180"></div>
      <p style="font-size:0.8rem;color:#666;margin-bottom:0.5rem;">Manual key:</p>
      <div class="secret-code">{{ totp_secret }}</div>
      <input type="hidden" name="totp_secret" value="{{ totp_secret }}">
      <label for="totp_code">Enter 6-digit code to confirm MFA (leave blank to skip)</label>
      <input type="text" id="totp_code" name="totp_code" maxlength="6" pattern="[0-9]{6}"
             autocomplete="one-time-code" inputmode="numeric" placeholder="Optional">
      {% endif %}

      <button type="submit">Save</button>
    </form>
    {% endif %}
  </div>
</body>
</html>
"""

TOTP_FORM = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Two-Factor Authentication</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f4f6f9; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #fff; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,0.08);
      padding: 2rem; width: 100%; max-width: 380px; }
    h1 { font-size: 1.4rem; margin-bottom: 1.5rem; color: #232f3e; }
    label { display: block; font-size: 0.85rem; color: #555; margin-bottom: 0.3rem; }
    input[type="text"] { width: 100%; padding: 0.6rem 0.75rem; border: 1px solid #ccc;
      border-radius: 4px; font-size: 1.2rem; letter-spacing: 0.3rem; text-align: center; margin-bottom: 1rem; }
    button { width: 100%; padding: 0.7rem; background: #0073bb; color: #fff; border: none;
      border-radius: 4px; font-size: 1rem; cursor: pointer; }
    button:hover { background: #005a94; }
    .error { color: #d13212; font-size: 0.85rem; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Two-Factor Authentication</h1>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
    <p style="margin-bottom:1rem;font-size:0.9rem;color:#555;">Enter the 6-digit code from your authenticator app.</p>
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="hidden" name="totp_step" value="1">
      <input type="hidden" name="username" value="{{ username }}">
      <input type="hidden" name="service_path" value="{{ service_path }}">
      <label for="totp_code">Verification code</label>
      <input type="text" id="totp_code" name="totp_code" maxlength="6" pattern="[0-9]{6}"
             required autofocus autocomplete="one-time-code" inputmode="numeric">
      <button type="submit">Verify</button>
    </form>
  </div>
</body>
</html>
"""

USER_PAGE_LOGIN = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Account Settings</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f4f6f9; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #fff; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,0.08);
      padding: 2rem; width: 100%; max-width: 380px; }
    h1 { font-size: 1.4rem; margin-bottom: 1.5rem; color: #232f3e; }
    label { display: block; font-size: 0.85rem; color: #555; margin-bottom: 0.3rem; }
    input[type="text"], input[type="password"] { width: 100%; padding: 0.6rem 0.75rem;
      border: 1px solid #ccc; border-radius: 4px; font-size: 0.95rem; margin-bottom: 1rem; }
    button { width: 100%; padding: 0.7rem; background: #0073bb; color: #fff; border: none;
      border-radius: 4px; font-size: 1rem; cursor: pointer; }
    button:hover { background: #005a94; }
    .error { color: #d13212; font-size: 0.85rem; margin-bottom: 1rem; }
    .challenge { background: #f0f4f8; border: 1px solid #d5dce6; border-radius: 4px;
      padding: 0.75rem; margin-bottom: 1rem; text-align: center; }
    .challenge-question { font-size: 1.1rem; font-weight: 600; color: #232f3e; margin-bottom: 0.5rem; }
    .challenge-label { font-size: 0.75rem; color: #666; text-transform: uppercase; letter-spacing: 0.5px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Account Settings</h1>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
    <p style="margin-bottom:1rem;font-size:0.9rem;color:#555;">Sign in to manage your MFA settings.</p>
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="hidden" name="challenge_hash" value="{{ challenge_hash }}">
      <input type="hidden" name="action" value="login">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" required autofocus>
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required>
      <div class="challenge">
        <div class="challenge-label">Human verification</div>
        <div class="challenge-question">{{ challenge_question }}</div>
      </div>
      <label for="challenge_answer">Your answer</label>
      <input type="text" id="challenge_answer" name="challenge_answer"
             placeholder="Type the answer" required autocomplete="off">
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>
"""

USER_PAGE_ENROLL = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Account Settings</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f4f6f9; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #fff; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,0.08);
      padding: 2rem; width: 100%; max-width: 420px; margin: 1rem; }
    h1 { font-size: 1.4rem; margin-bottom: 1rem; color: #232f3e; }
    h2 { font-size: 1.1rem; margin: 1.5rem 0 0.75rem; color: #232f3e; border-top: 1px solid #eee; padding-top: 1.5rem; }
    .qr { text-align: center; margin: 1rem 0; }
    .qr img { border: 4px solid #eee; border-radius: 8px; }
    .secret-code { background: #f0f4f8; border: 1px solid #d5dce6; border-radius: 4px;
      padding: 0.5rem; text-align: center; font-family: monospace; font-size: 0.9rem;
      letter-spacing: 2px; margin-bottom: 1rem; word-break: break-all; }
    label { display: block; font-size: 0.85rem; color: #555; margin-bottom: 0.3rem; }
    input[type="text"], input[type="password"] { width: 100%; padding: 0.6rem 0.75rem; border: 1px solid #ccc;
      border-radius: 4px; font-size: 0.95rem; margin-bottom: 1rem; }
    input[type="text"]#totp_code { font-size: 1.2rem; letter-spacing: 0.3rem; text-align: center; }
    button { width: 100%; padding: 0.7rem; background: #0073bb; color: #fff; border: none;
      border-radius: 4px; font-size: 1rem; cursor: pointer; margin-top: 0.5rem; }
    button:hover { background: #005a94; }
    .btn-danger { background: #d13212; }
    .btn-danger:hover { background: #a82610; }
    .error { color: #d13212; font-size: 0.85rem; margin-bottom: 1rem; }
    .success { color: #1d8102; font-size: 0.9rem; margin-bottom: 1rem; }
    .status { background: #e8f5e9; border: 1px solid #a5d6a7; border-radius: 4px;
      padding: 0.75rem; margin-bottom: 1rem; text-align: center; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Account Settings</h1>
    {% if password_success|default(false) %}<p class="success">Password changed successfully.</p>{% endif %}
    {% if password_error|default('') %}<p class="error">{{ password_error }}</p>{% endif %}

    <h2 style="border-top:none;margin-top:0;padding-top:0;">Two-Factor Authentication</h2>
    {% if mfa_enabled %}
      <div class="status">MFA is <strong>enabled</strong> for your account.</div>
      <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="hidden" name="action" value="disable">
        <input type="hidden" name="auth_token" value="{{ auth_token }}">
        <button class="btn-danger">Disable MFA</button>
      </form>
    {% else %}
      {% if error %}<p class="error">{{ error }}</p>{% endif %}
      <p style="margin-bottom:1rem;font-size:0.9rem;color:#555;">Scan this QR code with your authenticator app (Google Authenticator, Authy, 1Password, etc.):</p>
      <div class="qr"><img src="{{ qr_data_uri }}" alt="TOTP QR Code" width="200" height="200"></div>
      <p style="font-size:0.8rem;color:#666;margin-bottom:0.5rem;">Or enter this key manually:</p>
      <div class="secret-code">{{ totp_secret }}</div>
      <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="hidden" name="action" value="enroll">
        <input type="hidden" name="auth_token" value="{{ auth_token }}">
        <input type="hidden" name="totp_secret" value="{{ totp_secret }}">
        <label for="totp_code">Enter the 6-digit code to confirm</label>
        <input type="text" id="totp_code" name="totp_code" maxlength="6" pattern="[0-9]{6}"
               required autofocus autocomplete="one-time-code" inputmode="numeric">
        <button type="submit">Enable MFA</button>
      </form>
    {% endif %}

    <h2>Change Password</h2>
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="hidden" name="action" value="change_password">
      <input type="hidden" name="auth_token" value="{{ auth_token }}">
      <label for="new_password">New password</label>
      <input type="password" id="new_password" name="new_password" required minlength="8">
      <label for="confirm_password">Confirm new password</label>
      <input type="password" id="confirm_password" name="confirm_password" required minlength="8">
      <button type="submit">Change Password</button>
    </form>
  </div>
</body>
</html>
"""


def _check_password(stored: str, provided: str) -> bool:
    """Check a password against a stored value.

    Supports both bcrypt hashes (starting with $2b$) and plaintext passwords
    (for backward compatibility). Plaintext comparison uses constant-time
    comparison to avoid timing attacks.
    """
    if stored.startswith("$2b$"):
        import bcrypt

        return bcrypt.checkpw(provided.encode(), stored.encode())
    # Plaintext fallback — constant-time comparison
    return hmac.compare_digest(stored, provided)


class _RateLimiter:
    """Simple in-memory rate limiter per IP address."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 60) -> None:
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)

    def is_limited(self, key: str) -> bool:
        now = time.time()
        attempts = self._attempts[key]
        # Prune old entries
        self._attempts[key] = [t for t in attempts if now - t < self.window]
        return len(self._attempts[key]) >= self.max_attempts

    def record(self, key: str) -> None:
        self._attempts[key].append(time.time())


def _generate_challenge(secret: str) -> tuple[str, str, str]:
    """Generate a math challenge and its signed hash.

    Returns (question_text, correct_answer, challenge_hash).
    The hash is HMAC(secret, answer) so the server can verify without storing state.
    """
    ops = [
        ("+", lambda a, b: a + b),
        ("-", lambda a, b: a - b),
        ("×", lambda a, b: a * b),
    ]
    op_symbol, op_func = random.choice(ops)  # nosec B311
    a = random.randint(1, 20)  # nosec B311
    b = random.randint(1, 12)  # nosec B311

    # Ensure subtraction doesn't go negative
    if op_symbol == "-" and a < b:
        a, b = b, a

    answer = str(op_func(a, b))
    question = f"What is {a} {op_symbol} {b}?"
    challenge_hash = hmac.new(
        secret.encode(), answer.encode(), hashlib.sha256
    ).hexdigest()

    return question, answer, challenge_hash


def _verify_challenge(secret: str, answer: str, expected_hash: str) -> bool:
    """Verify a challenge answer against its signed hash."""
    computed = hmac.new(
        secret.encode(), answer.strip().encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed, expected_hash)


def _load_users(users_path: Path) -> dict[str, Any]:
    """Load users from a JSON file."""
    return {u["username"]: u for u in json.loads(users_path.read_text())}


def _save_users(users_path: Path, users: dict[str, Any]) -> None:
    """Save the users dict back to the JSON file."""
    user_list = list(users.values())
    users_path.write_text(json.dumps(user_list, indent=2) + "\n")


def create_app(
    data_dir: str,
    *,
    host: str = "127.0.0.1",
    port: int = 5000,
    provider_name: str = "local-idp",
    session_duration_hours: int = 1,
    secret_key: str | None = None,
    rate_limit_max_attempts: int = 5,
    rate_limit_window_seconds: int = 60,
    users_file: str = "users.json",
    certificate_file: str = "idp.crt",
    private_key_file: str = "idp.key",
    adfs_config: dict[str, str] | None = None,
    group_role_map: dict[str, list[dict[str, str]]] | None = None,
    skip_ldap_ssl_verify: bool = False,
) -> Flask:
    """Flask application factory.

    Args:
        data_dir: Path to directory containing data files.
        host: Bind host — used to derive the IdP entity ID.
        port: Bind port — used to derive the IdP entity ID.
        provider_name: SAML provider name registered in AWS IAM.
        session_duration_hours: SAML assertion validity in hours (1–12).
        secret_key: Flask secret key for CSRF tokens. Auto-generated if None.
        rate_limit_max_attempts: Max failed login attempts per IP before limiting.
        rate_limit_window_seconds: Rate limit window in seconds.
        users_file: Filename or path to users JSON file (relative to data_dir).
        certificate_file: Filename or path to signing certificate (relative to data_dir).
        private_key_file: Filename or path to private key (relative to data_dir).
        adfs_config: ADFS/LDAP connection config dict (enables ADFS auth mode).
        group_role_map: Mapping of AD group names to AWS role dicts (used with ADFS).
        skip_ldap_ssl_verify: If True, disable TLS certificate verification for LDAP.
    """
    data = Path(data_dir)

    def _resolve(filename: str) -> Path:
        p = Path(filename)
        return p if p.is_absolute() else data / p

    cert_pem = _resolve(certificate_file).read_text()
    key_pem = _resolve(private_key_file).read_text()

    # ADFS mode: authenticate via LDAP, no local users.json needed
    use_adfs = adfs_config is not None
    if use_adfs:
        users = {}
        users_path = None
        users_mtime = 0.0
        users_size = 0
        _group_role_map = group_role_map or {}
        logger.info("ADFS authentication mode enabled (host=%s)", adfs_config.get("host"))
    else:
        users_path = _resolve(users_file)
        users = _load_users(users_path)
        _stat = users_path.stat()
        users_mtime = _stat.st_mtime
        users_size = _stat.st_size
        _group_role_map = {}

    idp_entity_id = f"http://{host}:{port}/metadata"
    if port == 443:
        idp_entity_id = f"https://{host}/metadata"
    elif port == 80:
        idp_entity_id = f"http://{host}/metadata"
    cert_b64 = "".join(cert_pem.strip().splitlines()[1:-1])

    app = Flask(__name__)
    app.secret_key = secret_key or os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    rate_limiter = _RateLimiter(
        max_attempts=rate_limit_max_attempts, window_seconds=rate_limit_window_seconds
    )

    # Store config on app for access in tests
    app.config["IDP_ENTITY_ID"] = idp_entity_id
    app.config["PROVIDER_NAME"] = provider_name
    app.config["SESSION_DURATION_HOURS"] = session_duration_hours

    def _generate_csrf_token() -> str:
        """Generate a CSRF token tied to the app secret."""
        return secrets.token_hex(32)

    def _make_challenge() -> tuple[str, str]:
        """Generate a challenge question and its verification hash."""
        question, _answer, challenge_hash = _generate_challenge(app.secret_key)
        return question, challenge_hash

    def _reload_users_if_changed() -> None:
        """Reload users.json if the file has been modified."""
        nonlocal users, users_mtime, users_size
        if use_adfs or users_path is None:
            return
        try:
            stat = users_path.stat()
            if stat.st_mtime != users_mtime or stat.st_size != users_size:
                users = _load_users(users_path)
                users_mtime = stat.st_mtime
                users_size = stat.st_size
                logger.info("Reloaded users.json (file changed)")
        except OSError:
            logger.warning("Could not stat users.json for hot-reload check")

    @app.get("/health")
    def health():
        """Health check endpoint."""
        return {"status": "healthy"}, 200

    # --- Load service providers ---
    services_path = data / "services.yaml"
    _services = load_services(
        str(data),
        default_provider_name=provider_name,
        default_session_duration_hours=session_duration_hours,
    )
    _services_mtime = services_path.stat().st_mtime if services_path.is_file() else 0.0

    # --- Load claim-to-role mapping ---
    import yaml as _yaml
    claim_roles_path = data / "claim_roles.yaml"
    _claim_roles: dict[str, list[dict[str, str]]] = {}
    if claim_roles_path.is_file():
        _claim_roles = _yaml.safe_load(claim_roles_path.read_text()) or {}
        logger.info("Loaded claim_roles.yaml (%d claims mapped)", len(_claim_roles))

    def _resolve_roles_from_claims(user: dict[str, Any]) -> list[dict[str, str]]:
        """Resolve AWS roles from a user's claims + direct roles array."""
        roles: list[dict[str, str]] = []
        seen = set()
        # Roles from claims
        for claim in user.get("claims", []):
            for role in _claim_roles.get(claim, []):
                key = (role["account_id"], role["role"])
                if key not in seen:
                    roles.append(role)
                    seen.add(key)
        # Direct roles (backward compat)
        for role in user.get("roles", []):
            key = (role["account_id"], role["role"])
            if key not in seen:
                roles.append(role)
                seen.add(key)
        return roles

    def _reload_services_if_changed() -> None:
        """Reload services.yaml if modified."""
        nonlocal _services, _services_mtime
        if not services_path.is_file():
            return
        try:
            current_mtime = services_path.stat().st_mtime
            if current_mtime > _services_mtime:
                _services = load_services(
                    str(data),
                    default_provider_name=provider_name,
                    default_session_duration_hours=session_duration_hours,
                )
                _services_mtime = current_mtime
                logger.info("Reloaded services.yaml (file changed)")
        except (OSError, ValueError) as e:
            logger.warning("Could not reload services.yaml: %s", e)

    @app.before_request
    def _before_request() -> None:
        _reload_users_if_changed()
        _reload_services_if_changed()

    def _get_service(path: str) -> ServiceProvider | None:
        """Look up a service provider by path."""
        if _services:
            for sp in _services:
                if sp.path == path:
                    return sp
        return None

    def _authenticate_user(username: str, password: str) -> tuple[bool, list | None]:
        """Authenticate a user. Returns (success, roles_or_groups)."""
        if use_adfs:
            from .adfs import authenticate_adfs

            groups = authenticate_adfs(
                username, password, adfs_config,
                skip_ssl_verify=skip_ldap_ssl_verify,  # type: ignore[arg-type]
            )
            if groups is None:
                return False, None
            return True, groups
        else:
            user = users.get(username)
            if not user or not _check_password(user["password"], password):
                return False, None
            return True, _resolve_roles_from_claims(user)

    def _handle_login_form(service_path: str):
        """Render the login form for a service path."""
        # Check for valid session cookie — skip login if remembered
        session_user = _verify_session_cookie(request.cookies.get(SESSION_COOKIE_NAME, ""))
        if session_user and not use_adfs:
            user = users.get(session_user)
            if user:
                sp = _get_service(service_path)
                roles = _resolve_roles_from_claims(user)
                if sp and sp.protocol == "oauth":
                    token = build_oauth_token(
                        session_user, key_pem, idp_entity_id,
                        client_id=sp.client_id, scopes=sp.scopes,
                        token_expiry_minutes=sp.token_expiry_minutes, groups=None,
                        claims=user.get("claims", []),
                        email=user.get("email"),
                    )
                    separator = "&" if "?" in sp.url else "?"
                    return redirect(f"{sp.url}{separator}token={token}")
                else:
                    sp_acs_url = sp.url if sp else ACS_URL
                    sp_provider = sp.provider_name if sp else provider_name
                    sp_duration = sp.session_duration_hours if sp else session_duration_hours
                    sp_audience = (sp.audience if sp and sp.audience else "urn:amazon:webservices")
                    saml_b64 = build_saml_response(
                        session_user, roles, cert_pem, key_pem, idp_entity_id,
                        provider_name=sp_provider, session_duration_hours=sp_duration,
                        acs_url=sp_acs_url, audience=sp_audience,
                    )
                    return render_template_string(SAML_POST, acs=sp_acs_url, saml=saml_b64)

        sp = _get_service(service_path)
        title = service_path.upper() if sp else "AWS Console"
        token = _generate_csrf_token()
        question, challenge_hash = _make_challenge()
        response = render_template_string(
            LOGIN_FORM,
            error=None,
            csrf_token=token,
            challenge_question=question,
            challenge_hash=challenge_hash,
            service_title=title,
        )
        resp = app.make_response(response)
        resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
        return resp

    def _handle_login_post(service_path: str):
        """Handle login POST for a service path."""
        sp = _get_service(service_path)

        # CSRF validation
        form_token = request.form.get("csrf_token", "")
        cookie_token = request.cookies.get("csrf_token", "")
        title = service_path.upper() if sp else "AWS Console"
        if not form_token or not hmac.compare_digest(form_token, cookie_token):
            question, challenge_hash = _make_challenge()
            return render_template_string(
                LOGIN_FORM,
                error="Invalid request (CSRF)",
                csrf_token=_generate_csrf_token(),
                challenge_question=question,
                challenge_hash=challenge_hash,
                service_title=title,
            ), 403

        # Rate limiting
        client_ip = request.remote_addr or "unknown"
        if rate_limiter.is_limited(client_ip):
            logger.warning("Rate limited: %s", client_ip)
            token = _generate_csrf_token()
            question, challenge_hash = _make_challenge()
            return render_template_string(
                LOGIN_FORM,
                error="Too many attempts. Try again later.",
                csrf_token=token,
                challenge_question=question,
                challenge_hash=challenge_hash,
                service_title=title,
            ), 429

        # Human verification
        challenge_answer = request.form.get("challenge_answer", "")
        challenge_hash_val = request.form.get("challenge_hash", "")

        # Check if this is a TOTP verification step (second factor) — skip challenge
        totp_step = request.form.get("totp_step", "")
        if totp_step == "1":
            # Verify TOTP code
            totp_code = request.form.get("totp_code", "")
            auth_username = request.form.get("username", "")
            user = users.get(auth_username)
            if not user or not user.get("totp_secret"):
                question, new_hash = _make_challenge()
                return render_template_string(
                    LOGIN_FORM,
                    error="Invalid request",
                    csrf_token=_generate_csrf_token(),
                    challenge_question=question,
                    challenge_hash=new_hash,
                    service_title=title,
                ), 401

            if not verify_code(user["totp_secret"], totp_code):
                rate_limiter.record(client_ip)
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    TOTP_FORM,
                    error="Invalid code. Try again.",
                    csrf_token=token,
                    username=auth_username,
                    service_path=service_path,
                ))
                resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                return resp, 401

            # TOTP verified — proceed with token issuance
            username = auth_username
            if use_adfs:
                from .adfs import groups_to_roles
                roles = groups_to_roles([], _group_role_map)
                groups = []
            else:
                roles = _resolve_roles_from_claims(user)
                groups = None

            logger.info(
                "Successful MFA login: user=%s service=%s from ip=%s",
                username, service_path, client_ip,
            )

            # Issue the token
            if sp and sp.protocol == "oauth":
                token = build_oauth_token(
                    username, key_pem, idp_entity_id,
                    client_id=sp.client_id, scopes=sp.scopes,
                    token_expiry_minutes=sp.token_expiry_minutes, groups=groups,
                    claims=users.get(username, {}).get("claims", []),
                    email=users.get(username, {}).get("email"),
                )
                separator = "&" if "?" in sp.url else "?"
                resp = redirect(f"{sp.url}{separator}token={token}")
                _set_session_cookie(resp, username)
                return resp
            else:
                if use_adfs and not roles:
                    question, new_hash = _make_challenge()
                    return render_template_string(
                        LOGIN_FORM,
                        error="No roles mapped to your groups. Contact your administrator.",
                        csrf_token=_generate_csrf_token(),
                        challenge_question=question,
                        challenge_hash=new_hash,
                        service_title=title,
                    ), 403
                sp_acs_url = sp.url if sp else ACS_URL
                sp_provider = sp.provider_name if sp else provider_name
                sp_duration = sp.session_duration_hours if sp else session_duration_hours
                sp_audience = (sp.audience if sp and sp.audience else "urn:amazon:webservices")
                saml_b64 = build_saml_response(
                    username, roles, cert_pem, key_pem, idp_entity_id,
                    provider_name=sp_provider, session_duration_hours=sp_duration,
                    acs_url=sp_acs_url, audience=sp_audience,
                )
                resp = app.make_response(
                    render_template_string(SAML_POST, acs=sp_acs_url, saml=saml_b64)
                )
                _set_session_cookie(resp, username)
                return resp

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        success, auth_result = _authenticate_user(username, password)
        if not success:
            rate_limiter.record(client_ip)
            logger.info("Failed login for user=%s from ip=%s", username, client_ip)
            question, new_hash = _make_challenge()
            return render_template_string(
                LOGIN_FORM,
                error="Invalid credentials",
                csrf_token=_generate_csrf_token(),
                challenge_question=question,
                challenge_hash=new_hash,
                service_title=title,
            ), 401

        # If user has MFA, skip captcha (TOTP proves they're human).
        # If no MFA, enforce the captcha.
        user_has_mfa = False
        if not use_adfs:
            user = users.get(username)
            user_has_mfa = bool(user and user.get("totp_secret"))

        if not user_has_mfa:
            if not _verify_challenge(app.secret_key, challenge_answer, challenge_hash_val):
                rate_limiter.record(client_ip)
                logger.info("Failed challenge from ip=%s", client_ip)
                question, new_hash = _make_challenge()
                return render_template_string(
                    LOGIN_FORM,
                    error="Incorrect answer — please try again.",
                    csrf_token=_generate_csrf_token(),
                    challenge_question=question,
                    challenge_hash=new_hash,
                    service_title=title,
                ), 401

        # Resolve roles for ADFS mode
        if use_adfs:
            from .adfs import groups_to_roles

            roles = groups_to_roles(auth_result, _group_role_map)  # type: ignore[arg-type]
            groups = auth_result
        else:
            roles = auth_result  # type: ignore[assignment]
            groups = None

        # Check if MFA is required (user has totp_secret)
        if not use_adfs:
            user = users.get(username)
            if user and user.get("totp_secret"):
                # Show TOTP form instead of issuing token
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    TOTP_FORM,
                    error=None,
                    csrf_token=token,
                    username=username,
                    service_path=service_path,
                ))
                resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                return resp

        logger.info(
            "Successful login: user=%s service=%s from ip=%s",
            username, service_path, client_ip,
        )

        # Determine protocol and respond accordingly
        if sp and sp.protocol == "oauth":
            # OAuth: issue JWT and redirect
            token = build_oauth_token(
                username,
                key_pem,
                idp_entity_id,
                client_id=sp.client_id,
                scopes=sp.scopes,
                token_expiry_minutes=sp.token_expiry_minutes,
                groups=groups,
                claims=users.get(username, {}).get("claims", []),
                email=users.get(username, {}).get("email"),
            )
            separator = "&" if "?" in sp.url else "?"
            return redirect(f"{sp.url}{separator}token={token}")
        else:
            # SAML: build assertion and auto-POST
            if use_adfs and not roles:
                question, new_hash = _make_challenge()
                return render_template_string(
                    LOGIN_FORM,
                    error="No roles mapped to your groups. Contact your administrator.",
                    csrf_token=_generate_csrf_token(),
                    challenge_question=question,
                    challenge_hash=new_hash,
                    service_title=title,
                ), 403

            sp_acs_url = sp.url if sp else ACS_URL
            sp_provider = sp.provider_name if sp else provider_name
            sp_duration = sp.session_duration_hours if sp else session_duration_hours
            sp_audience = (sp.audience if sp and sp.audience else "urn:amazon:webservices")

            saml_b64 = build_saml_response(
                username,
                roles,  # type: ignore[arg-type]
                cert_pem,
                key_pem,
                idp_entity_id,
                provider_name=sp_provider,
                session_duration_hours=sp_duration,
                acs_url=sp_acs_url,
                audience=sp_audience,
            )
            return render_template_string(SAML_POST, acs=sp_acs_url, saml=saml_b64)

    def _issue_auth_token(username: str) -> str:
        """Issue a short-lived HMAC token proving the user authenticated."""
        payload = f"{username}:{int(time.time())}"
        sig = hmac.new(app.secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}:{sig}"

    def _verify_auth_token(token: str, max_age: int = 300) -> str | None:
        """Verify an auth token and return the username if valid (within max_age seconds)."""
        parts = token.rsplit(":", 1)
        if len(parts) != 2:
            return None
        payload, sig = parts
        expected = hmac.new(app.secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        user_parts = payload.rsplit(":", 1)
        if len(user_parts) != 2:
            return None
        username, ts_str = user_parts
        try:
            ts = int(ts_str)
        except ValueError:
            return None
        if time.time() - ts > max_age:
            return None
        return username

    SESSION_COOKIE_NAME = "idp_session"
    SESSION_MAX_AGE = 12 * 3600  # 12 hours

    def _issue_session_cookie(username: str) -> str:
        """Issue a signed session cookie value (username + timestamp + HMAC)."""
        payload = f"{username}:{int(time.time())}"
        sig = hmac.new(app.secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}:{sig}"

    def _verify_session_cookie(cookie_val: str) -> str | None:
        """Verify session cookie. Returns username if valid and not expired."""
        if not cookie_val:
            return None
        parts = cookie_val.rsplit(":", 1)
        if len(parts) != 2:
            return None
        payload, sig = parts
        expected = hmac.new(app.secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        user_parts = payload.rsplit(":", 1)
        if len(user_parts) != 2:
            return None
        username, ts_str = user_parts
        try:
            ts = int(ts_str)
        except ValueError:
            return None
        if time.time() - ts > SESSION_MAX_AGE:
            return None
        return username

    def _set_session_cookie(resp, username: str):
        """Set the session cookie on a response."""
        resp.set_cookie(
            SESSION_COOKIE_NAME,
            _issue_session_cookie(username),
            max_age=SESSION_MAX_AGE,
            httponly=True,
            samesite="Strict",
        )

    # --- /user route for MFA enrollment ---
    @app.get("/user")
    def user_page_get():
        """Show login form for account settings."""
        token = _generate_csrf_token()
        question, challenge_hash = _make_challenge()
        resp = app.make_response(render_template_string(
            USER_PAGE_LOGIN, error=None, csrf_token=token,
            challenge_question=question, challenge_hash=challenge_hash,
        ))
        resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
        return resp

    @app.post("/user")
    def user_page_post():
        """Handle account settings actions."""
        form_token = request.form.get("csrf_token", "")
        cookie_token = request.cookies.get("csrf_token", "")
        if not form_token or not hmac.compare_digest(form_token, cookie_token):
            token = _generate_csrf_token()
            resp = app.make_response(render_template_string(
                USER_PAGE_LOGIN, error="Invalid request (CSRF)", csrf_token=token,
            ))
            resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
            return resp, 403

        action = request.form.get("action", "login")

        # Handle TOTP verification for /user access (from TOTP_FORM)
        totp_step = request.form.get("totp_step", "")
        if totp_step == "1" and request.form.get("service_path") == "user":
            username = request.form.get("username", "")
            totp_code = request.form.get("totp_code", "")
            user = users.get(username)
            if not user or not user.get("totp_secret"):
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    USER_PAGE_LOGIN, error="Invalid request. Please sign in again.",
                    csrf_token=token,
                ))
                resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                return resp, 401

            if not verify_code(user["totp_secret"], totp_code):
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    TOTP_FORM,
                    error="Invalid code. Try again.",
                    csrf_token=token,
                    username=username,
                    service_path="user",
                ))
                resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                return resp, 401

            # TOTP verified — show settings page
            auth_token = _issue_auth_token(username)
            token = _generate_csrf_token()
            resp = app.make_response(render_template_string(
                USER_PAGE_ENROLL,
                mfa_enabled=True,
                csrf_token=token,
                auth_token=auth_token,
                qr_data_uri="",
                totp_secret="",
                error=None,
            ))
            resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
            return resp

        if action == "login":
            # Verify challenge
            challenge_answer = request.form.get("challenge_answer", "")
            challenge_hash_val = request.form.get("challenge_hash", "")
            if not _verify_challenge(app.secret_key, challenge_answer, challenge_hash_val):
                token = _generate_csrf_token()
                question, ch_hash = _make_challenge()
                resp = app.make_response(render_template_string(
                    USER_PAGE_LOGIN, error="Incorrect answer — please try again.",
                    csrf_token=token, challenge_question=question, challenge_hash=ch_hash,
                ))
                resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                return resp, 401

            username = request.form.get("username", "")
            password = request.form.get("password", "")
            user = users.get(username)
            if not user or not _check_password(user["password"], password):
                token = _generate_csrf_token()
                question, ch_hash = _make_challenge()
                resp = app.make_response(render_template_string(
                    USER_PAGE_LOGIN, error="Invalid credentials", csrf_token=token,
                    challenge_question=question, challenge_hash=ch_hash,
                ))
                resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                return resp, 401

            # If MFA is enabled, require TOTP before granting access
            mfa_enabled = bool(user.get("totp_secret"))
            if mfa_enabled:
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    TOTP_FORM,
                    error=None,
                    csrf_token=token,
                    username=username,
                    service_path="user",
                ))
                resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                return resp

            # No MFA — go straight to enrollment page
            auth_token = _issue_auth_token(username)
            token = _generate_csrf_token()
            secret = generate_secret()
            uri = provisioning_uri(secret, username, issuer="idp.botthouse.net")
            qr_uri = qr_code_data_uri(uri)
            resp = app.make_response(render_template_string(
                USER_PAGE_ENROLL,
                mfa_enabled=False,
                csrf_token=token,
                auth_token=auth_token,
                qr_data_uri=qr_uri,
                totp_secret=secret,
                error=None,
            ))
            resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
            return resp

        elif action == "enroll":
            auth_token = request.form.get("auth_token", "")
            username = _verify_auth_token(auth_token)
            if not username:
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    USER_PAGE_LOGIN, error="Session expired. Please sign in again.",
                    csrf_token=token,
                ))
                resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                return resp, 401

            totp_secret = request.form.get("totp_secret", "")
            totp_code = request.form.get("totp_code", "")

            if not totp_secret or not verify_code(totp_secret, totp_code):
                # Re-show the enrollment page with the same secret
                uri = provisioning_uri(totp_secret, username, issuer="idp.botthouse.net")
                qr_uri = qr_code_data_uri(uri)
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    USER_PAGE_ENROLL,
                    mfa_enabled=False,
                    csrf_token=token,
                    auth_token=_issue_auth_token(username),
                    qr_data_uri=qr_uri,
                    totp_secret=totp_secret,
                    error="Invalid code. Try again.",
                ))
                resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                return resp, 401

            # Save the TOTP secret to the user
            user = users.get(username)
            if user and users_path:
                user["totp_secret"] = totp_secret
                _save_users_and_update_mtime(users_path, users)
                logger.info("MFA enrolled for user=%s", username)

            token = _generate_csrf_token()
            resp = app.make_response(render_template_string(
                USER_PAGE_ENROLL,
                mfa_enabled=True,
                csrf_token=token,
                auth_token=_issue_auth_token(username),
                qr_data_uri="",
                totp_secret="",
                error=None,
            ))
            resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
            return resp

        elif action == "disable":
            auth_token = request.form.get("auth_token", "")
            username = _verify_auth_token(auth_token)
            if not username:
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    USER_PAGE_LOGIN, error="Session expired. Please sign in again.",
                    csrf_token=token,
                ))
                resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                return resp, 401

            user = users.get(username)
            if user and users_path:
                user.pop("totp_secret", None)
                _save_users_and_update_mtime(users_path, users)
                logger.info("MFA disabled for user=%s", username)

            token = _generate_csrf_token()
            resp = app.make_response(render_template_string(
                USER_PAGE_ENROLL,
                mfa_enabled=False,
                csrf_token=token,
                auth_token=_issue_auth_token(username),
                qr_data_uri=qr_code_data_uri(
                    provisioning_uri(generate_secret(), username, issuer="idp.botthouse.net")
                ),
                totp_secret=generate_secret(),
                error=None,
            ))
            resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
            return resp

        elif action == "change_password":
            auth_token = request.form.get("auth_token", "")
            username = _verify_auth_token(auth_token)
            if not username:
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    USER_PAGE_LOGIN, error="Session expired. Please sign in again.",
                    csrf_token=token,
                ))
                resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                return resp, 401

            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            # Validation
            password_error = None
            if not new_password or len(new_password) < 8:
                password_error = "Password must be at least 8 characters."
            elif new_password != confirm_password:
                password_error = "Passwords do not match."

            user = users.get(username)
            mfa_enabled = bool(user.get("totp_secret")) if user else False

            if password_error:
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    USER_PAGE_ENROLL,
                    mfa_enabled=mfa_enabled,
                    csrf_token=token,
                    auth_token=_issue_auth_token(username),
                    qr_data_uri="" if mfa_enabled else qr_code_data_uri(
                        provisioning_uri(generate_secret(), username, issuer="idp.botthouse.net")
                    ),
                    totp_secret="" if mfa_enabled else generate_secret(),
                    error=None,
                    password_error=password_error,
                ))
                resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                return resp

            # Hash and save the new password
            import bcrypt as _bcrypt
            hashed = _bcrypt.hashpw(new_password.encode(), _bcrypt.gensalt()).decode()
            if user and users_path:
                user["password"] = hashed
                _save_users_and_update_mtime(users_path, users)
                logger.info("Password changed for user=%s", username)

            token = _generate_csrf_token()
            resp = app.make_response(render_template_string(
                USER_PAGE_ENROLL,
                mfa_enabled=mfa_enabled,
                csrf_token=token,
                auth_token=_issue_auth_token(username),
                qr_data_uri="" if mfa_enabled else qr_code_data_uri(
                    provisioning_uri(generate_secret(), username, issuer="idp.botthouse.net")
                ),
                totp_secret="" if mfa_enabled else generate_secret(),
                error=None,
                password_success=True,
            ))
            resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
            return resp

        # Unknown action — redirect to login
        token = _generate_csrf_token()
        resp = app.make_response(render_template_string(
            USER_PAGE_LOGIN, error=None, csrf_token=token,
        ))
        resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
        return resp

    # --- Register routes ---
    if _services:
        # Dynamic routes from services.yaml
        for sp in _services:

            def _make_get(path: str):
                def _get():
                    return _handle_login_form(path)
                _get.__name__ = f"login_form_{path}"
                return _get

            def _make_post(path: str):
                def _post():
                    return _handle_login_post(path)
                _post.__name__ = f"login_post_{path}"
                return _post

            def _make_logout(path: str):
                def _logout():
                    resp = app.make_response(render_template_string(
                        LOGOUT_PAGE, service_path=path,
                    ))
                    resp.delete_cookie(SESSION_COOKIE_NAME)
                    resp.delete_cookie("csrf_token")
                    return resp
                _logout.__name__ = f"logout_{path}"
                return _logout

            app.add_url_rule(
                f"/{sp.path}", endpoint=f"get_{sp.path}",
                view_func=_make_get(sp.path), methods=["GET"],
            )
            app.add_url_rule(
                f"/{sp.path}", endpoint=f"post_{sp.path}",
                view_func=_make_post(sp.path), methods=["POST"],
            )
            app.add_url_rule(
                f"/{sp.path}/logout", endpoint=f"logout_{sp.path}",
                view_func=_make_logout(sp.path), methods=["GET"],
            )
    else:
        # Fallback: single /aws route (backward compatible)
        @app.get("/aws")
        def login_form():
            return _handle_login_form("aws")

        @app.post("/aws")
        def login_post():
            return _handle_login_post("aws")

        @app.get("/aws/logout")
        def logout_aws():
            resp = app.make_response(render_template_string(
                LOGOUT_PAGE, service_path="aws",
            ))
            resp.delete_cookie(SESSION_COOKIE_NAME)
            resp.delete_cookie("csrf_token")
            return resp

    @app.get("/metadata")
    def metadata():
        # Build SSO service entries for all SAML service providers
        sso_entries = ""
        if _services:
            for sp in _services:
                if sp.protocol == "saml":
                    sso_entries += (
                        f'    <SingleSignOnService '
                        f'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
                        f'Location="{idp_entity_id.replace("/metadata", "/" + sp.path)}"/>\n'
                    )
        else:
            sso_entries = (
                f'    <SingleSignOnService '
                f'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
                f'Location="{idp_entity_id.replace("/metadata", "/aws")}"/>\n'
            )

        xml = f"""<?xml version="1.0"?>
<EntityDescriptor entityID="{idp_entity_id}"
  xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor WantAuthnRequestsSigned="false"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>{cert_b64}</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
{sso_entries}  </IDPSSODescriptor>
</EntityDescriptor>"""
        return app.response_class(xml, mimetype="application/xml")

    # --- Recovery route ---
    @app.get("/recover/<recovery_token>")
    def recover_get(recovery_token: str):
        from .admin import validate_recovery_token, consume_recovery_token
        username = validate_recovery_token(recovery_token)
        if not username:
            return render_template_string(
                RECOVERY_PAGE, username="", recovery_token="",
                error="This recovery link is invalid or has expired.",
                success=None, qr_data_uri="", totp_secret="",
            ), 404

        # Generate TOTP secret for optional MFA enrollment
        totp_secret = generate_secret()
        uri = provisioning_uri(totp_secret, username, issuer="idp.botthouse.net")
        qr_uri = qr_code_data_uri(uri)

        return render_template_string(
            RECOVERY_PAGE, username=username, recovery_token=recovery_token,
            error=None, success=None, qr_data_uri=qr_uri, totp_secret=totp_secret,
        )

    @app.post("/recover/<recovery_token>")
    def recover_post(recovery_token: str):
        from .admin import validate_recovery_token, consume_recovery_token
        username = validate_recovery_token(recovery_token)
        if not username:
            return render_template_string(
                RECOVERY_PAGE, username="", recovery_token="",
                error="This recovery link is invalid or has expired.",
                success=None, qr_data_uri="", totp_secret="",
            ), 404

        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        totp_secret = request.form.get("totp_secret", "")
        totp_code = request.form.get("totp_code", "")

        # Validate password
        if len(new_password) < 8:
            uri = provisioning_uri(totp_secret, username, issuer="idp.botthouse.net")
            return render_template_string(
                RECOVERY_PAGE, username=username, recovery_token=recovery_token,
                error="Password must be at least 8 characters.",
                success=None, qr_data_uri=qr_code_data_uri(uri), totp_secret=totp_secret,
            )
        if new_password != confirm_password:
            uri = provisioning_uri(totp_secret, username, issuer="idp.botthouse.net")
            return render_template_string(
                RECOVERY_PAGE, username=username, recovery_token=recovery_token,
                error="Passwords do not match.",
                success=None, qr_data_uri=qr_code_data_uri(uri), totp_secret=totp_secret,
            )

        # Validate TOTP if provided
        mfa_enrolled = False
        if totp_code and totp_secret:
            if not verify_code(totp_secret, totp_code):
                uri = provisioning_uri(totp_secret, username, issuer="idp.botthouse.net")
                return render_template_string(
                    RECOVERY_PAGE, username=username, recovery_token=recovery_token,
                    error="Invalid MFA code. Try again.",
                    success=None, qr_data_uri=qr_code_data_uri(uri), totp_secret=totp_secret,
                )
            mfa_enrolled = True

        # Apply changes
        import bcrypt as _bcrypt
        user = users.get(username)
        if user:
            user["password"] = _bcrypt.hashpw(new_password.encode(), _bcrypt.gensalt()).decode()
            if mfa_enrolled:
                user["totp_secret"] = totp_secret
            if users_path:
                _save_users_and_update_mtime(users_path, users)
            logger.info("Recovery completed for user=%s (MFA=%s)", username, mfa_enrolled)

        # Consume the token (single-use)
        consume_recovery_token(recovery_token)

        mfa_msg = " MFA has been enabled." if mfa_enrolled else ""
        return render_template_string(
            RECOVERY_PAGE, username=username, recovery_token="",
            error=None, success=f"Password updated successfully.{mfa_msg} You can now log in.",
            qr_data_uri="", totp_secret="",
        )

    # --- Admin panel ---
    def _save_users_and_update_mtime(path: Path, user_dict: dict[str, Any]) -> None:
        """Save users and update mtime/size tracker so this worker doesn't re-read."""
        nonlocal users_mtime, users_size
        _save_users(path, user_dict)
        _stat = path.stat()
        users_mtime = _stat.st_mtime
        users_size = _stat.st_size

    from .admin import register_admin_routes
    register_admin_routes(
        app, users, users_path, _check_password, _save_users_and_update_mtime,
        make_challenge_fn=_make_challenge,
        verify_challenge_fn=lambda answer, h: _verify_challenge(app.secret_key, answer, h),
        services_path=services_path,
        verify_session_cookie_fn=_verify_session_cookie,
        set_session_cookie_fn=_set_session_cookie,
    )

    return app
