from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
import random
import re
import secrets
import tempfile
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from flask import Flask, Response, g, jsonify, redirect, render_template_string, request

from . import webauthn_flows as wf
from .audit import AuditLogger
from .oauth_builder import build_oauth_token
from .saml_builder import ACS_URL, build_saml_response
from .services import ServiceProvider, load_services
from .tokens import (
    PURPOSE_MFA_PENDING,
    PURPOSE_USER,
    NonceStore,
    issue_session_token,
    issue_token,
    safe_compare,
    verify_session_token,
    verify_token,
)
from .totp import generate_secret, provisioning_uri, qr_code_data_uri, verify_code

logger = logging.getLogger(__name__)

# Sentinel marking a ``create_app`` keyword argument the caller did not supply.
# It is distinct from any legitimate value (including ``None`` and ``""``), so
# the factory can tell "caller omitted this" from "caller passed the literal
# default" and fall back to the ``load_config`` value only in the former case.
_UNSET: Any = object()


class ConfigNotConsumedError(RuntimeError):
    """Raised at startup when a supplied setting could not be applied.

    ``create_app`` loads ``config.yaml`` and ``IDP_*`` env vars itself and uses
    them as defaults. This error fails closed if a setting was supplied by the
    operator yet never threaded through to the running app, so a silently
    ignored configuration value can never masquerade as applied.
    """


# Mapping of each create_app resolution key to the AppConfig attribute path it
# is sourced from, and the env var(s) that supply it. This is the authoritative
# list of settings create_app must thread through from load_config; the guard
# checks every entry so a future field added to the loader but not to the
# resolution block fails closed instead of being silently dropped.
_CONFIG_FIELD_SOURCES: dict[str, tuple[str, str]] = {
    "host": ("server", "host"),
    "port": ("server", "port"),
    "provider_name": ("saml", "provider_name"),
    "session_duration_hours": ("saml", "session_duration_hours"),
    "secret_key": ("security", "secret_key"),
    "audit_chain_key": ("security", "audit_chain_key"),
    "rate_limit_max_attempts": ("security", "rate_limit_max_attempts"),
    "rate_limit_window_seconds": ("security", "rate_limit_window_seconds"),
    "users_file": ("data", "users_file"),
    "certificate_file": ("data", "certificate_file"),
    "private_key_file": ("data", "private_key_file"),
    "trust_proxy": ("server", "trust_proxy"),
    "webauthn_enabled": ("webauthn", "enabled"),
    "webauthn_rp_id": ("webauthn", "rp_id"),
    "webauthn_rp_name": ("webauthn", "rp_name"),
    "webauthn_expected_origin": ("webauthn", "expected_origin"),
}


def _config_supplied(data_dir: str) -> bool:
    """Return True if an operator supplied config via file or env var.

    Args:
        data_dir: The data directory ``create_app`` was given.

    Returns:
        True when ``config.yaml`` exists in ``data_dir`` or any mapped
        ``IDP_*``/``SECRET_KEY`` environment variable is set.
    """
    from .config import CONFIG_FILENAME, ENV_OVERRIDE_MAP

    if (Path(data_dir) / CONFIG_FILENAME).is_file():
        return True
    return any(name in os.environ for name in ENV_OVERRIDE_MAP)


def _assert_config_consumed(
    data_dir: str,
    cfg: Any,
    resolved: dict[str, Any],
) -> None:
    """Fail closed if a supplied setting was never applied to the app.

    ``create_app`` resolves every entry in ``_CONFIG_FIELD_SOURCES`` from
    ``cfg`` into ``resolved``. If the operator supplied configuration (a
    ``config.yaml`` file or any mapped env var) but a mapped field is missing
    from ``resolved`` — i.e. the loader knows the setting yet nothing threaded
    it through — the setting would be silently ignored. This guard logs at
    ERROR and raises so that can never happen.

    A caller override (a CLI launcher passing an explicit value) is NOT an
    error: the field is still present in ``resolved``, so it is counted as
    consumed regardless of whether its value matches ``cfg``.

    Args:
        data_dir: The data directory ``create_app`` was given.
        cfg: The resolved :class:`~identity_provider_server.config.AppConfig`.
        resolved: The final values ``create_app`` will use, keyed by the names
            in ``_CONFIG_FIELD_SOURCES``.

    Raises:
        ConfigNotConsumedError: If config was supplied but a mapped field was
            not present in ``resolved``.
    """
    if not _config_supplied(data_dir):
        return
    missing = [name for name in _CONFIG_FIELD_SOURCES if name not in resolved]
    if missing:
        detail = ", ".join(sorted(missing))
        logger.error(
            "Configuration supplied but these settings were not applied: %s. "
            "Refusing to start with silently ignored configuration.",
            detail,
        )
        raise ConfigNotConsumedError(
            f"Supplied configuration was not consumed: {detail}"
        )
    _ = cfg  # cfg reserved for future value-level consistency checks.


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
    {% if passkey_available|default(false) %}
    <p style="text-align:center;margin:1rem 0 0.5rem;font-size:0.8rem;color:#888;">or</p>
    <button type="button" id="passkey-login"
            data-begin-url="/{{ service_path }}/passkey/begin"
            data-finish-url="/{{ service_path }}/passkey/finish"
            data-csrf="{{ csrf_token }}"
            style="background:#232f3e;">Use a passkey</button>
    <p id="passkey-status" class="error" style="margin-top:0.75rem;"></p>
    <script src="/static/passkey.js?v={{ passkey_js_version }}" defer></script>
    {% endif %}
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
    <p class="subtitle">Hello, {{ username }}. Set your new password{% if qr_data_uri %} and enable MFA{% elif mfa_required %} and confirm your MFA code{% endif %}.</p>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
    {% if success %}<p class="success">{{ success }}</p>{% endif %}

    {% if not success %}
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="hidden" name="recovery_token" value="{{ recovery_token }}">

      <label for="new_password">New password (min 12 characters)</label>
      <input type="password" id="new_password" name="new_password" required minlength="8">
      <label for="confirm_password">Confirm password</label>
      <input type="password" id="confirm_password" name="confirm_password" required minlength="8">

      {% if mfa_required %}
      <h2 style="border-top:none;margin-top:1rem;padding-top:0;">Confirm MFA</h2>
      <p style="font-size:0.85rem;color:#555;margin-bottom:0.75rem;">Enter the current 6-digit code from your authenticator app.</p>
      <label for="totp_code">Authenticator code</label>
      <input type="text" id="totp_code" name="totp_code" maxlength="6" pattern="[0-9]{6}"
             autocomplete="one-time-code" inputmode="numeric" required placeholder="123456">
      {% elif qr_data_uri %}
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
      <input type="hidden" name="mfa_ticket" value="{{ mfa_ticket }}">
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
        <label for="disable_current_password">Confirm current password to disable MFA</label>
        <input type="password" id="disable_current_password" name="current_password"
               required autocomplete="current-password">
        <label for="disable_totp_code">Current authenticator code</label>
        <input type="text" id="disable_totp_code" name="totp_code" maxlength="6"
               pattern="[0-9]{6}" required autocomplete="one-time-code" inputmode="numeric">
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
        <input type="hidden" name="secret_handle" value="{{ secret_handle|default('') }}">
        <label for="enroll_current_password">Confirm current password</label>
        <input type="password" id="enroll_current_password" name="current_password"
               required autocomplete="current-password">
        <label for="totp_code">Enter the 6-digit code to confirm</label>
        <input type="text" id="totp_code" name="totp_code" maxlength="6" pattern="[0-9]{6}"
               required autocomplete="one-time-code" inputmode="numeric">
        <button type="submit">Enable MFA</button>
      </form>
    {% endif %}

    {% if passkey_available|default(false) %}
    <h2>Passkeys</h2>
    <p style="margin-bottom:1rem;font-size:0.9rem;color:#555;">
      Register a passkey (Touch ID, Windows Hello, or a security key) as an
      additional second factor.</p>
    {% set passkeys = passkeys|default([]) %}
    <p id="passkey-empty" style="font-size:0.85rem;color:#777;margin-bottom:1rem;{% if passkeys %}display:none;{% endif %}">No passkeys registered yet.</p>
    <ul id="passkey-list" style="list-style:none;margin-bottom:1rem;">
      {% for pk in passkeys %}
      <li style="display:flex;justify-content:space-between;align-items:center;
                 border:1px solid #eee;border-radius:4px;padding:0.5rem 0.75rem;margin-bottom:0.5rem;">
        <span style="font-size:0.9rem;">{{ pk.label }}</span>
        <form method="post" style="margin:0;width:auto;">
          <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
          <input type="hidden" name="action" value="remove_passkey">
          <input type="hidden" name="auth_token" value="{{ auth_token }}">
          <input type="hidden" name="credential_id" value="{{ pk.credential_id }}">
          <button class="btn-danger" style="width:auto;padding:0.35rem 0.75rem;margin:0;font-size:0.8rem;">Remove</button>
        </form>
      </li>
      {% endfor %}
    </ul>
    <button type="button" id="passkey-register"
            data-begin-url="/user/passkey/register/begin"
            data-finish-url="/user/passkey/register/finish"
            data-csrf="{{ csrf_token }}"
            data-auth-token="{{ auth_token }}">Register a passkey</button>
    <p id="passkey-status" class="error" style="margin-top:0.75rem;"></p>
    <script src="/static/passkey.js?v={{ passkey_js_version }}" defer></script>

    <h2 style="border-top:1px dashed #eee;">Password-less sign-in</h2>
    {% if passwordless_error|default('') %}<p class="error">{{ passwordless_error }}</p>{% endif %}
    {% if passwordless_enabled|default(false) %}
      <div class="status">Password-less sign-in is <strong>enabled</strong>. You can sign in with just a passkey.</div>
      <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="hidden" name="action" value="unset_passwordless">
        <input type="hidden" name="auth_token" value="{{ auth_token }}">
        <button class="btn-danger">Disable password-less sign-in</button>
      </form>
    {% else %}
      <p style="margin-bottom:1rem;font-size:0.9rem;color:#555;">
        Sign in with only a passkey (no password). Requires a recovery path:
        two passkeys, or one passkey plus a password or TOTP.</p>
      <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="hidden" name="action" value="set_passwordless">
        <input type="hidden" name="auth_token" value="{{ auth_token }}">
        <button type="submit" id="passkey-set"{% if not passwordless_eligible|default(false) %} disabled{% endif %}>Enable password-less sign-in</button>
      </form>
    {% endif %}
    {% endif %}

    <h2>Change Password</h2>
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="hidden" name="action" value="change_password">
      <input type="hidden" name="auth_token" value="{{ auth_token }}">
      <label for="current_password">Current password</label>
      <input type="password" id="current_password" name="current_password" required>
      <label for="new_password">New password</label>
      <input type="password" id="new_password" name="new_password" required minlength="12">
      <label for="confirm_password">Confirm new password</label>
      <input type="password" id="confirm_password" name="confirm_password" required minlength="12">
      <button type="submit">Change Password</button>
    </form>
  </div>
</body>
</html>
"""


# Shown after a successful authentication when the account is flagged for a
# forced password change. No SAML/JWT/session is issued until the change
# completes. It carries a short-lived step-up token proving the user just
# authenticated, so the change is bound to this session.
FORCED_CHANGE_PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Password Change Required</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f4f6f9; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #fff; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,0.08);
      padding: 2rem; width: 100%; max-width: 400px; }
    h1 { font-size: 1.3rem; margin-bottom: 0.75rem; color: #232f3e; }
    p.note { font-size: 0.9rem; color: #555; margin-bottom: 1.25rem; }
    label { display: block; font-size: 0.85rem; color: #555; margin: 0.5rem 0 0.3rem; }
    input[type="password"] { width: 100%; padding: 0.6rem 0.75rem; border: 1px solid #ccc;
      border-radius: 4px; font-size: 1rem; }
    button { width: 100%; padding: 0.7rem; margin-top: 1rem; background: #0073bb; color: #fff;
      border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; }
    button:hover { background: #005a94; }
    .error { color: #d13212; font-size: 0.85rem; margin-bottom: 1rem; }
    .success { color: #1a7f37; font-size: 0.9rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Password change required</h1>
    {% if success %}
      <p class="success">{{ success }}</p>
    {% else %}
      <p class="note">Your administrator requires you to set a new password before continuing.</p>
      {% if error %}<p class="error">{{ error }}</p>{% endif %}
      <form method="post" action="/user">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="hidden" name="action" value="force_change">
        <input type="hidden" name="auth_token" value="{{ auth_token }}">
        <label for="current_password">Current password</label>
        <input type="password" id="current_password" name="current_password" required>
        <label for="new_password">New password (min 12 characters)</label>
        <input type="password" id="new_password" name="new_password" required minlength="12">
        <label for="confirm_password">Confirm new password</label>
        <input type="password" id="confirm_password" name="confirm_password" required minlength="12">
        <button type="submit">Change password</button>
      </form>
    {% endif %}
  </div>
</body>
</html>
"""


_BCRYPT_PREFIXES = ("$2a$", "$2b$", "$2y$")
# A valid but non-matching bcrypt hash, used to equalise timing when the stored
# value is unusable so an attacker cannot distinguish that case from a wrong
# password. It is never expected to match any real input.
_DUMMY_BCRYPT_HASH = b"$2b$12$xqbTfXWMEaMp3sym0SL0/.xghcHMx7WPgGncfpJYimAFLypk8ddDm"


def _user_can_login(user: dict[str, Any]) -> bool:
    """Return True if the account is permitted to authenticate.

    Accounts flagged ``must_set_password`` (a freshly seeded admin) or explicitly
    disabled (``enabled == False``) are always refused. Otherwise the account
    must have a usable authentication factor: a stored password, or — for a
    password-less account (Phase 2) — at least one registered passkey.

    This gate is factor-agnostic; the caller still verifies the actual factor
    (a password check, or a passkey assertion). A password-less account with a
    passkey returns True here but fails any password check, so the password path
    stays closed while the passkey path stays open.

    Args:
        user: The user record.

    Returns:
        Whether the account may proceed to a credential check.
    """
    if user.get("must_set_password"):
        return False
    if user.get("enabled") is False:
        return False
    return bool(user.get("password")) or wf.has_passkey(user)


def _check_password(stored: str, provided: str) -> bool:
    """Check a password against a stored bcrypt hash.

    Only bcrypt hashes are accepted. Any stored value that is not a recognised
    bcrypt hash (a seeded plaintext password, or a foreign digest that would
    otherwise be usable as a literal password) is treated as unusable and
    authentication fails. A dummy bcrypt check is still performed so timing does
    not distinguish "no usable hash" from "wrong password".

    Args:
        stored: The stored password value (expected to be a bcrypt hash).
        provided: The candidate password.

    Returns:
        True only if ``stored`` is a bcrypt hash and ``provided`` matches it.
    """
    import bcrypt

    if stored.startswith(_BCRYPT_PREFIXES):
        return bcrypt.checkpw(provided.encode(), stored.encode())
    # Non-bcrypt stored value: refuse, but spend comparable time.
    logger.warning("Rejected login for account with non-bcrypt stored password")
    bcrypt.checkpw(provided.encode(), _DUMMY_BCRYPT_HASH)
    return False


class _RateLimiter:
    """Simple in-memory sliding-window rate limiter, keyed by caller-supplied
    strings (per-IP, per-account, or a composite).

    The key space is attacker-influenced (it includes the submitted username
    and the X-Forwarded-For-derived client IP), so the store is bounded to
    prevent unbounded memory growth (finding idp-20261003 F1):

    * ``is_limited`` never creates an entry — it reads with ``.get`` and only
      ``record`` inserts, so merely *asking about* a key costs nothing.
    * Entries whose window has fully drained are deleted on access.
    * The total number of keys is capped at ``max_keys``; when full, the
      oldest-touched key is evicted (LRU), so the dict cannot grow without
      bound even under a high-cardinality probe.
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 60,
        max_keys: int = 10000,
    ) -> None:
        self.max_attempts = max_attempts
        self.window = window_seconds
        self.max_keys = max_keys
        # OrderedDict preserves insertion/touch order for cheap LRU eviction.
        self._attempts: OrderedDict[str, list[float]] = OrderedDict()

    def _prune_key(self, key: str, now: float) -> list[float]:
        """Return the live timestamps for ``key``; delete the entry if empty."""
        attempts = [t for t in self._attempts.get(key, ()) if now - t < self.window]
        if attempts:
            self._attempts[key] = attempts
            self._attempts.move_to_end(key)
        else:
            self._attempts.pop(key, None)
        return attempts

    def is_limited(self, key: str) -> bool:
        return len(self._prune_key(key, time.time())) >= self.max_attempts

    def record(self, key: str) -> None:
        now = time.time()
        attempts = self._prune_key(key, now)
        attempts.append(now)
        self._attempts[key] = attempts
        self._attempts.move_to_end(key)
        # Enforce the hard key cap, evicting the least-recently-touched entries.
        while len(self._attempts) > self.max_keys:
            self._attempts.popitem(last=False)


MIN_PASSWORD_LENGTH = 12

# Durable account lockout. The sliding-window rate limiter bounds burst guessing
# but self-clears after its window; these settings add a persisted lockout so a
# patient attacker cannot simply pace their attempts under the window.
LOCKOUT_THRESHOLD = 10  # consecutive failures before the account is locked
LOCKOUT_DURATION_SECONDS = 30 * 60  # 30-minute hold once locked

# Password history: reject reuse of the last N bcrypt hashes (includes the
# current one), closing the "alternate between two passwords" gap.
PASSWORD_HISTORY_SIZE = 5


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string (lifecycle stamps)."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _password_policy_error(password: str) -> str | None:
    """Validate a password against the complexity policy.

    Requires at least ``MIN_PASSWORD_LENGTH`` characters and a mix of character
    classes (lower, upper, digit, symbol — at least three of the four).

    Args:
        password: The candidate password.

    Returns:
        An error message if the password is unacceptable, else ``None``.
    """
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    classes = sum(
        bool(match)
        for match in (
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        )
    )
    if classes < 3:
        return (
            "Password must include at least three of: lowercase, uppercase, "
            "digit, symbol."
        )
    return None


_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]+$")
_CLAIM_RE = re.compile(r"^[a-z0-9_-]+$")


def _validate_username(username: str) -> bool:
    """Return True if ``username`` matches the allowed character set.

    Restricting the charset prevents values that could break out of a JS/HTML
    context in the admin panel and keeps identifiers predictable.
    """
    return bool(username) and bool(_USERNAME_RE.match(username))


# Upper bound on an accepted login username. Real usernames are short; capping
# the length keeps an attacker from using a giant value as a rate-limiter key
# or forcing large allocations (finding idp-20261003 F1).
MAX_USERNAME_LENGTH = 64


def _valid_login_username(username: str) -> bool:
    """Return True if ``username`` is an acceptable login identifier.

    Combines the charset rule with a hard length cap. Applied on the login
    paths before the value becomes a rate-limiter key or a user-store lookup.
    """
    return len(username) <= MAX_USERNAME_LENGTH and _validate_username(username)


def _validate_claim(claim: str) -> bool:
    """Return True if ``claim`` matches the allowed character set."""
    return bool(claim) and bool(_CLAIM_RE.match(claim))


def _rl_key(client_ip: str, username: str = "") -> str:
    """Build a rate-limit key.

    Keying on both the client IP and the username bounds password spraying
    against a single account across many source IPs as well as brute force
    from a single IP.

    Args:
        client_ip: The requesting client IP.
        username: The account being targeted, if known.

    Returns:
        A composite string key.
    """
    return f"{client_ip}|{username}" if username else client_ip


CAPTCHA_MAX_AGE = 300  # seconds a challenge stays valid


def _generate_challenge(secret: str) -> tuple[str, str, str]:
    """Generate a math challenge and its signed, single-use token.

    The token binds the answer to a random nonce and an issue timestamp:
    ``nonce:issued_at:HMAC(secret, "nonce:issued_at:answer")``. This makes a
    captured (answer, token) pair non-replayable (the nonce is recorded on
    first use) and short-lived, closing the previous stateless-captcha bypass.

    Args:
        secret: The application secret used to sign the challenge.

    Returns:
        ``(question_text, correct_answer, challenge_token)``.
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
    nonce = secrets.token_urlsafe(9)
    issued_at = int(time.time())
    sig = hmac.new(
        secret.encode(), f"{nonce}:{issued_at}:{answer}".encode(), hashlib.sha256
    ).hexdigest()
    challenge_token = f"{nonce}:{issued_at}:{sig}"

    return question, answer, challenge_token


def _verify_challenge(
    secret: str, answer: str, challenge_token: str, nonces: NonceStore | None = None
) -> bool:
    """Verify a challenge answer against its single-use, time-bound token.

    Args:
        secret: The application secret.
        answer: The answer the user submitted.
        challenge_token: The ``nonce:issued_at:sig`` token from the form.
        nonces: Optional nonce store; when provided, a token can be used once.

    Returns:
        True only if the signature matches, the token is not expired, and (when
        a nonce store is provided) the nonce has not been used before.
    """
    parts = challenge_token.split(":")
    if len(parts) != 3:
        return False
    nonce, ts_str, sig = parts
    try:
        issued_at = int(ts_str)
    except ValueError:
        return False
    if issued_at < 0 or time.time() - issued_at > CAPTCHA_MAX_AGE:
        return False
    expected = hmac.new(
        secret.encode(), f"{nonce}:{issued_at}:{answer.strip()}".encode(), hashlib.sha256
    ).hexdigest()
    if not safe_compare(sig, expected):
        return False
    return not (nonces is not None and not nonces.consume(nonce))


def _load_users(users_path: Path) -> dict[str, Any]:
    """Load users from a JSON file."""
    return {u["username"]: u for u in json.loads(users_path.read_text())}


def _users_digest(users_path: Path) -> str | None:
    """Return a content hash of the users file, or None if unreadable.

    Hashing the bytes (rather than trusting mtime/size) means any out-of-band
    edit is detected on the next request, even if the size is unchanged or the
    modification time is coincidentally equal.
    """
    try:
        return hashlib.sha256(users_path.read_bytes()).hexdigest()
    except OSError:
        return None


def _save_users(users_path: Path, users: dict[str, Any]) -> None:
    """Save the users dict back to the JSON file."""
    user_list = list(users.values())
    _atomic_write_private(users_path, json.dumps(user_list, indent=2) + "\n")


# Known placeholder secrets shipped in example manifests / docs. A value equal
# to any of these (case-insensitive) is rejected so a deployment cannot run on a
# publicly-known root HMAC key. See finding idp-20261003 F5.
_PLACEHOLDER_SECRETS = frozenset(
    s.lower()
    for s in (
        "change-me-in-production",
        "change-me",
        "changeme",
        "CHANGE-ME-generate-a-real-secret-key",
        "secret",
        "secret-key",
        "secretkey",
        "please-change-me",
        "replace-me",
        "test",
        "testing",
        "dev",
        "development",
    )
)

MIN_SECRET_KEY_LENGTH = 32


class WeakSecretKeyError(RuntimeError):
    """Raised when the configured SECRET_KEY is missing-safe-fallback-ineligible.

    Specifically: a value WAS supplied (via argument or environment) but it is a
    known placeholder or too short to be a credible HMAC root key. We fail closed
    rather than silently signing every session/step-up token with a guessable
    key.
    """


def _resolve_secret_key(secret_key: str | None) -> str:
    """Resolve the application secret key, failing closed on weak values.

    Resolution:
      * If a value is supplied (argument or ``SECRET_KEY`` env), it MUST be at
        least ``MIN_SECRET_KEY_LENGTH`` chars and not a known placeholder, else
        ``WeakSecretKeyError`` is raised.
      * If no value is supplied at all, a random ephemeral key is generated and
        a warning is logged (sessions will not survive a restart).

    Args:
        secret_key: The explicitly-passed key, if any.

    Returns:
        A validated secret key string.

    Raises:
        WeakSecretKeyError: If a supplied value is a placeholder or too short.
    """
    supplied = secret_key or os.environ.get("SECRET_KEY")
    if supplied:
        if supplied.strip().lower() in _PLACEHOLDER_SECRETS:
            raise WeakSecretKeyError(
                "SECRET_KEY is a known placeholder value; set a real, random "
                "secret (e.g. `python3 -c \"import secrets; "
                "print(secrets.token_hex(32))\"`)."
            )
        if len(supplied) < MIN_SECRET_KEY_LENGTH:
            raise WeakSecretKeyError(
                f"SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters; "
                f"got {len(supplied)}."
            )
        return supplied
    logger.warning(
        "No SECRET_KEY supplied; generating an ephemeral random key. Sessions "
        "and step-up tokens will not survive a restart. Set SECRET_KEY for "
        "production."
    )
    return secrets.token_hex(32)


AUDIT_CHAIN_KEY_FILENAME = "audit_chain.key"


class AuditChainKeyError(RuntimeError):
    """Raised when a stable audit-log chain key cannot be established.

    The audit hash chain must be keyed with a value that survives restarts; if
    it were keyed with an ephemeral secret the chain could never be verified
    after a restart. We fail closed rather than silently auditing on a key that
    disappears, so this is raised when no key is supplied and a persistent key
    file cannot be read or created (e.g. the data dir is not writable).
    """


def _resolve_audit_chain_key(audit_chain_key: str | None, data_dir: Path) -> str:
    """Resolve the dedicated audit-log hash-chain key, failing closed.

    Resolution:
      * If a value is supplied (argument or ``IDP_AUDIT_CHAIN_KEY`` env), use it
        verbatim.
      * Otherwise establish a STABLE per-deployment key by reading an existing
        ``data / audit_chain.key`` or creating it (0600, ``secrets.token_hex``).

    The resolved key is deliberately independent of ``app.secret_key`` so the
    audit chain stays verifiable even when the Flask secret rotates or is
    ephemeral.

    Args:
        audit_chain_key: The explicitly-passed key, if any.
        data_dir: The resolved data directory holding the persistent key file.

    Returns:
        A stable chain-key string.

    Raises:
        AuditChainKeyError: If no key is supplied and a persistent key file can
            neither be read nor created.
    """
    supplied = audit_chain_key or os.environ.get("IDP_AUDIT_CHAIN_KEY")
    if supplied:
        return supplied
    key_path = Path(data_dir) / AUDIT_CHAIN_KEY_FILENAME
    try:
        if key_path.exists():
            existing = key_path.read_text().strip()
            if existing:
                return existing
        key = secrets.token_hex(32)
        # Create 0600 before any secret bytes land so it is never readable.
        fd = os.open(key_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key)
        return key
    except OSError as exc:
        raise AuditChainKeyError(
            "Could not establish a stable audit-log chain key: set "
            "IDP_AUDIT_CHAIN_KEY or make the data directory writable so "
            f"{AUDIT_CHAIN_KEY_FILENAME} can be created ({exc})."
        ) from exc


def _atomic_write_private(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` as mode 0600, atomically.

    Writes to a temp file in the same directory, chmods it 0600 before it holds
    data visible to others, then ``os.replace()`` over the target so the
    restrictive mode is never momentarily absent. Used for every file that
    carries secrets (user DB, recovery tokens). See finding idp-20261003 F8.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp_name, path)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def create_app(
    data_dir: str,
    *,
    host: str | object = _UNSET,
    port: int | object = _UNSET,
    provider_name: str | object = _UNSET,
    session_duration_hours: int | object = _UNSET,
    secret_key: str | None | object = _UNSET,
    audit_chain_key: str | object = _UNSET,
    rate_limit_max_attempts: int | object = _UNSET,
    rate_limit_window_seconds: int | object = _UNSET,
    users_file: str | object = _UNSET,
    certificate_file: str | object = _UNSET,
    private_key_file: str | object = _UNSET,
    adfs_config: dict[str, str] | None = None,
    group_role_map: dict[str, list[dict[str, str]]] | None = None,
    skip_ldap_ssl_verify: bool = False,
    secure_cookies: bool = True,
    trust_proxy: bool | object = _UNSET,
    webauthn_enabled: bool | object = _UNSET,
    webauthn_rp_id: str | object = _UNSET,
    webauthn_rp_name: str | object = _UNSET,
    webauthn_expected_origin: str | object = _UNSET,
) -> Flask:
    """Flask application factory and single configuration entry point.

    ``create_app`` loads ``config.yaml`` and ``IDP_*`` environment variables
    itself via :func:`identity_provider_server.config.load_config`, using the
    resolved values as the DEFAULTS for every security-relevant parameter.
    Any keyword argument the caller passes explicitly overrides the config
    value; omitted arguments (left at the ``_UNSET`` sentinel) fall back to
    config. This makes the bare production entrypoint
    ``create_app('/data')`` honor ``config.yaml`` and ``IDP_*`` while the CLI
    launchers, which pass explicit values for every mapped field, still win.

    Args:
        data_dir: Path to directory containing data files, ``config.yaml`` and
            the ``IDP_*`` env vars read from here.
        host: Bind host — used to derive the IdP entity ID. Defaults to config.
        port: Bind port — used to derive the IdP entity ID. Defaults to config.
        provider_name: SAML provider name registered in AWS IAM. Defaults to
            config.
        session_duration_hours: SAML assertion validity in hours (1–12).
            Defaults to config.
        secret_key: Flask secret key for CSRF tokens. Auto-generated if None.
            Defaults to config.
        audit_chain_key: Dedicated key for the audit-log hash chain. When empty,
            a stable per-deployment key is read from (or created in)
            ``data_dir/audit_chain.key``; it is never derived from secret_key so
            the chain stays verifiable across restarts and secret rotation.
        rate_limit_max_attempts: Max failed login attempts per IP before limiting.
        rate_limit_window_seconds: Rate limit window in seconds.
        users_file: Filename or path to users JSON file (relative to data_dir).
        certificate_file: Filename or path to signing certificate (relative to data_dir).
        private_key_file: Filename or path to private key (relative to data_dir).
        adfs_config: ADFS/LDAP connection config dict (enables ADFS auth mode).
        group_role_map: Mapping of AD group names to AWS role dicts (used with ADFS).
        skip_ldap_ssl_verify: If True, disable TLS certificate verification for LDAP.
        secure_cookies: If True (default), set the Secure flag on all cookies.
            Set False only for local HTTP development.
        trust_proxy: When False, ignore X-Forwarded-For/Proto headers and key
            rate limiting on the direct peer address. Defaults to config.
            Enable only when the service runs behind exactly one trusted
            reverse proxy; trusting these headers on a directly exposed
            deployment lets a client forge its source IP (rate-limit bypass
            and audit source-IP forgery).
        webauthn_enabled: If True, enable passkey (WebAuthn) endpoints and UI.
            Defaults to config.
        webauthn_rp_id: WebAuthn Relying Party ID (the effective domain).
            Defaults to config.
        webauthn_rp_name: Human-readable RP name shown by authenticators.
            Defaults to config.
        webauthn_expected_origin: The full https origin browsers report.
            Defaults to config.

    Raises:
        ConfigNotConsumedError: If a setting was supplied via ``config.yaml`` or
            an ``IDP_*`` env var but could not be applied to the running app.
    """
    from .config import load_config

    # create_app is the single configuration entry point: load config.yaml and
    # IDP_* overrides, then use them as defaults for every parameter the caller
    # left at the _UNSET sentinel. Explicit kwargs (passed by the CLI launchers
    # with CLI-flag overrides already applied) still win.
    cfg = load_config(data_dir)
    host = cfg.server.host if host is _UNSET else host
    port = cfg.server.port if port is _UNSET else port
    provider_name = (
        cfg.saml.provider_name if provider_name is _UNSET else provider_name
    )
    session_duration_hours = (
        cfg.saml.session_duration_hours
        if session_duration_hours is _UNSET
        else session_duration_hours
    )
    secret_key = (
        (cfg.security.secret_key or None) if secret_key is _UNSET else secret_key
    )
    audit_chain_key = (
        cfg.security.audit_chain_key if audit_chain_key is _UNSET else audit_chain_key
    )
    rate_limit_max_attempts = (
        cfg.security.rate_limit_max_attempts
        if rate_limit_max_attempts is _UNSET
        else rate_limit_max_attempts
    )
    rate_limit_window_seconds = (
        cfg.security.rate_limit_window_seconds
        if rate_limit_window_seconds is _UNSET
        else rate_limit_window_seconds
    )
    users_file = cfg.data.users_file if users_file is _UNSET else users_file
    certificate_file = (
        cfg.data.certificate_file if certificate_file is _UNSET else certificate_file
    )
    private_key_file = (
        cfg.data.private_key_file if private_key_file is _UNSET else private_key_file
    )
    trust_proxy = cfg.server.trust_proxy if trust_proxy is _UNSET else trust_proxy
    webauthn_enabled = (
        cfg.webauthn.enabled if webauthn_enabled is _UNSET else webauthn_enabled
    )
    webauthn_rp_id = (
        cfg.webauthn.rp_id if webauthn_rp_id is _UNSET else webauthn_rp_id
    )
    webauthn_rp_name = (
        cfg.webauthn.rp_name if webauthn_rp_name is _UNSET else webauthn_rp_name
    )
    webauthn_expected_origin = (
        cfg.webauthn.expected_origin
        if webauthn_expected_origin is _UNSET
        else webauthn_expected_origin
    )

    # Fail closed if any supplied setting could not be threaded through.
    _assert_config_consumed(
        data_dir,
        cfg,
        {
            "host": host,
            "port": port,
            "provider_name": provider_name,
            "session_duration_hours": session_duration_hours,
            "secret_key": secret_key,
            "audit_chain_key": audit_chain_key,
            "rate_limit_max_attempts": rate_limit_max_attempts,
            "rate_limit_window_seconds": rate_limit_window_seconds,
            "users_file": users_file,
            "certificate_file": certificate_file,
            "private_key_file": private_key_file,
            "trust_proxy": trust_proxy,
            "webauthn_enabled": webauthn_enabled,
            "webauthn_rp_id": webauthn_rp_id,
            "webauthn_rp_name": webauthn_rp_name,
            "webauthn_expected_origin": webauthn_expected_origin,
        },
    )

    data = Path(data_dir)
    # Harden the data directory to owner-only (0700) best-effort, so the
    # sensitive files inside (user DB, recovery tokens, audit log) are not
    # reachable by other local accounts (finding idp-20261003 F8).
    try:
        if data.is_dir():
            data.chmod(0o700)
    except OSError:  # pragma: no cover - best effort on exotic filesystems
        logger.warning("Could not chmod 700 the data directory")

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
        users_digest = None
        _group_role_map = group_role_map or {}
        logger.info("ADFS authentication mode enabled (host=%s)", adfs_config.get("host"))
    else:
        users_path = _resolve(users_file)
        users = _load_users(users_path)
        # Track the file by content hash so any out-of-band edit is detected
        # on the next request (mtime/size alone can miss same-size rewrites).
        users_digest = _users_digest(users_path)
        _group_role_map = {}

    idp_entity_id = f"http://{host}:{port}/metadata"
    if port == 443:
        idp_entity_id = f"https://{host}/metadata"
    elif port == 80:
        idp_entity_id = f"http://{host}/metadata"
    cert_b64 = "".join(cert_pem.strip().splitlines()[1:-1])

    app = Flask(__name__)
    app.secret_key = _resolve_secret_key(secret_key)
    # Cache-bust the static passkey script per release so a deploy is never
    # masked by a stale CDN/browser copy. Available to every template render.
    from ._version import __version__ as _idp_version
    app.jinja_env.globals["passkey_js_version"] = _idp_version

    # Trust exactly one upstream proxy for the client IP / scheme so rate
    # limiting keys on the real client rather than the proxy address.
    if trust_proxy:
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # type: ignore[method-assign]

    # Whether to mark cookies Secure. On by default; callers disable only for
    # local plain-HTTP development.
    _cookies_secure = secure_cookies

    app.config.update(
        SESSION_COOKIE_SECURE=secure_cookies,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        # Cap request bodies: these forms and JSON payloads are tiny, so a small
        # limit prevents a single multi-megabyte field (e.g. a giant username)
        # from being parsed into memory or into a rate-limiter key (F1).
        MAX_CONTENT_LENGTH=64 * 1024,  # 64 KiB
    )

    rate_limiter = _RateLimiter(
        max_attempts=rate_limit_max_attempts, window_seconds=rate_limit_window_seconds
    )

    # The rate limiter and the single-use nonce / challenge stores below are
    # per-process. Running multiple workers/replicas without a shared backend
    # silently weakens them (the failed-login budget multiplies and a nonce can
    # be replayed once per process). Warn loudly if the environment advertises
    # more than one worker so an operator does not deploy an unsafe topology
    # by accident. ``WEB_CONCURRENCY`` / ``GUNICORN_WORKERS`` are the usual hints.
    for _worker_var in ("WEB_CONCURRENCY", "GUNICORN_WORKERS"):
        try:
            _worker_count = int(os.environ.get(_worker_var, "1"))
        except ValueError:  # pragma: no cover - non-numeric env is ignored
            continue
        if _worker_count > 1:
            logger.warning(
                "%s=%d but the rate limiter and single-use nonce stores are "
                "per-process; run a single worker or add a shared store, else "
                "these anti-abuse controls weaken by a factor of the worker count.",
                _worker_var, _worker_count,
            )

    # Single-use nonce store backing the short-lived MFA "password proven"
    # ticket, so an observed ticket cannot be replayed within its window.
    MFA_TICKET_MAX_AGE = 120  # seconds
    mfa_nonces = NonceStore(ttl_seconds=MFA_TICKET_MAX_AGE)

    # Single-use nonce store for captcha challenges (replay protection).
    captcha_nonces = NonceStore(ttl_seconds=CAPTCHA_MAX_AGE)

    # Server-side store of pending TOTP enrolment secrets, keyed by an opaque
    # handle rendered into the enrol form. The enrol action reads the secret
    # from here by handle rather than trusting a client-supplied value, so an
    # attacker cannot inject or silently overwrite a factor with a secret of
    # their own choosing (finding idp-20261003 F7).
    ENROLL_SECRET_MAX_AGE = 600  # seconds
    _enroll_secrets: dict[str, tuple[str, float]] = {}

    def _stash_enroll_secret(secret: str) -> str:
        """Store ``secret`` server-side; return an opaque handle for the form."""
        now = time.time()
        # Opportunistically prune expired handles so the dict cannot grow.
        for h, (_s, exp) in list(_enroll_secrets.items()):
            if exp <= now:  # pragma: no cover - opportunistic prune of expired handles
                del _enroll_secrets[h]
        handle = secrets.token_urlsafe(16)
        _enroll_secrets[handle] = (secret, now + ENROLL_SECRET_MAX_AGE)
        return handle

    def _take_enroll_secret(handle: str) -> str | None:
        """Consume and return the secret for ``handle`` (single use), or None."""
        entry = _enroll_secrets.pop(handle, None)
        if entry is None:
            return None
        secret, expiry = entry
        if expiry <= time.time():  # pragma: no cover - expired handle (TTL >> step-up token TTL)
            return None
        return secret

    # --- Passkey (WebAuthn) setup ---
    _webauthn_rp = wf.RelyingParty(
        rp_id=webauthn_rp_id,
        rp_name=webauthn_rp_name,
        expected_origin=webauthn_expected_origin,
    )
    _passkey_challenges = wf.ChallengeStore(ttl_seconds=120)

    def _passkey_available() -> bool:
        """True if passkeys are enabled and configured (local-user mode only)."""
        return bool(
            webauthn_enabled and webauthn_rp_id and webauthn_expected_origin
            and not use_adfs
        )

    def _enroll_passkey_context(username: str) -> dict[str, Any]:
        """Template context for the passkey section of ``USER_PAGE_ENROLL``.

        Returns the availability flag and the user's registered credentials
        (id + label only — never the public key) so the enroll page can list
        and manage them. Empty/harmless defaults when passkeys are disabled.
        """
        if not _passkey_available():
            return {
                "passkey_available": False,
                "passkeys": [],
                "passwordless_enabled": False,
                "passwordless_eligible": False,
            }
        user = users.get(username) or {}
        creds = [
            {"credential_id": c.get("credential_id", ""), "label": c.get("label", "passkey")}
            for c in wf.get_credentials(user)
        ]
        return {
            "passkey_available": True,
            "passkeys": creds,
            "passwordless_enabled": bool(user.get(wf.PASSWORDLESS_FIELD)),
            "passwordless_eligible": wf.meets_passwordless_minimum(user),
        }

    def _render_enroll_page(
        username: str,
        *,
        status: int = 200,
        error: str | None = None,
        password_error: str | None = None,
        password_success: bool = False,
        passwordless_error: str | None = None,
    ):
        """Render the self-service account page (``USER_PAGE_ENROLL``).

        Single source of truth for this page so every caller renders a
        consistent context. When MFA is not enabled it stashes ONE freshly
        generated secret server-side and renders its handle (plus the matching
        QR), fixing the former bug where the QR and the hidden field used two
        different secrets, and ensuring the enrol action can only accept a
        server-issued secret (finding idp-20261003 F7).
        """
        user = users.get(username) or {}
        mfa_enabled = bool(user.get("totp_secret"))
        ctx: dict[str, Any] = {"qr_data_uri": "", "totp_secret": "", "secret_handle": ""}
        if not mfa_enabled:
            new_secret = generate_secret()
            uri = provisioning_uri(new_secret, username, issuer="idp.botthouse.net")
            ctx = {
                "qr_data_uri": qr_code_data_uri(uri),
                "totp_secret": new_secret,
                "secret_handle": _stash_enroll_secret(new_secret),
            }
        token = _generate_csrf_token()
        resp = app.make_response(render_template_string(
            USER_PAGE_ENROLL,
            mfa_enabled=mfa_enabled,
            csrf_token=token,
            auth_token=_issue_auth_token(username),
            error=error,
            password_error=password_error,
            password_success=password_success,
            passwordless_error=passwordless_error,
            **ctx,
            **_enroll_passkey_context(username),
        ))
        resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
        return (resp, status) if status != 200 else resp

    def _check_challenge(answer: str, token: str) -> bool:
        """Verify a captcha answer/token, consuming the nonce on success."""
        return _verify_challenge(app.secret_key, answer, token, captcha_nonces)

    def _audit_write_failed(message: str) -> None:
        # pragma: no cover - only fires on a real audit-log write failure
        """Fire a loud notification when the audit log cannot be written (F9)."""
        from . import notify  # pragma: no cover
        notify.notify("audit_write_failed", message, severity="critical")  # pragma: no cover

    # Key the audit hash chain with a dedicated, stable key — never reuse
    # app.secret_key, which may be ephemeral (and thus leave the chain
    # unverifiable after a restart). Fails closed via AuditChainKeyError.
    resolved_audit_chain_key = _resolve_audit_chain_key(audit_chain_key, data)
    audit = AuditLogger(
        data_dir,
        chain_key=resolved_audit_chain_key,
        failure_callback=_audit_write_failed,
    )
    # Verify the on-disk chain at startup; a mismatch means the log was
    # truncated or rewritten, so notify loudly. NOTE: the in-memory _seq /
    # _last_hash cursor is per-process — externalising chain state for a
    # multi-worker topology is deliberately out of scope (single-worker by
    # design); see docs/security.md.
    if not audit.verify_chain():
        logger.error("Audit log chain verification failed at startup")
        from . import notify

        notify.notify(
            "audit_chain_invalid",
            "audit log hash chain failed verification at startup "
            "(possible truncation or tampering)",
            severity="critical",
        )

    # Store config on app for access in tests
    app.config["IDP_ENTITY_ID"] = idp_entity_id
    app.config["PROVIDER_NAME"] = provider_name
    app.config["SESSION_DURATION_HOURS"] = session_duration_hours
    # Expose the resolved WebAuthn relying-party settings so operators and
    # tests can confirm config.yaml / IDP_* actually reached create_app.
    app.config["WEBAUTHN_ENABLED"] = bool(webauthn_enabled)
    app.config["WEBAUTHN_RP_ID"] = webauthn_rp_id
    app.config["WEBAUTHN_RP_NAME"] = webauthn_rp_name
    app.config["WEBAUTHN_EXPECTED_ORIGIN"] = webauthn_expected_origin

    def _generate_csrf_token() -> str:
        """Generate a CSRF token tied to the app secret."""
        return secrets.token_hex(32)

    @app.after_request
    def _security_headers(resp):  # type: ignore[no-untyped-def]
        """Add hardening headers and enforce the Secure cookie flag.

        Setting Secure here (rather than at each ``set_cookie`` call site)
        guarantees no handler can accidentally emit a credential cookie without
        it. HSTS is only emitted when cookies are Secure (i.e. an HTTPS
        deployment) to avoid pinning HTTPS during local HTTP development.

        The Content-Security-Policy uses a per-request nonce for the single
        inline ``<script>`` block the admin panel needs; inline event-handler
        attributes are disallowed, which is what neutralises reflected/stored
        script in interpolated values.
        """
        if _cookies_secure:
            resp.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
            # Ensure every cookie carries Secure even if a handler omitted it.
            cookies = resp.headers.getlist("Set-Cookie")
            if cookies:
                resp.headers.pop("Set-Cookie")
                for cookie in cookies:
                    if "secure" not in cookie.lower():
                        cookie = f"{cookie}; Secure"
                    resp.headers.add("Set-Cookie", cookie)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        nonce = getattr(g, "csp_nonce", "")
        script_src = f"script-src 'self' 'nonce-{nonce}'" if nonce else "script-src 'self'"
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            f"{script_src}; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        )
        return resp

    @app.errorhandler(Exception)
    def _handle_uncaught(exc):  # type: ignore[no-untyped-def]
        """Catch-all so an uncaught fault is bounded, audited, and generic.

        Flask re-raises HTTPExceptions it already knows how to render (404, 405,
        the 413 from MAX_CONTENT_LENGTH, etc.); only genuinely unexpected
        exceptions reach the generic branch. Without this, a crafted request
        (e.g. a non-ASCII token field) could produce an unlogged HTTP 500
        (finding idp-20261003 F2).
        """
        from werkzeug.exceptions import HTTPException
        if isinstance(exc, HTTPException):
            return exc
        logger.exception("Unhandled exception serving %s", request.path)
        try:
            audit.log(
                username="", ip=request.remote_addr or "unknown",
                service=request.path, protocol="error", result="failure",
                reason="unhandled_exception",
                user_agent=request.headers.get("User-Agent", ""),
            )
        except Exception:  # noqa: BLE001 - never let auditing mask the 500  # pragma: no cover - defensive
            logger.exception("Failed to audit an unhandled exception")
        return "Internal Server Error", 500

    def _make_challenge() -> tuple[str, str]:
        """Generate a challenge question and its verification hash."""
        question, _answer, challenge_hash = _generate_challenge(app.secret_key)
        return question, challenge_hash

    def _reload_users_if_changed() -> None:
        """Reload users.json if its content hash has changed.

        Comparing a content digest (rather than mtime/size) guarantees that any
        edit — including out-of-band writes that keep the same size or mtime — is
        picked up on the next request, so the in-memory copy can never go stale.
        """
        nonlocal users_digest
        if use_adfs or users_path is None:
            return
        current = _users_digest(users_path)
        if current is None:
            logger.warning("Could not read users.json for hot-reload check")
            return
        if current != users_digest:
            try:
                fresh = _load_users(users_path)
            except (OSError, ValueError) as exc:
                logger.warning("Could not reload users.json: %s", exc)
                return
            # Update the dict IN PLACE rather than rebinding it, so every holder
            # of the reference (notably the admin blueprint, which captured it
            # at registration) sees the change. Rebinding would leave the admin
            # routes reading a stale copy, defeating the account-state gate.
            users.clear()
            users.update(fresh)
            users_digest = current
            logger.info("Reloaded users.json (content changed)")

    @app.get("/health")
    def health():
        """Health check endpoint."""
        return {"status": "healthy"}, 200

    _static_dir = Path(__file__).resolve().parent / "static"

    @app.get("/static/passkey.js")
    def passkey_js():
        """Serve the passkey client script under the app's own origin.

        Serving from ``'self'`` means the file loads under the existing strict
        ``script-src 'self'`` CSP with no relaxation (no inline script, no
        external host). The file is small and immutable per release, so it is
        cached for a day.
        """
        js_path = _static_dir / "passkey.js"
        body = js_path.read_text(encoding="utf-8")
        resp = Response(body, mimetype="text/javascript")
        # Short TTL + revalidation: the script changes with releases, so a long
        # cache would serve stale client code after a deploy. 5 minutes bounds
        # how long an intermediary/browser can hold an outdated copy.
        resp.headers["Cache-Control"] = "public, max-age=300, must-revalidate"
        return resp

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
        g.csp_nonce = secrets.token_urlsafe(16)
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
            # Reject empty/whitespace-only passwords outright so a blank field
            # can never be read as a match (defence in depth alongside bcrypt).
            if not password or not password.strip():
                return False, None
            user = users.get(username)
            if not user or not _user_can_login(user):
                return False, None
            if not _check_password(user.get("password", ""), password):
                return False, None
            return True, _resolve_roles_from_claims(user)

    def _handle_login_form(service_path: str):
        """Render the login form for a service path."""
        # Check for valid session cookie — skip login if remembered
        session = _verify_session_cookie_full(request.cookies.get(SESSION_COOKIE_NAME, ""))
        session_user = session[0] if session else None
        session_auth_time = session[1] if session else None
        session_mfa = session[2] if session else False
        if session_user and not use_adfs:
            user = users.get(session_user)
            # Re-apply the account-state gate on this credential-issuing path:
            # a live cookie must not outlive disablement or a forced-rotation
            # flag. Falls through to the login form otherwise.
            if (
                user
                and _user_can_login(user)
                and not _needs_password_change(session_user)
            ):
                sp = _get_service(service_path)
                protocol = sp.protocol if sp else "saml"
                audit.log(
                    username=session_user,
                    ip=request.remote_addr or "unknown",
                    service=service_path,
                    protocol=protocol,
                    result="session_reuse",
                    user_agent=request.headers.get("User-Agent", ""),
                )
                roles = _resolve_roles_from_claims(user)
                if sp and sp.protocol == "oauth":
                    token = build_oauth_token(
                        session_user, key_pem, idp_entity_id,
                        client_id=sp.client_id, scopes=sp.scopes,
                        token_expiry_minutes=sp.token_expiry_minutes, groups=None,
                        claims=user.get("claims", []),
                        email=user.get("email"),
                    )
                    # Deliver the JWT in the URL fragment so it never reaches
                    # server access logs or the Referer header (idp-20261006 F2).
                    resp = app.make_response(redirect(f"{sp.url}#token={token}"))
                    # Slide the idle window but keep the absolute-cap anchor and
                    # the factor marker (never upgrade a one-factor session).
                    _set_session_cookie(
                        resp, session_user,
                        auth_time=session_auth_time, mfa=session_mfa,
                    )
                    return resp
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
                    resp = app.make_response(
                        render_template_string(SAML_POST, acs=sp_acs_url, saml=saml_b64)
                    )
                    _set_session_cookie(
                        resp, session_user,
                        auth_time=session_auth_time, mfa=session_mfa,
                    )
                    return resp

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
            passkey_available=_passkey_available(),
            service_path=service_path,
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
        if not form_token or not safe_compare(form_token, cookie_token):
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
            audit.log(
                username="",
                ip=client_ip,
                service=service_path,
                protocol=sp.protocol if sp else "saml",
                result="failure",
                reason="rate_limited",
                user_agent=request.headers.get("User-Agent", ""),
            )
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
            # The username comes from a signed, single-use ticket proving the
            # password step already passed — never from an unauthenticated form
            # field. A ticket alone (without a prior password) cannot exist.
            totp_code = request.form.get("totp_code", "")
            ticket_info = _read_mfa_ticket(request.form.get("mfa_ticket", ""))
            if ticket_info is None:
                question, new_hash = _make_challenge()
                return render_template_string(
                    LOGIN_FORM,
                    error="Your session expired. Please sign in again.",
                    csrf_token=_generate_csrf_token(),
                    challenge_question=question,
                    challenge_hash=new_hash,
                    service_title=title,
                ), 401
            auth_username, ticket_nonce = ticket_info
            user = users.get(auth_username)
            # Re-run the full eligibility predicate before issuance — the
            # account can be disabled or locked between the password leg (which
            # minted the ticket) and this second leg, and the siblings (password
            # leg + SP passkey finish) already gate here (finding
            # idp-2026-10-06 F2).
            if (
                not user
                or not user.get("totp_secret")
                or not _user_can_login(user)
                or _account_locked(auth_username)
            ):
                question, new_hash = _make_challenge()
                return render_template_string(
                    LOGIN_FORM,
                    error="Invalid request",
                    csrf_token=_generate_csrf_token(),
                    challenge_question=question,
                    challenge_hash=new_hash,
                    service_title=title,
                ), 401

            # Burn the ticket nonce BEFORE verifying the code so each ticket
            # permits exactly one guess. A wrong code therefore costs the
            # attacker a fresh password-proof round-trip, and the 120-second
            # ticket can no longer be replayed for unlimited attempts.
            if not _consume_mfa_nonce(auth_username, ticket_nonce):
                question, new_hash = _make_challenge()
                return render_template_string(
                    LOGIN_FORM,
                    error="Your session expired. Please sign in again.",
                    csrf_token=_generate_csrf_token(),
                    challenge_question=question,
                    challenge_hash=new_hash,
                    service_title=title,
                ), 401

            if not verify_code(user["totp_secret"], totp_code):
                # Record the buckets the limiter actually CHECKS (per-IP at
                # app start of this handler, and per-account), not only the
                # composite key — a failed second factor must count toward
                # throttling and lockout.
                rate_limiter.record(client_ip)
                rate_limiter.record(f"acct:{auth_username}")
                rate_limiter.record(_rl_key(client_ip, auth_username))
                _register_auth_failure(auth_username)
                audit.log(
                    username=auth_username,
                    ip=client_ip,
                    service=service_path,
                    protocol=sp.protocol if sp else "saml",
                    result="failure",
                    reason="invalid_mfa",
                    user_agent=request.headers.get("User-Agent", ""),
                )
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    TOTP_FORM,
                    error="Invalid code. Try again.",
                    csrf_token=token,
                    mfa_ticket=request.form.get("mfa_ticket", ""),
                    service_path=service_path,
                ))
                resp.set_cookie(
                    "csrf_token", token, httponly=True,
                    samesite="Strict", secure=_cookies_secure,
                )
                return resp, 401

            # TOTP verified — the single-use ticket was already burned above,
            # so a correct code here issues credentials exactly once.
            _reset_auth_failures(auth_username)
            username = auth_username
            if use_adfs:  # pragma: no cover - ADFS accounts never carry a local totp_secret, so this MFA-ticket branch is unreachable in ADFS mode
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
            _record_login(username)
            audit.log(
                username=username,
                ip=client_ip,
                service=service_path,
                protocol=sp.protocol if sp else "saml",
                result="success",
                user_agent=request.headers.get("User-Agent", ""),
            )

            # Forced rotation: block credential issuance until the password is changed.
            if _needs_password_change(username):
                return _forced_change_response(username)

            # Issue the token
            if sp and sp.protocol == "oauth":
                token = build_oauth_token(
                    username, key_pem, idp_entity_id,
                    client_id=sp.client_id, scopes=sp.scopes,
                    token_expiry_minutes=sp.token_expiry_minutes, groups=groups,
                    claims=users.get(username, {}).get("claims", []),
                    email=users.get(username, {}).get("email"),
                )
                # Deliver the JWT in the URL fragment so it never reaches
                # server access logs or the Referer header (idp-20261006 F2).
                resp = redirect(f"{sp.url}#token={token}")
                # Second factor verified — mark the session two-factor.
                _set_session_cookie(resp, username, mfa=True)
                return resp
            else:
                if use_adfs and not roles:  # pragma: no cover - unreachable: ADFS accounts have no local totp_secret to reach this MFA-ticket branch
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
                # Second factor verified — mark the session two-factor.
                _set_session_cookie(resp, username, mfa=True)
                return resp

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Reject malformed / over-long usernames BEFORE they touch any
        # account-keyed state (rate-limiter buckets, user lookup). This bounds
        # the rate-limiter key space and rejects junk early (F1). An invalid
        # username can never match a real account, so return the generic
        # "Invalid credentials" without recording account-scoped state.
        if username and not _valid_login_username(username):
            rate_limiter.record(client_ip)  # per-IP only; never an attacker key
            question, new_hash = _make_challenge()
            return render_template_string(
                LOGIN_FORM,
                error="Invalid credentials",
                csrf_token=_generate_csrf_token(),
                challenge_question=question,
                challenge_hash=new_hash,
                service_title=title,
            ), 401

        # Durable per-account lockout (survives the sliding window and restarts).
        if _account_locked(username):
            audit.log(
                username=username,
                ip=client_ip,
                service=service_path,
                protocol=sp.protocol if sp else "saml",
                result="failure",
                reason="account_locked",
                user_agent=request.headers.get("User-Agent", ""),
            )
            question, new_hash = _make_challenge()
            return render_template_string(
                LOGIN_FORM,
                error="Account temporarily locked. Try again later.",
                csrf_token=_generate_csrf_token(),
                challenge_question=question,
                challenge_hash=new_hash,
                service_title=title,
            ), 429

        # Per-account lockout check (bounds spraying one account from many IPs).
        if username and rate_limiter.is_limited(f"acct:{username}"):
            # A throttled attempt is still a failed attempt against the account;
            # count it toward the durable lockout so a spray paced to stay under
            # the sliding window still eventually locks the account.
            _register_auth_failure(username)
            audit.log(
                username=username,
                ip=client_ip,
                service=service_path,
                protocol=sp.protocol if sp else "saml",
                result="failure",
                reason="rate_limited",
                user_agent=request.headers.get("User-Agent", ""),
            )
            question, new_hash = _make_challenge()
            return render_template_string(
                LOGIN_FORM,
                error="Too many attempts. Try again later.",
                csrf_token=_generate_csrf_token(),
                challenge_question=question,
                challenge_hash=new_hash,
                service_title=title,
            ), 429

        # Human verification BEFORE the credential check, applied uniformly to
        # every account (previously it ran after the password check and was
        # skipped for TOTP accounts, an inconsistency the review flagged).
        if not _check_challenge(challenge_answer, challenge_hash_val):
            rate_limiter.record(_rl_key(client_ip, username))
            rate_limiter.record(client_ip)
            logger.info("Failed challenge from ip=%s", client_ip)
            audit.log(
                username=username,
                ip=client_ip,
                service=service_path,
                protocol=sp.protocol if sp else "saml",
                result="failure",
                reason="failed_captcha",
                user_agent=request.headers.get("User-Agent", ""),
            )
            question, new_hash = _make_challenge()
            return render_template_string(
                LOGIN_FORM,
                error="Incorrect answer — please try again.",
                csrf_token=_generate_csrf_token(),
                challenge_question=question,
                challenge_hash=new_hash,
                service_title=title,
            ), 401

        success, auth_result = _authenticate_user(username, password)
        if not success:
            rate_limiter.record(_rl_key(client_ip, username))
            rate_limiter.record(client_ip)  # also throttle at the IP level
            if username:
                rate_limiter.record(f"acct:{username}")  # per-account lockout
                _register_auth_failure(username)  # durable lockout counter
            logger.info("Failed login for user=%s from ip=%s", username, client_ip)
            audit.log(
                username=username,
                ip=client_ip,
                service=service_path,
                protocol=sp.protocol if sp else "saml",
                result="failure",
                reason="invalid_credentials",
                user_agent=request.headers.get("User-Agent", ""),
            )
            question, new_hash = _make_challenge()
            return render_template_string(
                LOGIN_FORM,
                error="Invalid credentials",
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
                # Password proven — hand out a single-use ticket that the TOTP
                # step will verify. The username is NOT trusted from the form on
                # the second step; it is derived from this signed ticket.
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    TOTP_FORM,
                    error=None,
                    csrf_token=token,
                    mfa_ticket=_issue_mfa_ticket(username),
                    service_path=service_path,
                ))
                resp.set_cookie(
                    "csrf_token", token, httponly=True,
                    samesite="Strict", secure=_cookies_secure,
                )
                return resp

        # Fully authenticated (password + captcha, no MFA enrolled, or ADFS) —
        # clear any durable lockout counters.
        _reset_auth_failures(username)
        logger.info(
            "Successful login: user=%s service=%s from ip=%s",
            username, service_path, client_ip,
        )
        _record_login(username)
        audit.log(
            username=username,
            ip=client_ip,
            service=service_path,
            protocol=sp.protocol if sp else "saml",
            result="success",
            user_agent=request.headers.get("User-Agent", ""),
        )

        # Forced rotation: block credential issuance until the password is changed.
        if _needs_password_change(username):
            return _forced_change_response(username)

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
            # Deliver the JWT in the URL fragment so it never reaches
            # server access logs or the Referer header (idp-20261006 F2).
            resp = app.make_response(redirect(f"{sp.url}#token={token}"))
            # Establish the SSO session cookie here too — the MFA-ticket and
            # passkey paths already do, and omitting it on the no-MFA path was a
            # known inconsistency that broke SSO for password-only accounts.
            _set_session_cookie(resp, username)
            return resp
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
            resp = app.make_response(
                render_template_string(SAML_POST, acs=sp_acs_url, saml=saml_b64)
            )
            _set_session_cookie(resp, username)
            return resp

    # Step-up token lifetime for the self-service /user flow.
    USER_STEPUP_MAX_AGE = 300  # 5 minutes

    def _issue_auth_token(username: str) -> str:
        """Issue a short-lived, purpose-scoped self-service step-up token."""
        return issue_token(app.secret_key, username, PURPOSE_USER)

    def _verify_auth_token(token: str, max_age: int = USER_STEPUP_MAX_AGE) -> str | None:
        """Verify a self-service step-up token; return the username if valid."""
        return verify_token(app.secret_key, token, PURPOSE_USER, max_age)

    def _issue_mfa_ticket(username: str) -> str:
        """Issue a single-use ticket proving the password step already passed.

        The ticket embeds a random nonce so a second use is rejected by the
        nonce store, and it is purpose-scoped so it cannot be replayed as a
        session or step-up credential.
        """
        nonce = secrets.token_urlsafe(16)
        return issue_token(app.secret_key, f"{username}|{nonce}", PURPOSE_MFA_PENDING)

    def _read_mfa_ticket(ticket: str) -> tuple[str, str] | None:
        """Verify an MFA ticket's signature/age/purpose without consuming it.

        Returns ``(username, nonce)`` if valid, else ``None``. The nonce is
        consumed separately (only when credentials are actually issued) so a
        mistyped TOTP code does not invalidate the ticket.
        """
        subject = verify_token(
            app.secret_key, ticket, PURPOSE_MFA_PENDING, MFA_TICKET_MAX_AGE
        )
        if subject is None or "|" not in subject:
            return None
        username, nonce = subject.rsplit("|", 1)
        return username, nonce

    def _consume_mfa_nonce(username: str, nonce: str) -> bool:
        """Consume the ticket nonce; False if already used (replay)."""
        if not mfa_nonces.consume(nonce):
            logger.warning("Rejected replayed MFA ticket for user=%s", username)
            return False
        return True

    SESSION_COOKIE_NAME = "idp_session"
    SESSION_MAX_AGE = 12 * 3600  # 12 hours (absolute cap, enforced server-side)
    SESSION_IDLE_MAX_AGE = 15 * 60  # 15 minutes of inactivity

    def _load_deleted_epochs() -> dict[str, int]:
        """Return the persisted deleted-account epoch tombstones.

        Reads ``data / 'deleted_epochs.json'`` (written by the admin
        ``delete_user`` path) which maps a deleted username to the last
        session epoch it held. The tombstone survives a delete/recreate so a
        recreated username cannot reset its epoch below the deleted account's
        last value, defeating stale-cookie resurrection (finding
        idp-2026-10-06 F5).

        Returns:
            A mapping of username to epoch, or an empty dict when the file is
            absent or unreadable.
        """
        try:
            raw = (data / "deleted_epochs.json").read_text()
            return json.loads(raw)
        except (OSError, json.JSONDecodeError):
            return {}

    def _user_session_epoch(username: str) -> int:
        """Return the account's current session-revocation epoch.

        The epoch is bumped whenever outstanding sessions must be invalidated
        (account disabled, password reset, claims changed). A cookie minted with
        a stale epoch no longer verifies, giving server-side revocation on top
        of the stateless token. The effective epoch is the larger of the live
        record epoch and any deleted-account tombstone, so a recreated username
        inherits the deleted account's floor (finding idp-2026-10-06 F5).
        """
        user = users.get(username) or {}
        try:
            record_epoch = int(user.get("session_epoch", 0))
        except (TypeError, ValueError):
            record_epoch = 0
        try:
            tombstone_epoch = int(_load_deleted_epochs().get(username, 0))
        except (TypeError, ValueError):
            tombstone_epoch = 0
        return max(record_epoch, tombstone_epoch)

    def _issue_session_cookie(
        username: str, *, auth_time: int | None = None, mfa: bool = False
    ) -> str:
        """Issue a signed session cookie value binding auth_time, epoch and mfa.

        Args:
            username: The authenticated subject.
            auth_time: The absolute-cap anchor. ``None`` starts a fresh session
                (anchored at now); re-mints pass the original value to keep the
                absolute window fixed while the idle window slides.
            mfa: Whether a real second factor established the session. Preserved
                verbatim across re-mints so a one-factor session never silently
                becomes two-factor (finding idp-2026-10-06 F6).
        """
        now = int(time.time())
        return issue_session_token(
            app.secret_key,
            username,
            auth_time=now if auth_time is None else auth_time,
            epoch=_user_session_epoch(username),
            mfa=mfa,
        )

    def _verify_session_cookie_full(cookie_val: str) -> tuple[str, int, bool] | None:
        """Verify a session cookie against idle, absolute, and revocation limits.

        Returns ``(username, auth_time, mfa)`` so the caller can preserve the
        absolute-cap anchor and the factor marker when re-minting, or ``None``
        if the cookie is expired (idle or absolute), tampered, or revoked by an
        epoch bump.
        """
        result = verify_session_token(
            app.secret_key, cookie_val, SESSION_IDLE_MAX_AGE, SESSION_MAX_AGE
        )
        if result is None:
            return None
        username, auth_time, epoch, mfa = result
        # Reject a cookie for an account that no longer exists. In local-user
        # mode a deleted account must not keep a usable session just because the
        # epoch of an absent user defaults to 0 (finding idp-20261003 F11).
        if not use_adfs and username not in users:
            logger.info("Rejected session cookie for unknown user=%s", username)
            return None
        if epoch != _user_session_epoch(username):
            logger.info("Rejected session cookie with stale epoch for user=%s", username)
            return None
        return username, auth_time, mfa

    def _verify_session_cookie(cookie_val: str) -> str | None:
        """Verify a session cookie and return the username, or ``None``.

        Enforces the idle window, the server-side absolute lifetime, and the
        per-user revocation epoch. The account-state gate (disabled /
        must-set-password) is applied by callers that issue credentials.
        """
        result = _verify_session_cookie_full(cookie_val)
        return result[0] if result else None

    def _session_cookie_is_mfa(cookie_val: str) -> bool:
        """True only if the session cookie records a verified second factor.

        Used by privileged entry points to refuse a single-factor cookie
        (finding idp-2026-10-06 F6). A legacy or tampered cookie reads as
        single-factor.
        """
        result = _verify_session_cookie_full(cookie_val)
        return bool(result and result[2])

    def _set_session_cookie(
        resp, username: str, *, auth_time: int | None = None, mfa: bool = False
    ):
        """Set the session cookie on a response (Secure in non-debug mode).

        ``auth_time`` is passed through on re-mint so sliding the idle window
        does not reset the absolute lifetime cap. ``mfa`` records whether a
        real second factor established the session; it is preserved across
        re-mints so a one-factor cookie cannot be upgraded by activity alone.
        """
        resp.set_cookie(
            SESSION_COOKIE_NAME,
            _issue_session_cookie(username, auth_time=auth_time, mfa=mfa),
            max_age=SESSION_MAX_AGE,
            httponly=True,
            samesite="Strict",
            secure=_cookies_secure,
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
        if not form_token or not safe_compare(form_token, cookie_token):
            token = _generate_csrf_token()
            resp = app.make_response(render_template_string(
                USER_PAGE_LOGIN, error="Invalid request (CSRF)", csrf_token=token,
            ))
            resp.set_cookie(
                "csrf_token", token, httponly=True,
                samesite="Strict", secure=_cookies_secure,
            )
            return resp, 403

        action = request.form.get("action", "login")
        client_ip = request.remote_addr or "unknown"

        # Throttle credential-bearing actions on the self-service endpoint.
        if action == "login" and rate_limiter.is_limited(client_ip):
            token = _generate_csrf_token()
            question, ch_hash = _make_challenge()
            resp = app.make_response(render_template_string(
                USER_PAGE_LOGIN, error="Too many attempts. Try again later.",
                csrf_token=token, challenge_question=question, challenge_hash=ch_hash,
            ))
            resp.set_cookie(
                "csrf_token", token, httponly=True,
                samesite="Strict", secure=_cookies_secure,
            )
            return resp, 429

        # Handle TOTP verification for /user access (from TOTP_FORM)
        totp_step = request.form.get("totp_step", "")
        if totp_step == "1" and request.form.get("service_path") == "user":
            # Throttle the second-factor step too, so repeated wrong codes
            # trip the per-IP limiter they now feed. (In practice the password
            # step's own per-IP check usually trips first; this is the belt to
            # that braces.)
            if rate_limiter.is_limited(client_ip):  # pragma: no cover - shadowed by the password-step limiter on the same IP
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    USER_PAGE_LOGIN, error="Too many attempts. Try again later.",
                    csrf_token=token,
                ))
                resp.set_cookie(
                    "csrf_token", token, httponly=True,
                    samesite="Strict", secure=_cookies_secure,
                )
                return resp, 429
            totp_code = request.form.get("totp_code", "")
            # Username is derived from the signed single-use ticket, never the form.
            ticket_info = _read_mfa_ticket(request.form.get("mfa_ticket", ""))
            if ticket_info is None:
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    USER_PAGE_LOGIN, error="Your session expired. Please sign in again.",
                    csrf_token=token,
                ))
                resp.set_cookie(
                    "csrf_token", token, httponly=True,
                    samesite="Strict", secure=_cookies_secure,
                )
                return resp, 401
            username, ticket_nonce = ticket_info
            user = users.get(username)
            # Re-run the full eligibility predicate before granting access — the
            # account can be disabled or locked between the password leg and
            # this second leg (finding idp-2026-10-06 F2).
            if (
                not user
                or not user.get("totp_secret")
                or not _user_can_login(user)
                or _account_locked(username)
            ):
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    USER_PAGE_LOGIN, error="Invalid request. Please sign in again.",
                    csrf_token=token,
                ))
                resp.set_cookie(
                    "csrf_token", token, httponly=True,
                    samesite="Strict", secure=_cookies_secure,
                )
                return resp, 401

            # Burn the ticket before verifying so each ticket is one guess.
            if not _consume_mfa_nonce(username, ticket_nonce):
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    USER_PAGE_LOGIN, error="Your session expired. Please sign in again.",
                    csrf_token=token,
                ))
                resp.set_cookie(
                    "csrf_token", token, httponly=True,
                    samesite="Strict", secure=_cookies_secure,
                )
                return resp, 401

            if not verify_code(user["totp_secret"], totp_code):
                # Record the checked buckets (per-IP + per-account) and count
                # the failure toward lockout — this branch previously fed only
                # the never-read composite key.
                rate_limiter.record(client_ip)
                rate_limiter.record(f"acct:{username}")
                rate_limiter.record(_rl_key(client_ip, username))
                _register_auth_failure(username)
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    TOTP_FORM,
                    error="Invalid code. Try again.",
                    csrf_token=token,
                    mfa_ticket=request.form.get("mfa_ticket", ""),
                    service_path="user",
                ))
                resp.set_cookie(
                    "csrf_token", token, httponly=True,
                    samesite="Strict", secure=_cookies_secure,
                )
                return resp, 401

            _reset_auth_failures(username)
            # TOTP verified — show settings page
            return _render_enroll_page(username)

        if action == "login":
            # Verify challenge
            challenge_answer = request.form.get("challenge_answer", "")
            challenge_hash_val = request.form.get("challenge_hash", "")
            if not _check_challenge(challenge_answer, challenge_hash_val):
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
            # Reject malformed/over-long usernames before any account-keyed
            # state is touched (F1), returning the generic error.
            if username and not _valid_login_username(username):
                rate_limiter.record(client_ip)
                token = _generate_csrf_token()
                question, ch_hash = _make_challenge()
                resp = app.make_response(render_template_string(
                    USER_PAGE_LOGIN, error="Invalid credentials", csrf_token=token,
                    challenge_question=question, challenge_hash=ch_hash,
                ))
                resp.set_cookie(
                    "csrf_token", token, httponly=True,
                    samesite="Strict", secure=_cookies_secure,
                )
                return resp, 401
            # Durable lockout + volatile window, applied uniformly with the SP
            # login path (finding idp-20261003 F6). A hold earned anywhere is
            # honoured here, and failures here count toward the same hold.
            if username and (
                _account_locked(username)
                or rate_limiter.is_limited(f"acct:{username}")
            ):
                # A throttled attempt is still a failed attempt against the
                # account; count it toward the durable lockout so a spray paced
                # under the sliding window still eventually locks the account.
                _register_auth_failure(username)
                audit.log(
                    username=username, ip=client_ip, service="user",
                    protocol="user_settings", result="failure",
                    reason="rate_limited",
                    user_agent=request.headers.get("User-Agent", ""),
                )
                token = _generate_csrf_token()
                question, ch_hash = _make_challenge()
                resp = app.make_response(render_template_string(
                    USER_PAGE_LOGIN, error="Too many attempts. Try again later.",
                    csrf_token=token, challenge_question=question, challenge_hash=ch_hash,
                ))
                resp.set_cookie(
                    "csrf_token", token, httponly=True,
                    samesite="Strict", secure=_cookies_secure,
                )
                return resp, 429
            user = users.get(username)
            if (
                not user
                or not _user_can_login(user)
                or not _check_password(user.get("password", ""), password)
            ):
                rate_limiter.record(_rl_key(client_ip, username))
                rate_limiter.record(client_ip)  # also throttle at the IP level
                if username:
                    rate_limiter.record(f"acct:{username}")  # per-account lockout
                    _register_auth_failure(username)  # durable lockout counter
                audit.log(
                    username=username, ip=client_ip, service="user",
                    protocol="user_settings", result="failure",
                    reason="invalid_credentials",
                    user_agent=request.headers.get("User-Agent", ""),
                )
                token = _generate_csrf_token()
                question, ch_hash = _make_challenge()
                resp = app.make_response(render_template_string(
                    USER_PAGE_LOGIN, error="Invalid credentials", csrf_token=token,
                    challenge_question=question, challenge_hash=ch_hash,
                ))
                resp.set_cookie(
                    "csrf_token", token, httponly=True,
                    samesite="Strict", secure=_cookies_secure,
                )
                return resp, 401

            # If MFA is enabled, require TOTP before granting access
            mfa_enabled = bool(user.get("totp_secret"))
            if mfa_enabled:
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    TOTP_FORM,
                    error=None,
                    csrf_token=token,
                    mfa_ticket=_issue_mfa_ticket(username),
                    service_path="user",
                ))
                resp.set_cookie(
                    "csrf_token", token, httponly=True,
                    samesite="Strict", secure=_cookies_secure,
                )
                return resp

            # No MFA — go straight to enrollment page (full authentication for a
            # TOTP-less account), so clear any durable lockout counters.
            _reset_auth_failures(username)
            return _render_enroll_page(username)

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

            current_password = request.form.get("current_password", "")
            secret_handle = request.form.get("secret_handle", "")
            totp_code = request.form.get("totp_code", "")
            # The secret is read from the server-side store by handle, never
            # from the client — an attacker cannot enrol a secret of their own
            # choosing. A single-use handle also prevents replay.
            totp_secret = _take_enroll_secret(secret_handle)
            user = users.get(username)

            # Re-prove the current password before any second-factor change.
            if not user or not _check_password(user.get("password", ""), current_password):
                return _render_enroll_page(
                    username, status=401, error="Current password is incorrect."
                )
            # Refuse to silently overwrite an existing factor unless the current
            # TOTP code is also supplied and valid.
            if user.get("totp_secret") and not verify_code(
                user["totp_secret"], request.form.get("current_totp", "")
            ):
                return _render_enroll_page(
                    username, status=401,
                    error="An authenticator is already enrolled; it cannot be "
                          "replaced here. Disable it first with a current code.",
                )
            if not totp_secret:
                return _render_enroll_page(
                    username, status=401,
                    error="Your enrolment session expired. Try again.",
                )
            if not verify_code(totp_secret, totp_code):
                return _render_enroll_page(
                    username, status=401, error="Invalid code. Try again."
                )

            # Save the TOTP secret to the user
            if user and users_path:
                user["totp_secret"] = totp_secret
                _bump_session_epoch_local(username)  # revoke sessions on factor change
                _save_users_and_update_mtime(users_path, users)
                logger.info("MFA enrolled for user=%s", username)
                audit.log(
                    username=username,
                    ip=request.remote_addr or "unknown",
                    service="user",
                    protocol="user_settings",
                    result="success",
                    reason="totp_enrolled",
                    user_agent=request.headers.get("User-Agent", ""),
                )

            return _render_enroll_page(username)

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
            current_password = request.form.get("current_password", "")
            current_totp = request.form.get("totp_code", "")

            # Disabling a factor requires re-proving BOTH the password and the
            # current authenticator code, so a stolen step-up token alone (or a
            # stolen password alone) cannot strip the second factor.
            if not user or not _check_password(user.get("password", ""), current_password):
                return _render_enroll_page(
                    username, status=401, error="Current password is incorrect."
                )
            if user.get("totp_secret") and not verify_code(user["totp_secret"], current_totp):
                return _render_enroll_page(
                    username, status=401,
                    error="Enter a valid code from your authenticator to disable MFA.",
                )
            # Anti-lockout: refuse if TOTP is the account's only usable factor.
            # (Defensive: reaching here needs a /user step-up token, which in
            # turn needs a password or passkey, so a genuinely TOTP-only account
            # cannot normally get this far — but the guard stays as a backstop.)
            if not wf.may_remove_totp(user):  # pragma: no cover - backstop; unreachable via the normal step-up flow
                return _render_enroll_page(
                    username, status=400,
                    error="MFA is your only sign-in factor; set a password or add "
                          "a passkey before disabling it.",
                )

            if users_path:
                user.pop("totp_secret", None)
                _bump_session_epoch_local(username)  # revoke sessions on factor change
                _save_users_and_update_mtime(users_path, users)
                audit.log(
                    username=username,
                    ip=request.remote_addr or "unknown",
                    service="user",
                    protocol="user_settings",
                    result="success",
                    reason="totp_removed",
                    user_agent=request.headers.get("User-Agent", ""),
                )
                logger.info("MFA disabled for user=%s", username)

            return _render_enroll_page(username)

        elif action == "force_change":
            # Complete a forced password rotation. Requires the step-up token
            # from the forced-change page, the current password, and a new
            # policy-compliant password. Clears the rotation flag on success.
            auth_token = request.form.get("auth_token", "")
            username = _verify_auth_token(auth_token)
            if not username:
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    USER_PAGE_LOGIN, error="Session expired. Please sign in again.",
                    csrf_token=token,
                ))
                resp.set_cookie(
                    "csrf_token", token, httponly=True,
                    samesite="Strict", secure=_cookies_secure,
                )
                return resp, 401

            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            user = users.get(username)

            error = None
            policy_error = _password_policy_error(new_password)
            if not user or not _check_password(user.get("password", ""), current_password):
                error = "Current password is incorrect."
            elif policy_error is not None:
                error = policy_error
            elif new_password != confirm_password:
                error = "Passwords do not match."
            elif _password_reused(user, new_password):
                error = (
                    f"New password must differ from the last "
                    f"{PASSWORD_HISTORY_SIZE} passwords."
                )

            if error:
                token = _generate_csrf_token()
                resp = app.make_response(render_template_string(
                    FORCED_CHANGE_PAGE,
                    csrf_token=token,
                    auth_token=_issue_auth_token(username),
                    error=error,
                    success=None,
                ))
                resp.set_cookie(
                    "csrf_token", token, httponly=True,
                    samesite="Strict", secure=_cookies_secure,
                )
                return resp, 400

            import bcrypt as _bcrypt
            _record_password_history(user)
            user["password"] = _bcrypt.hashpw(
                new_password.encode(), _bcrypt.gensalt()
            ).decode()
            user.pop("force_password_change", None)
            user.pop("must_set_password", None)
            _bump_session_epoch_local(username)
            if users_path:
                _save_users_and_update_mtime(users_path, users)
            logger.info("Forced password rotation completed for user=%s", username)
            audit.log(
                username=username,
                ip=request.remote_addr or "unknown",
                service="user",
                protocol="user_settings",
                result="success",
                reason="password_changed",
                user_agent=request.headers.get("User-Agent", ""),
            )

            token = _generate_csrf_token()
            resp = app.make_response(render_template_string(
                FORCED_CHANGE_PAGE,
                csrf_token=token,
                auth_token="",
                error=None,
                success="Password updated. Please sign in again to continue.",
            ))
            resp.set_cookie(
                "csrf_token", token, httponly=True,
                samesite="Strict", secure=_cookies_secure,
            )
            return resp

        elif action == "remove_passkey":
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

            credential_id = request.form.get("credential_id", "")
            user = users.get(username)
            # Anti-lockout: refuse to remove the last usable factor. Re-evaluate
            # the same minimum-factor policy enforced when enabling passwordless
            # mode, on the removal side of the transition (finding
            # idp-20261003 F4).
            if user and not wf.may_remove_credential(user, credential_id):  # pragma: no cover - backstop; a lone-passkey account has no /user step-up path
                return _render_enroll_page(
                    username,
                    status=400,
                    error=(
                        "Removing this passkey would leave your account with no "
                        "way to sign in. Set a password or keep another factor "
                        "first."
                    ),
                )
            if user and users_path and wf.remove_credential(user, credential_id):
                _save_users_and_update_mtime(users_path, users)
                logger.info("Passkey removed for user=%s", username)
                audit.log(
                    username=username,
                    ip=client_ip,
                    service="user",
                    protocol="webauthn",
                    result="success",
                    reason="passkey_removed",
                    user_agent=request.headers.get("User-Agent", ""),
                )

            return _render_enroll_page(username)

        elif action in ("set_passwordless", "unset_passwordless"):
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
            passwordless_error = None
            if action == "set_passwordless":
                # Anti-lockout guard (design §10): only allow going password-less
                # if the account retains a recovery path — two passkeys, or one
                # passkey plus a password or TOTP.
                if not user or not wf.meets_passwordless_minimum(user):
                    passwordless_error = (
                        "Register a second passkey (or keep a password/TOTP) "
                        "before enabling password-less sign-in."
                    )
                elif users_path:
                    user[wf.PASSWORDLESS_FIELD] = True
                    _save_users_and_update_mtime(users_path, users)
                    logger.info("Passwordless enabled for user=%s", username)
                    audit.log(
                        username=username, ip=client_ip, service="user",
                        protocol="webauthn", result="success",
                        reason="passwordless_enabled",
                        user_agent=request.headers.get("User-Agent", ""),
                    )
            elif user and users_path:  # unset_passwordless
                user.pop(wf.PASSWORDLESS_FIELD, None)
                _save_users_and_update_mtime(users_path, users)
                logger.info("Passwordless disabled for user=%s", username)
                audit.log(
                    username=username, ip=client_ip, service="user",
                    protocol="webauthn", result="success",
                    reason="passwordless_disabled",
                    user_agent=request.headers.get("User-Agent", ""),
                )

            mfa_enabled = bool(user.get("totp_secret")) if user else False
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
                passwordless_error=passwordless_error,
                **_enroll_passkey_context(username),
            ))
            resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
            return resp, (400 if passwordless_error else 200)

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

            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            user = users.get(username)
            mfa_enabled = bool(user.get("totp_secret")) if user else False

            # Validation. Proof of the current password is required so a stolen
            # step-up token alone cannot silently reset the password.
            password_error = None
            policy_error = _password_policy_error(new_password)
            if not user or not _check_password(user["password"], current_password):
                password_error = "Current password is incorrect."
            elif policy_error is not None:
                password_error = policy_error
            elif new_password != confirm_password:
                password_error = "Passwords do not match."
            elif _password_reused(user, new_password):
                password_error = (
                    f"New password must differ from the last "
                    f"{PASSWORD_HISTORY_SIZE} passwords."
                )

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
                    **_enroll_passkey_context(username),
                ))
                resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                return resp

            # Hash and save the new password
            import bcrypt as _bcrypt
            hashed = _bcrypt.hashpw(new_password.encode(), _bcrypt.gensalt()).decode()
            if user and users_path:
                _record_password_history(user)
                user["password"] = hashed
                _bump_session_epoch_local(username)
                _save_users_and_update_mtime(users_path, users)
                logger.info("Password changed for user=%s", username)
                audit.log(
                    username=username,
                    ip=request.remote_addr or "unknown",
                    service="user",
                    protocol="user_settings",
                    result="success",
                    reason="password_changed",
                    user_agent=request.headers.get("User-Agent", ""),
                )

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
                **_enroll_passkey_context(username),
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

    # --- Passkey (WebAuthn) JSON endpoints ---
    def _json_csrf_ok(payload: dict[str, Any]) -> bool:
        """Validate the CSRF double-submit token from a JSON passkey request."""
        form_token = payload.get("csrf_token", "")
        cookie_token = request.cookies.get("csrf_token", "")
        return bool(form_token) and safe_compare(str(form_token), cookie_token)

    def _passkey_error(message: str, status: int) -> tuple[Response, int]:
        """Return a JSON error response for a passkey endpoint."""
        return jsonify({"error": message}), status

    @app.post("/user/passkey/register/begin")
    def passkey_register_begin():
        """Begin passkey registration for the signed-in self-service user.

        Gated by the same ``PURPOSE_USER`` step-up token as TOTP enrollment. The
        challenge is stashed in the single-use challenge store and its handle is
        returned so ``finish`` can bind the two halves of the ceremony.
        """
        if not _passkey_available():
            return _passkey_error("Passkeys are not enabled.", 404)
        payload = request.get_json(silent=True) or {}
        if not _json_csrf_ok(payload):
            return _passkey_error("Invalid request (CSRF).", 403)
        username = _verify_auth_token(payload.get("auth_token", ""))
        if not username:
            return _passkey_error("Session expired. Please sign in again.", 401)
        user = users.get(username) or {}
        options_json, challenge = wf.begin_registration(
            _webauthn_rp, username, wf.get_credentials(user)
        )
        handle = _passkey_challenges.put(
            challenge=challenge, username=username, purpose="register"
        )
        return jsonify({"handle": handle, "options": json.loads(options_json)})

    @app.post("/user/passkey/register/finish")
    def passkey_register_finish():
        """Verify a registration response and persist the new credential."""
        if not _passkey_available():
            return _passkey_error("Passkeys are not enabled.", 404)
        payload = request.get_json(silent=True) or {}
        if not _json_csrf_ok(payload):
            return _passkey_error("Invalid request (CSRF).", 403)
        username = _verify_auth_token(payload.get("auth_token", ""))
        if not username:
            return _passkey_error("Session expired. Please sign in again.", 401)
        entry = _passkey_challenges.consume(
            payload.get("handle", ""), purpose="register"
        )
        if entry is None or entry.get("username") != username:
            return _passkey_error("Registration session expired.", 400)
        credential_json = json.dumps(payload.get("credential", {}))
        try:
            cred = wf.finish_registration(
                _webauthn_rp, credential_json, entry["challenge"]
            )
        except wf.WebAuthnError as exc:
            logger.info("Passkey registration failed for user=%s: %s", username, exc)
            return _passkey_error("Passkey registration failed.", 400)
        user = users.get(username)
        if not user or not users_path:  # pragma: no cover - user present post step-up
            return _passkey_error("Account not found.", 400)
        transports = (payload.get("credential", {}).get("response", {}) or {}).get(
            "transports", []
        )
        wf.add_credential(
            user,
            credential_id=cred["credential_id"],
            public_key=cred["public_key"],
            sign_count=cred["sign_count"],
            transports=transports if isinstance(transports, list) else [],
            now_iso=_now_iso(),
        )
        _save_users_and_update_mtime(users_path, users)
        logger.info("Passkey registered for user=%s", username)
        audit.log(
            username=username,
            ip=request.remote_addr or "unknown",
            service="user",
            protocol="webauthn",
            result="success",
            reason="passkey_registered",
            user_agent=request.headers.get("User-Agent", ""),
        )
        return jsonify({
            "status": "ok",
            "credential": {
                "credential_id": cred["credential_id"],
                "label": "passkey",
            },
            # Let the page enable the "go password-less" control without a
            # reload once the account meets the minimum-factor policy.
            "passwordless_eligible": wf.meets_passwordless_minimum(user),
        })

    def _issue_passkey_login(username: str, service_path: str):
        """Funnel a verified passkey login into the standard issuance path.

        Mirrors the password→TOTP success tail: stamp last-login, audit, honour
        the forced-rotation gate, then issue SAML or OAuth and set the SSO
        session cookie. Returns a JSON body telling the client where to go.
        """
        sp = _get_service(service_path)
        client_ip = request.remote_addr or "unknown"
        roles = _resolve_roles_from_claims(users.get(username, {}))
        logger.info(
            "Successful passkey login: user=%s service=%s from ip=%s",
            username, service_path, client_ip,
        )
        _record_login(username)
        audit.log(
            username=username,
            ip=client_ip,
            service=service_path,
            protocol=sp.protocol if sp else "saml",
            result="success",
            reason="passkey",
            user_agent=request.headers.get("User-Agent", ""),
        )
        if _needs_password_change(username):
            return jsonify({"redirect": f"/{service_path}"})
        if sp and sp.protocol == "oauth":
            token = build_oauth_token(
                username, key_pem, idp_entity_id,
                client_id=sp.client_id, scopes=sp.scopes,
                token_expiry_minutes=sp.token_expiry_minutes, groups=None,
                claims=users.get(username, {}).get("claims", []),
                email=users.get(username, {}).get("email"),
            )
            # Deliver the JWT in the URL fragment so it never reaches
            # server access logs or the Referer header (idp-20261006 F2).
            resp = jsonify({"redirect": f"{sp.url}#token={token}"})
            _set_session_cookie(resp, username)
            return resp
        sp_acs_url = sp.url if sp else ACS_URL
        sp_provider = sp.provider_name if sp else provider_name
        sp_duration = sp.session_duration_hours if sp else session_duration_hours
        sp_audience = sp.audience if sp and sp.audience else "urn:amazon:webservices"
        saml_b64 = build_saml_response(
            username, roles, cert_pem, key_pem, idp_entity_id,
            provider_name=sp_provider, session_duration_hours=sp_duration,
            acs_url=sp_acs_url, audience=sp_audience,
        )
        html = render_template_string(SAML_POST, acs=sp_acs_url, saml=saml_b64)
        resp = jsonify({"html": html})
        _set_session_cookie(resp, username)
        return resp

    def _passkey_auth_begin(service_path: str):
        """Begin a username-first passkey authentication for an SP flow."""
        if not _passkey_available():
            return _passkey_error("Passkeys are not enabled.", 404)
        payload = request.get_json(silent=True) or {}
        if not _json_csrf_ok(payload):
            return _passkey_error("Invalid request (CSRF).", 403)
        client_ip = request.remote_addr or "unknown"
        if rate_limiter.is_limited(client_ip):
            return _passkey_error("Too many attempts. Try again later.", 429)
        username = payload.get("username", "")
        user = users.get(username)
        # Return a syntactically valid 200 with options in EVERY case so the
        # response shape does not reveal whether the account exists, is enabled,
        # or has a passkey (the enumeration oracle the review flagged). Unknown
        # or ineligible accounts get decoy options over a deterministic dummy
        # credential; their finish step still fails, so no login is possible.
        credentials = (
            wf.get_credentials(user) if user and _user_can_login(user) else []
        )
        if credentials:
            options_json, challenge = wf.begin_authentication(_webauthn_rp, credentials)
        else:
            # Count the probe toward throttling (begin previously recorded
            # nothing, so the is_limited check above could never trip).
            rate_limiter.record(client_ip)
            if username:
                rate_limiter.record(_rl_key(client_ip, username))
            options_json, challenge = wf.begin_authentication_decoy(
                _webauthn_rp, username or client_ip
            )
        handle = _passkey_challenges.put(
            challenge=challenge, username=username, purpose="authenticate"
        )
        return jsonify({"handle": handle, "options": json.loads(options_json)})

    def _passkey_auth_finish(service_path: str):
        """Verify a passkey assertion and issue credentials for the SP."""
        if not _passkey_available():
            return _passkey_error("Passkeys are not enabled.", 404)
        payload = request.get_json(silent=True) or {}
        if not _json_csrf_ok(payload):
            return _passkey_error("Invalid request (CSRF).", 403)
        client_ip = request.remote_addr or "unknown"
        if rate_limiter.is_limited(client_ip):
            return _passkey_error("Too many attempts. Try again later.", 429)
        entry = _passkey_challenges.consume(
            payload.get("handle", ""), purpose="authenticate"
        )
        if entry is None:
            return _passkey_error("Authentication session expired.", 400)
        username = entry["username"]
        # Account-scoped throttle: the gate above only reads the per-IP bucket,
        # so also bound repeated finish failures against one account.
        if username and rate_limiter.is_limited(_rl_key(client_ip, username)):
            return _passkey_error("Too many attempts. Try again later.", 429)  # pragma: no cover - shadowed by the per-IP gate above on the same IP

        def _record_finish_failure() -> None:
            """Record the buckets the gates actually read (per-IP + composite),
            so failed finish attempts are genuinely throttled (F3)."""
            rate_limiter.record(client_ip)
            rate_limiter.record(_rl_key(client_ip, username))

        user = users.get(username)
        # Re-check eligibility at finish: the account could have been disabled
        # between begin and finish (they are separate requests).
        if not user or not _user_can_login(user):
            _record_finish_failure()
            return _passkey_error("Unknown passkey.", 400)
        credential_json = json.dumps(payload.get("credential", {}))
        cred_id = wf.credential_id_from_response(credential_json)
        stored = wf.find_credential(user, cred_id) if cred_id else None
        if stored is None:
            _record_finish_failure()
            return _passkey_error("Unknown passkey.", 400)
        try:
            new_sign_count = wf.finish_authentication(
                _webauthn_rp, credential_json, entry["challenge"], stored
            )
            wf.update_credential_usage(
                stored, new_sign_count=new_sign_count, now_iso=_now_iso()
            )
        except wf.WebAuthnError as exc:
            _record_finish_failure()
            logger.info("Passkey auth failed for user=%s: %s", username, exc)
            audit.log(
                username=username,
                ip=client_ip,
                service=service_path,
                protocol="webauthn",
                result="failure",
                reason="invalid_passkey",
                user_agent=request.headers.get("User-Agent", ""),
            )
            return _passkey_error("Passkey authentication failed.", 401)
        if users_path:
            _save_users_and_update_mtime(users_path, users)
        return _issue_passkey_login(username, service_path)

    def _do_logout(path: str):
        """Revoke the current session server-side and clear the cookies.

        Beyond deleting the ``idp_session`` / ``csrf_token`` cookies, this bumps
        the user's ``session_epoch`` so the surrendered stateless-HMAC cookie
        can no longer be replayed against the session-reuse GET path to mint a
        fresh assertion (finding idp-2026-10-06 F3). A ``csrf_token``
        double-submit check (query/form token vs cookie) makes logout
        unforgeable by a third-party ``<img>``/link, and the event is written to
        the hash-chained audit log.

        Args:
            path: The service path whose logout was invoked (used for the audit
                ``service`` field and the "sign in again" link).

        Returns:
            A Flask response: the logout page on success, or a 403 when the CSRF
            double-submit token is missing or does not match.
        """
        form_token = request.values.get("csrf_token", "")
        cookie_token = request.cookies.get("csrf_token", "")
        if not form_token or not safe_compare(form_token, cookie_token):
            logger.info("Rejected logout for service=%s: CSRF token mismatch", path)
            return app.make_response(("Invalid request (CSRF)", 403))

        username = _verify_session_cookie(
            request.cookies.get(SESSION_COOKIE_NAME, "")
        )
        if username and not use_adfs and users_path is not None and username in users:
            _bump_session_epoch_local(username)
            _save_users_and_update_mtime(users_path, users)

        audit.log(
            username=username or "",
            ip=request.remote_addr or "unknown",
            service=path,
            protocol="session",
            result="success",
            reason="logout",
            user_agent=request.headers.get("User-Agent", ""),
        )
        resp = app.make_response(render_template_string(
            LOGOUT_PAGE, service_path=path,
        ))
        resp.delete_cookie(SESSION_COOKIE_NAME)
        resp.delete_cookie("csrf_token")
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
                    return _do_logout(path)
                _logout.__name__ = f"logout_{path}"
                return _logout

            def _make_pk_begin(path: str):
                def _begin():
                    return _passkey_auth_begin(path)
                _begin.__name__ = f"passkey_begin_{path}"
                return _begin

            def _make_pk_finish(path: str):
                def _finish():
                    return _passkey_auth_finish(path)
                _finish.__name__ = f"passkey_finish_{path}"
                return _finish

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
            app.add_url_rule(
                f"/{sp.path}/passkey/begin", endpoint=f"passkey_begin_{sp.path}",
                view_func=_make_pk_begin(sp.path), methods=["POST"],
            )
            app.add_url_rule(
                f"/{sp.path}/passkey/finish", endpoint=f"passkey_finish_{sp.path}",
                view_func=_make_pk_finish(sp.path), methods=["POST"],
            )
    else:
        # Fallback: single /aws route (backward compatible)
        @app.get("/aws")
        def login_form():
            return _handle_login_form("aws")

        @app.post("/aws")
        def login_post():
            return _handle_login_post("aws")

        @app.post("/aws/passkey/begin")
        def aws_passkey_begin():
            return _passkey_auth_begin("aws")

        @app.post("/aws/passkey/finish")
        def aws_passkey_finish():
            return _passkey_auth_finish("aws")

        @app.get("/aws/logout")
        def logout_aws():
            return _do_logout("aws")

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
        from .admin import validate_recovery_token
        username = validate_recovery_token(recovery_token)
        if not username:
            return render_template_string(
                RECOVERY_PAGE, username="", recovery_token="", csrf_token="",
                error="This recovery link is invalid or has expired.",
                success=None, qr_data_uri="", totp_secret="", mfa_required=False,
            ), 404

        csrf = _generate_csrf_token()
        if users.get(username, {}).get("totp_secret"):
            # Already enrolled: verify against the existing secret, do not
            # re-enroll. Show a "confirm current MFA code" field, not a QR.
            page = render_template_string(
                RECOVERY_PAGE, username=username, recovery_token=recovery_token,
                csrf_token=csrf, error=None, success=None,
                qr_data_uri="", totp_secret="", mfa_required=True,
            )
        else:
            # Not enrolled: offer optional MFA enrollment with a fresh secret.
            totp_secret = generate_secret()
            uri = provisioning_uri(
                totp_secret, username, issuer="idp.botthouse.net"
            )
            page = render_template_string(
                RECOVERY_PAGE, username=username, recovery_token=recovery_token,
                csrf_token=csrf, error=None, success=None,
                qr_data_uri=qr_code_data_uri(uri), totp_secret=totp_secret,
                mfa_required=False,
            )

        resp = app.make_response(page)
        resp.set_cookie(
            "csrf_token", csrf, httponly=True, samesite="Strict", secure=_cookies_secure
        )
        return resp

    @app.post("/recover/<recovery_token>")
    def recover_post(recovery_token: str):
        from .admin import consume_recovery_token, validate_recovery_token

        # CSRF: double-submit check (was missing entirely).
        form_token = request.form.get("csrf_token", "")
        cookie_token = request.cookies.get("csrf_token", "")
        if not form_token or not safe_compare(form_token, cookie_token):
            return render_template_string(
                RECOVERY_PAGE, username="", recovery_token="", csrf_token="",
                error="Invalid request (CSRF). Reload the page and try again.",
                success=None, qr_data_uri="", totp_secret="", mfa_required=False,
            ), 403

        # Rate limit recovery attempts per IP.
        client_ip = request.remote_addr or "unknown"
        if rate_limiter.is_limited(client_ip):
            return render_template_string(
                RECOVERY_PAGE, username="", recovery_token="", csrf_token="",
                error="Too many attempts. Try again later.",
                success=None, qr_data_uri="", totp_secret="", mfa_required=False,
            ), 429

        username = validate_recovery_token(recovery_token)
        if not username:
            rate_limiter.record(client_ip)
            return render_template_string(
                RECOVERY_PAGE, username="", recovery_token="", csrf_token="",
                error="This recovery link is invalid or has expired.",
                success=None, qr_data_uri="", totp_secret="", mfa_required=False,
            ), 404

        # Honour a durable account lockout on the recovery path too (F6), so a
        # held account cannot be guessed at via /recover.
        if _account_locked(username):
            audit.log(
                username=username, ip=client_ip, service="user",
                protocol="recovery", result="failure", reason="rate_limited",
                user_agent=request.headers.get("User-Agent", ""),
            )
            return render_template_string(
                RECOVERY_PAGE, username="", recovery_token="", csrf_token="",
                error="Too many attempts. Try again later.",
                success=None, qr_data_uri="", totp_secret="", mfa_required=False,
            ), 429

        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        totp_code = request.form.get("totp_code", "")

        # Determine MFA mode from the user's existing enrollment, NOT from the
        # form. An already-enrolled user must confirm their CURRENT authenticator
        # code (verified against their stored secret); a not-yet-enrolled user
        # may optionally enroll a fresh secret shown as a QR on the page.
        enrolled_secret = users.get(username, {}).get("totp_secret", "")
        is_enrolled = bool(enrolled_secret)
        # The enrollment secret only comes from the form for non-enrolled users.
        enroll_secret = "" if is_enrolled else request.form.get("totp_secret", "")

        def _rerender(error: str):
            """Re-render the recovery page in the correct MFA mode on error."""
            if is_enrolled:
                return render_template_string(
                    RECOVERY_PAGE, username=username,
                    recovery_token=recovery_token, csrf_token=form_token,
                    error=error, success=None, qr_data_uri="", totp_secret="",
                    mfa_required=True,
                )
            uri = provisioning_uri(
                enroll_secret, username, issuer="idp.botthouse.net"
            )
            return render_template_string(
                RECOVERY_PAGE, username=username, recovery_token=recovery_token,
                csrf_token=form_token, error=error, success=None,
                qr_data_uri=qr_code_data_uri(uri), totp_secret=enroll_secret,
                mfa_required=False,
            )

        # Validate password against the complexity policy.
        policy_error = _password_policy_error(new_password)
        if policy_error is not None:
            return _rerender(policy_error)
        if new_password != confirm_password:
            return _rerender("Passwords do not match.")

        # MFA handling.
        mfa_enrolled = False
        if is_enrolled:
            # Enrolled users must prove their existing MFA to reset.
            if not verify_code(enrolled_secret, totp_code):
                rate_limiter.record(client_ip)
                _register_auth_failure(username)  # count toward durable lockout
                return _rerender("Invalid MFA code. Try again.")
        elif totp_code and enroll_secret:
            # Optional enrollment for users without MFA.
            if not verify_code(enroll_secret, totp_code):
                rate_limiter.record(client_ip)
                return _rerender("Invalid MFA code. Try again.")
            mfa_enrolled = True

        # Reject reuse of a recent password on the recovery path too.
        user = users.get(username)
        if user and _password_reused(user, new_password):
            return _rerender(
                f"New password must differ from the last "
                f"{PASSWORD_HISTORY_SIZE} passwords."
            )

        # Apply changes
        import bcrypt as _bcrypt
        if user:
            _record_password_history(user)
            user["password"] = _bcrypt.hashpw(new_password.encode(), _bcrypt.gensalt()).decode()
            user.pop("must_set_password", None)
            if mfa_enrolled:
                user["totp_secret"] = enroll_secret
            _reset_auth_failures(username)  # successful recovery clears the hold
            _bump_session_epoch_local(username)
            if users_path:
                _save_users_and_update_mtime(users_path, users)
            logger.info("Recovery completed for user=%s (MFA=%s)", username, mfa_enrolled)
            audit.log(
                username=username,
                ip=request.remote_addr or "unknown",
                service="user",
                protocol="recovery",
                result="success",
                reason="password_reset",
                user_agent=request.headers.get("User-Agent", ""),
            )

        # Consume the token (single-use)
        consume_recovery_token(recovery_token)

        mfa_msg = " MFA has been enabled." if mfa_enrolled else ""
        return render_template_string(
            RECOVERY_PAGE, username=username, recovery_token="", csrf_token="",
            error=None, success=f"Password updated successfully.{mfa_msg} You can now log in.",
            qr_data_uri="", totp_secret="", mfa_required=False,
        )

    # --- Admin panel ---
    def _save_users_and_update_mtime(path: Path, user_dict: dict[str, Any]) -> None:
        """Save users and refresh the content-hash tracker after our own write."""
        nonlocal users_digest
        _save_users(path, user_dict)
        users_digest = _users_digest(path)

    def _record_login(username: str) -> None:
        """Stamp the account's last-login time for lifecycle/inactivity review."""
        if use_adfs or users_path is None:
            return
        user = users.get(username)
        if not user:  # pragma: no cover - defensive: user is always present here (just authenticated)
            return
        user["last_login"] = _now_iso()
        try:
            _save_users_and_update_mtime(users_path, users)
        except OSError:
            logger.warning("Could not persist last_login for user=%s", username)

    def _account_locked(username: str) -> bool:
        """True if the account is currently within a durable lockout hold."""
        if use_adfs or not username:
            return False
        user = users.get(username)
        if not user:
            return False
        try:
            locked_until = float(user.get("locked_until", 0))
        except (TypeError, ValueError):
            return False
        return locked_until > time.time()

    def _register_auth_failure(username: str) -> None:
        """Count a failed authentication and lock the account past the threshold.

        Persists ``failed_count`` and, once it reaches ``LOCKOUT_THRESHOLD``, a
        ``locked_until`` timestamp. Unlike the in-memory sliding window this
        survives process restarts and does not self-clear while the attacker
        paces their guesses.
        """
        if use_adfs or users_path is None or not username:
            return
        user = users.get(username)
        if not user:
            return
        try:
            count = int(user.get("failed_count", 0)) + 1
        except (TypeError, ValueError):
            count = 1
        user["failed_count"] = count
        if count >= LOCKOUT_THRESHOLD:
            user["locked_until"] = time.time() + LOCKOUT_DURATION_SECONDS
            logger.warning("Account locked after %d failures: user=%s", count, username)
        try:
            _save_users_and_update_mtime(users_path, users)
        except OSError:  # pragma: no cover - defensive
            logger.warning("Could not persist lockout state for user=%s", username)

    def _reset_auth_failures(username: str) -> None:
        """Clear lockout counters after a fully successful authentication."""
        if use_adfs or users_path is None or not username:
            return
        user = users.get(username)
        if not user or not (user.get("failed_count") or user.get("locked_until")):
            return
        user.pop("failed_count", None)
        user.pop("locked_until", None)
        try:
            _save_users_and_update_mtime(users_path, users)
        except OSError:  # pragma: no cover - defensive
            logger.warning("Could not clear lockout state for user=%s", username)

    def _bump_session_epoch_local(username: str) -> None:
        """Invalidate the account's outstanding session cookies (self-service).

        Mirrors the admin-side bump: a password change must revoke sessions
        established under the old credential.
        """
        user = users.get(username)
        if not user:  # pragma: no cover - callers always pass an existing user
            return
        try:
            current = int(user.get("session_epoch", 0))
        except (TypeError, ValueError):
            current = 0
        user["session_epoch"] = current + 1

    def _password_reused(user: dict[str, Any], new_password: str) -> bool:
        """True if ``new_password`` matches the current or a recent hash."""
        if _check_password(user.get("password", ""), new_password):
            return True
        for old_hash in user.get("password_history", []):
            if _check_password(old_hash, new_password):
                return True
        return False

    def _record_password_history(user: dict[str, Any]) -> None:
        """Push the current password hash onto the bounded history list.

        Call AFTER setting ``user['password']`` to the new hash is wrong; call
        with the OLD hash still in place. The caller passes the user dict before
        the new hash is assigned, so the retiring hash is captured here.
        """
        current = user.get("password", "")
        if not current:  # pragma: no cover - change paths always have a current password
            return
        history = list(user.get("password_history", []))
        history.insert(0, current)
        # Keep the last N-1 retired hashes; the live hash is the Nth slot.
        user["password_history"] = history[: PASSWORD_HISTORY_SIZE - 1]

    def _needs_password_change(username: str) -> bool:
        """True if the account must change its password before proceeding.

        A forced password rotation is meaningless for a password-less (passkey-
        only) account — there is no password to change and the forced-change
        page requires the current password — so the gate is skipped for those.
        """
        if use_adfs:
            return False
        user = users.get(username)
        if not user or not user.get("force_password_change"):
            return False
        return not wf.is_passwordless(user)

    def _forced_change_response(username: str):
        """Render the forced password-change page instead of issuing credentials.

        The user has already authenticated (password + MFA), so a short-lived
        step-up token is issued to bind the subsequent change to this session.
        No SAML/JWT/session cookie is set until the password is changed.
        """
        auth_token = _issue_auth_token(username)
        token = _generate_csrf_token()
        resp = app.make_response(render_template_string(
            FORCED_CHANGE_PAGE,
            csrf_token=token,
            auth_token=auth_token,
            error=None,
            success=None,
        ))
        resp.set_cookie(
            "csrf_token", token, httponly=True,
            samesite="Strict", secure=_cookies_secure,
        )
        return resp

    from .admin import register_admin_routes
    register_admin_routes(
        app, users, users_path, _check_password, _save_users_and_update_mtime,
        make_challenge_fn=_make_challenge,
        verify_challenge_fn=_check_challenge,
        services_path=services_path,
        verify_session_cookie_fn=_verify_session_cookie,
        session_mfa_fn=_session_cookie_is_mfa,
        set_session_cookie_fn=_set_session_cookie,
        audit_logger=audit,
        data_dir=data,
        rate_limiter=rate_limiter,
        rate_limit_key_fn=_rl_key,
        validate_username_fn=_validate_username,
        validate_claim_fn=_validate_claim,
        password_policy_fn=_password_policy_error,
        account_locked_fn=_account_locked,
        register_auth_failure_fn=_register_auth_failure,
        reset_auth_failures_fn=_reset_auth_failures,
        webauthn_rp=_webauthn_rp,
        passkey_challenges=_passkey_challenges,
        passkey_available_fn=_passkey_available,
    )

    return app
