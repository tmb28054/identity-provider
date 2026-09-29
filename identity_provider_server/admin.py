"""Admin panel for user and claims management.

Accessible at /admin to users with the 'idpadmin' claim.
"""

from __future__ import annotations

import hmac
import json
import logging
import secrets
import subprocess  # nosec
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, g, jsonify, render_template_string, request

from . import backup as bk
from . import webauthn_flows as wf
from .tokens import PURPOSE_ADMIN, issue_token, verify_token
from .totp import verify_code

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string (lifecycle stamps)."""
    return datetime.now(timezone.utc).isoformat()

# Path to the venv python + data dir are needed to trigger the privileged
# backup/restore units and the connection test via sudo. These match the
# deploy layout (scripts/deploy.py).
_SUDO = "/usr/bin/sudo"
_SYSTEMCTL = "/bin/systemctl"

ADMIN_LOGIN = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Login</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #1a1a2e; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #fff; border-radius: 8px; box-shadow: 0 4px 24px rgba(0,0,0,0.3);
      padding: 2rem; width: 100%; max-width: 380px; }
    h1 { font-size: 1.4rem; margin-bottom: 1.5rem; color: #232f3e; }
    label { display: block; font-size: 0.85rem; color: #555; margin-bottom: 0.3rem; }
    input[type="text"], input[type="password"] { width: 100%; padding: 0.6rem 0.75rem;
      border: 1px solid #ccc; border-radius: 4px; font-size: 0.95rem; margin-bottom: 1rem; }
    button { width: 100%; padding: 0.7rem; background: #232f3e; color: #fff; border: none;
      border-radius: 4px; font-size: 1rem; cursor: pointer; }
    button:hover { background: #37475a; }
    .error { color: #d13212; font-size: 0.85rem; margin-bottom: 1rem; }
    .challenge { background: #f0f4f8; border: 1px solid #d5dce6; border-radius: 4px;
      padding: 0.75rem; margin-bottom: 1rem; text-align: center; }
    .challenge-question { font-size: 1.1rem; font-weight: 600; color: #232f3e; margin-bottom: 0.5rem; }
    .challenge-label { font-size: 0.75rem; color: #666; text-transform: uppercase; letter-spacing: 0.5px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Admin Panel</h1>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="hidden" name="challenge_hash" value="{{ challenge_hash }}">
      <input type="hidden" name="action" value="login">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" required autofocus>
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required>
      <label for="totp_code">MFA Code (if enabled)</label>
      <input type="text" id="totp_code" name="totp_code" maxlength="6" pattern="[0-9]{6}"
             autocomplete="one-time-code" inputmode="numeric" placeholder="6-digit code">
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
            data-begin-url="/admin/passkey/begin"
            data-finish-url="/admin/passkey/finish"
            data-csrf="{{ csrf_token }}">Use a passkey</button>
    <p id="passkey-status" class="error" style="margin-top:0.75rem;"></p>
    <script src="/static/passkey.js?v={{ passkey_js_version }}" defer></script>
    {% endif %}
  </div>
</body>
</html>
"""

ADMIN_PANEL = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Panel</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f4f6f9; padding: 2rem; }
    .container { max-width: 900px; margin: 0 auto; }
    h1 { font-size: 1.6rem; color: #232f3e; margin-bottom: 1.5rem; }
    h2 { font-size: 1.2rem; color: #232f3e; margin: 2rem 0 1rem; border-bottom: 2px solid #0073bb; padding-bottom: 0.5rem; }
    .card { background: #fff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.06);
      padding: 1.5rem; margin-bottom: 1.5rem; }
    table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
    th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #eee; }
    th { background: #f8f9fa; font-weight: 600; color: #555; }
    .badge { display: inline-block; background: #e8f5e9; color: #1d8102; padding: 2px 8px;
      border-radius: 12px; font-size: 0.75rem; margin: 1px 2px; }
    .badge-mfa { background: #e3f2fd; color: #0073bb; }
    label { display: block; font-size: 0.85rem; color: #555; margin-bottom: 0.3rem; }
    input[type="text"], input[type="password"], select { width: 100%; padding: 0.5rem 0.6rem;
      border: 1px solid #ccc; border-radius: 4px; font-size: 0.9rem; margin-bottom: 0.75rem; }
    .form-row { display: flex; gap: 0.75rem; align-items: flex-end; }
    .form-row > div { flex: 1; }
    button, .btn { padding: 0.5rem 1rem; background: #0073bb; color: #fff; border: none;
      border-radius: 4px; font-size: 0.85rem; cursor: pointer; text-decoration: none; display: inline-block; }
    button:hover, .btn:hover { background: #005a94; }
    .btn-sm { padding: 0.3rem 0.6rem; font-size: 0.75rem; }
    .btn-danger { background: #d13212; }
    .btn-danger:hover { background: #a82610; }
    .btn-warning { background: #ff9900; }
    .btn-warning:hover { background: #cc7a00; }
    .success { color: #1d8102; font-size: 0.9rem; margin-bottom: 1rem; padding: 0.5rem;
      background: #e8f5e9; border-radius: 4px; }
    .error { color: #d13212; font-size: 0.9rem; margin-bottom: 1rem; padding: 0.5rem;
      background: #fde8e8; border-radius: 4px; }
    .actions form { display: inline; }
  </style>
</head>
<body>
<div class="container">
  <h1>Admin Panel <a href="/admin" style="font-size:0.7rem;color:#0073bb;text-decoration:none;margin-left:1rem;">↻ Reload</a>
  <a href="/admin/audit-log" style="font-size:0.7rem;color:#0073bb;text-decoration:none;margin-left:1rem;">Audit Log</a>
  <a href="/admin/backups" style="font-size:0.7rem;color:#0073bb;text-decoration:none;margin-left:1rem;">Backups</a></h1>
  {% if backup_failing %}<div style="background:#fde8e8;border:1px solid #f5b5b5;color:#d13212;padding:0.6rem 1rem;border-radius:6px;margin-bottom:1rem;font-size:0.85rem;font-weight:600;">⚠ The last backup failed. <a href="/admin/backups" style="color:#d13212;">View backups →</a></div>{% endif %}
  {% if message %}<p class="success">{{ message }}</p>{% endif %}
  {% if error %}<p class="error">{{ error }}</p>{% endif %}

  <h2>Users</h2>
  <div class="card">
    <table>
      <tr><th>Username</th><th>Email</th><th>Claims</th><th>MFA</th><th>Actions</th></tr>
      {% for u in users_list %}
      <tr>
        <td><a href="/admin/user/{{ u.username }}" style="color:#0073bb;text-decoration:none;font-weight:600;">{{ u.username }}</a></td>
        <td style="font-size:0.85rem;">{{ u.get('email', '') }}</td>
        <td>{% for c in u.get('claims', []) %}<span class="badge">{{ c }}</span>{% endfor %}</td>
        <td>{% if u.get('totp_secret') %}<span class="badge badge-mfa">MFA</span>{% else %}—{% endif %}</td>
        <td class="actions">
          <form method="post" style="display:inline-flex;align-items:center;gap:0.25rem;">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="hidden" name="auth_token" value="{{ auth_token }}">
            <input type="hidden" name="action" value="reset_password">
            <input type="hidden" name="target_user" value="{{ u.username }}">
            <input type="password" name="new_pw" placeholder="New password"
              minlength="12" required
              style="width:9rem;padding:0.2rem 0.4rem;margin-bottom:0;font-size:0.8rem;">
            <button class="btn-sm btn-warning">Reset PW</button>
          </form>
          {% if u.get('totp_secret') %}
          <form method="post" style="display:inline">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="hidden" name="auth_token" value="{{ auth_token }}">
            <input type="hidden" name="action" value="remove_mfa">
            <input type="hidden" name="target_user" value="{{ u.username }}">
            <button class="btn-sm btn-warning">Remove MFA</button>
          </form>
          {% endif %}
          <form method="post" style="display:inline" data-confirm="Delete this user?">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="hidden" name="auth_token" value="{{ auth_token }}">
            <input type="hidden" name="action" value="delete_user">
            <input type="hidden" name="target_user" value="{{ u.username }}">
            <button class="btn-sm btn-danger">Delete</button>
          </form>
        </td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <h2>Add User</h2>
  <div class="card">
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="hidden" name="auth_token" value="{{ auth_token }}">
      <input type="hidden" name="action" value="add_user">
      <div class="form-row">
        <div><label>Username</label><input type="text" name="new_username" required></div>
        <div><label>Password</label><input type="password" name="new_user_password" required minlength="8"></div>
      </div>
      <label>Email</label>
      <input type="text" name="new_user_email" placeholder="user@example.com">
      <label>Claims (comma-separated)</label>
      <input type="text" name="new_user_claims" placeholder="e.g. idpadmin,developer">
      <button type="submit">Add User</button>
    </form>
  </div>

  <h2>Claims Registry</h2>
  <div class="card">
    <p style="font-size:0.85rem;color:#555;margin-bottom:0.75rem;">Defined claims (click a username above to assign claims to users):</p>
    <div style="margin-bottom:1rem;">
      {% for c in all_claims %}<span class="badge" style="font-size:0.85rem;padding:4px 10px;">{{ c }}
        <form method="post" style="display:inline">
          <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
          <input type="hidden" name="auth_token" value="{{ auth_token }}">
          <input type="hidden" name="action" value="delete_claim">
          <input type="hidden" name="claim_name" value="{{ c }}">
          <button style="background:none;border:none;color:#d13212;cursor:pointer;font-size:0.75rem;padding:0 3px;" title="Delete claim" data-confirm="Delete this claim? It will be removed from all users.">✕</button>
        </form>
      </span>{% endfor %}
      {% if not all_claims %}<span style="color:#888;font-size:0.85rem;">No claims defined yet.</span>{% endif %}
    </div>
    <form method="post" style="display:flex;gap:0.5rem;align-items:flex-end;">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="hidden" name="auth_token" value="{{ auth_token }}">
      <input type="hidden" name="action" value="add_claim">
      <div style="flex:1;"><label>New claim name</label><input type="text" name="claim_name" required pattern="[a-zA-Z0-9_-]+" placeholder="e.g. wiki-admin" style="margin-bottom:0;"></div>
      <button type="submit" style="margin-bottom:0;">Add Claim</button>
    </form>
  </div>

  <h2>Service Providers</h2>
  <div class="card">
    <table>
      <tr><th>Path</th><th>Protocol</th><th>URL</th><th>Token Duration</th><th>Actions</th></tr>
      {% for sp in sp_list %}
      <tr>
        <td><code>/{{ sp.path }}</code></td>
        <td><span class="badge">{{ sp.protocol }}</span></td>
        <td style="font-size:0.8rem;word-break:break-all;">{{ sp.url }}</td>
        <td>
          <form method="post" style="display:inline-flex;align-items:center;gap:0.3rem;">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="hidden" name="auth_token" value="{{ auth_token }}">
            <input type="hidden" name="action" value="update_sp_duration">
            <input type="hidden" name="sp_protocol" value="{{ sp.protocol }}">
            <input type="hidden" name="sp_path" value="{{ sp.path }}">
            <input type="number" name="sp_token_duration"
              value="{{ sp.token_duration }}" min="1" max="720"
              style="width:5rem;padding:0.2rem 0.4rem;
              margin-bottom:0;font-size:0.85rem;">
            <span style="font-size:0.8rem;color:#555;">min</span>
            <button class="btn-sm" style="padding:0.2rem 0.5rem;">Save</button>
          </form>
        </td>
        <td class="actions">
          <form method="post" style="display:inline" data-confirm="Delete this service provider?">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="hidden" name="auth_token" value="{{ auth_token }}">
            <input type="hidden" name="action" value="delete_sp">
            <input type="hidden" name="sp_protocol" value="{{ sp.protocol }}">
            <input type="hidden" name="sp_path" value="{{ sp.path }}">
            <button class="btn-sm btn-danger">Delete</button>
          </form>
        </td>
      </tr>
      {% endfor %}
      {% if not sp_list %}
      <tr><td colspan="5" style="text-align:center;color:#888;">No service providers configured.</td></tr>
      {% endif %}
    </table>
  </div>

  <h2>Add / Update Service Provider</h2>
  <div class="card">
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="hidden" name="auth_token" value="{{ auth_token }}">
      <input type="hidden" name="action" value="upsert_sp">
      <div class="form-row">
        <div>
          <label>Protocol</label>
          <select name="sp_protocol">
            <option value="saml">SAML</option>
            <option value="oauth">OAuth</option>
          </select>
        </div>
        <div><label>Path (e.g. aws, gitlab)</label><input type="text" name="sp_path" required pattern="[a-zA-Z0-9_-]+" placeholder="myapp"></div>
      </div>
      <label>Service Provider URL</label>
      <input type="text" name="sp_url" required placeholder="https://example.com/saml/acs">
      <div class="form-row">
        <div>
          <label>Token duration (minutes)</label>
          <input type="number" name="sp_token_duration" min="1" max="720" value="60" placeholder="60">
          <p style="font-size:0.75rem;color:#888;margin-top:-0.5rem;">SAML: session duration. OAuth: JWT expiry. Default: 60 min.</p>
        </div>
      </div>
      <button type="submit">Add / Update SP</button>
    </form>
  </div>
</div>
<script nonce="{{ csp_nonce }}">
// Confirmation guard for destructive actions. The message is a static string
// from a data-confirm attribute; no server-supplied value is ever evaluated
// as JavaScript, which closes the previous inline-handler XSS.
document.addEventListener("submit", function (e) {
  var msg = e.target.getAttribute && e.target.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) { e.preventDefault(); }
});
document.addEventListener("click", function (e) {
  var el = e.target.closest ? e.target.closest("[data-confirm]") : null;
  if (el && el.tagName === "BUTTON" && !el.form) {
    var msg = el.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) { e.preventDefault(); }
  }
});
</script>
</body>
</html>
"""


ADMIN_USER_DETAIL = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>User: {{ user.username }}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f4f6f9; padding: 2rem; }
    .container { max-width: 700px; margin: 0 auto; }
    h1 { font-size: 1.6rem; color: #232f3e; margin-bottom: 0.5rem; }
    .subtitle { font-size: 0.9rem; color: #555; margin-bottom: 1.5rem; }
    h2 { font-size: 1.2rem; color: #232f3e; margin: 2rem 0 1rem; border-bottom: 2px solid #0073bb; padding-bottom: 0.5rem; }
    .card { background: #fff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.06);
      padding: 1.5rem; margin-bottom: 1.5rem; }
    .badge { display: inline-flex; align-items: center; background: #e8f5e9; color: #1d8102; padding: 4px 10px;
      border-radius: 12px; font-size: 0.85rem; margin: 3px 4px; }
    .badge form { display: inline; margin-left: 6px; }
    .badge button { background: none; border: none; color: #d13212; cursor: pointer; font-size: 0.8rem; padding: 0; }
    label { display: block; font-size: 0.85rem; color: #555; margin-bottom: 0.3rem; }
    select, input[type="text"] { width: 100%; padding: 0.5rem 0.6rem; border: 1px solid #ccc;
      border-radius: 4px; font-size: 0.9rem; margin-bottom: 0.75rem; }
    button, .btn { padding: 0.5rem 1rem; background: #0073bb; color: #fff; border: none;
      border-radius: 4px; font-size: 0.85rem; cursor: pointer; text-decoration: none; display: inline-block; }
    button:hover, .btn:hover { background: #005a94; }
    .back-link { display: inline-block; margin-bottom: 1rem; color: #0073bb; text-decoration: none; font-size: 0.9rem; }
    .back-link:hover { text-decoration: underline; }
    .success { color: #1d8102; font-size: 0.9rem; margin-bottom: 1rem; padding: 0.5rem;
      background: #e8f5e9; border-radius: 4px; }
    .error { color: #d13212; font-size: 0.9rem; margin-bottom: 1rem; padding: 0.5rem;
      background: #fde8e8; border-radius: 4px; }
    .info-row { display: flex; gap: 2rem; margin-bottom: 0.5rem; font-size: 0.9rem; }
    .info-row .label { color: #555; min-width: 80px; }
  </style>
</head>
<body>
<div class="container">
  <a href="/admin" class="back-link">← Back to Admin Panel</a>
  <h1>{{ user.username }}</h1>
  <p class="subtitle">{{ user.get('email', 'No email set') }}</p>
  {% if message %}<p class="success">{{ message }}</p>{% endif %}
  {% if error %}<p class="error">{{ error }}</p>{% endif %}

  <h2>User Claims</h2>
  <div class="card">
    <div style="margin-bottom:1rem;">
      {% for c in user.get('claims', []) %}
      <span class="badge">{{ c }}
        <form method="post">
          <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
          <input type="hidden" name="auth_token" value="{{ auth_token }}">
          <input type="hidden" name="action" value="remove_user_claim">
          <input type="hidden" name="claim_name" value="{{ c }}">
          <button type="submit" title="Remove this claim">✕</button>
        </form>
      </span>
      {% endfor %}
      {% if not user.get('claims', []) %}<span style="color:#888;font-size:0.85rem;">No claims assigned.</span>{% endif %}
    </div>

    <form method="post" style="display:flex;gap:0.5rem;align-items:flex-end;">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="hidden" name="auth_token" value="{{ auth_token }}">
      <input type="hidden" name="action" value="add_user_claim">
      <div style="flex:1;">
        <label>Add claim</label>
        <select name="claim_name" style="margin-bottom:0;">
          {% for c in available_claims %}<option value="{{ c }}">{{ c }}</option>{% endfor %}
          {% if not available_claims %}<option disabled>No claims available to add</option>{% endif %}
        </select>
      </div>
      <button type="submit" style="margin-bottom:0;" {% if not available_claims %}disabled{% endif %}>Add</button>
    </form>
  </div>

  <h2>Details</h2>
  <div class="card">
    <div class="info-row"><span class="label">Username:</span> {{ user.username }}</div>
    <div class="info-row"><span class="label">Email:</span> {{ user.get('email', '—') }}</div>
    <div class="info-row"><span class="label">MFA:</span> {{ 'Enabled' if user.get('totp_secret') else 'Disabled' }}</div>
    <div class="info-row"><span class="label">Claims:</span> {{ user.get('claims', [])|length }}</div>
  </div>

  <h2>Recovery Link</h2>
  <div class="card">
    <p style="font-size:0.85rem;color:#555;margin-bottom:0.75rem;">Generate a one-time link for this user to reset their password and set up MFA. The link expires after 24 hours.</p>
    {% if recovery_url %}
    <div style="background:#f0f4f8;border:1px solid #d5dce6;border-radius:4px;padding:0.75rem;margin-bottom:1rem;word-break:break-all;font-family:monospace;font-size:0.85rem;">{{ recovery_url }}</div>
    <p style="font-size:0.8rem;color:#888;">Copy this link and send it to the user. It can only be used once.</p>
    {% else %}
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="hidden" name="auth_token" value="{{ auth_token }}">
      <input type="hidden" name="action" value="generate_recovery">
      <button type="submit">Generate Recovery Link</button>
    </form>
    {% endif %}
  </div>
</div>
</body>
</html>
"""


def register_admin_routes(
    app: Flask,
    users: dict[str, Any],
    users_path: Path | None,
    check_password_fn,
    save_users_fn,
    make_challenge_fn=None,
    verify_challenge_fn=None,
    services_path: Path | None = None,
    reload_services_fn=None,
    verify_session_cookie_fn=None,
    set_session_cookie_fn=None,
    audit_logger=None,
    data_dir: Path | None = None,
    rate_limiter=None,
    rate_limit_key_fn=None,
    validate_username_fn=None,
    validate_claim_fn=None,
    password_policy_fn=None,
    webauthn_rp=None,
    passkey_challenges=None,
    passkey_available_fn=None,
) -> None:
    """Register /admin routes on the Flask app.

    The optional ``webauthn_rp`` / ``passkey_challenges`` /
    ``passkey_available_fn`` arguments enable admin passkey login (Phase 3): a
    two-step WebAuthn ceremony that funnels into the same ``idpadmin`` check and
    shared ``idp_session`` issuance as the password + TOTP form.
    """

    def _rl_key(username: str = "") -> str:
        """Build a rate-limit key for the current request."""
        ip = request.remote_addr or "unknown"
        if rate_limit_key_fn:
            return rate_limit_key_fn(ip, username)
        return f"{ip}|{username}" if username else ip

    def _rl_limited(username: str = "") -> bool:
        return bool(rate_limiter) and rate_limiter.is_limited(_rl_key(username))

    def _rl_record(username: str = "") -> None:
        if rate_limiter:
            rate_limiter.record(_rl_key(username))

    def _csrf_token() -> str:
        return secrets.token_hex(32)

    ADMIN_TOKEN_MAX_AGE = 3600  # 1 hour

    def _issue_token(username: str) -> str:
        """Issue a purpose-scoped admin authorization token."""
        return issue_token(app.secret_key, username, PURPOSE_ADMIN)

    def _verify_token(token: str, max_age: int = ADMIN_TOKEN_MAX_AGE) -> str | None:
        """Verify an admin token; rejects tokens minted for any other purpose."""
        return verify_token(app.secret_key, token, PURPOSE_ADMIN, max_age)

    def _has_claim(username: str, claim: str) -> bool:
        user = users.get(username)
        if not user:
            return False
        return claim in user.get("claims", [])

    def _require_admin(auth_token: str) -> str | None:
        """Return the admin username if the token is valid and holds idpadmin.

        Central authorization predicate for state-changing admin actions, so
        the check is defined once rather than copied per handler.
        """
        admin_user = _verify_token(auth_token)
        if not admin_user or not _has_claim(admin_user, "idpadmin"):
            return None
        return admin_user

    def _audit_admin(admin_user: str, mutation: str, target: str = "") -> None:
        """Record a privileged admin mutation in the audit log.

        Args:
            admin_user: The acting administrator.
            mutation: A short action name (e.g. ``add_user``).
            target: The affected object (username, claim, SP path).
        """
        if not audit_logger:
            return
        audit_logger.log(
            username=admin_user,
            ip=request.remote_addr or "unknown",
            service="admin",
            protocol="admin",
            result="mutation",
            reason=f"{mutation}:{target}" if target else mutation,
            user_agent=request.headers.get("User-Agent", ""),
        )

    def _valid_username(name: str) -> bool:
        """Charset-validate a username (defaults to allowing all if no fn)."""
        return validate_username_fn(name) if validate_username_fn else True

    def _valid_claim(name: str) -> bool:
        """Charset-validate a claim name (defaults to allowing all if no fn)."""
        return validate_claim_fn(name) if validate_claim_fn else True

    def _password_error(pw: str) -> str | None:
        """Return a password-policy error, or None. Falls back to length >= 8."""
        if password_policy_fn:
            return password_policy_fn(pw)
        return None if len(pw) >= 8 else "Password must be at least 8 characters."

    def _load_claims_registry() -> list[str]:
        """Load the claims registry from claims.json (or derive from users)."""
        claims_file = users_path.parent / "claims.json" if users_path else None
        if claims_file and claims_file.is_file():
            return json.loads(claims_file.read_text())
        # Fallback: derive from all users' claims
        return sorted({c for u in users.values() for c in u.get("claims", [])})

    def _save_claims_registry(claims: list[str]) -> None:
        """Save the claims registry to claims.json."""
        claims_file = users_path.parent / "claims.json" if users_path else None
        if claims_file:
            claims_file.write_text(json.dumps(sorted(set(claims)), indent=2) + "\n")

    # --- Recovery tokens ---
    RECOVERY_TOKEN_EXPIRY = 24 * 3600  # 24 hours

    def _recovery_tokens_path() -> Path | None:
        return users_path.parent / "recovery_tokens.json" if users_path else None

    def _load_recovery_tokens() -> dict[str, dict]:
        path = _recovery_tokens_path()
        if path and path.is_file():
            return json.loads(path.read_text())
        return {}

    def _save_recovery_tokens(tokens: dict[str, dict]) -> None:
        path = _recovery_tokens_path()
        if path:
            path.write_text(json.dumps(tokens, indent=2) + "\n")

    def _generate_recovery_token(username: str) -> str:
        """Generate a secure recovery token for a user. Returns the token string."""
        token = secrets.token_urlsafe(48)  # 64 chars, 384 bits of entropy
        tokens = _load_recovery_tokens()
        # Prune expired tokens
        now = time.time()
        tokens = {k: v for k, v in tokens.items() if v.get("expires", 0) > now}
        # Store new token
        tokens[token] = {
            "username": username,
            "created": now,
            "expires": now + RECOVERY_TOKEN_EXPIRY,
        }
        _save_recovery_tokens(tokens)
        return token

    def _validate_recovery_token(token: str) -> str | None:
        """Validate and consume a recovery token. Returns username or None."""
        tokens = _load_recovery_tokens()
        entry = tokens.get(token)
        if not entry:
            return None
        if time.time() > entry.get("expires", 0):
            # Expired — clean up
            del tokens[token]
            _save_recovery_tokens(tokens)
            return None
        return entry.get("username")

    def _consume_recovery_token(token: str) -> None:
        """Delete a recovery token after use."""
        tokens = _load_recovery_tokens()
        tokens.pop(token, None)
        _save_recovery_tokens(tokens)

    def _load_services_yaml() -> dict[str, dict[str, str]]:
        """Load services.yaml and return as {protocol: {path: url}}."""
        if not services_path or not services_path.is_file():
            return {}
        import yaml
        try:
            data = yaml.safe_load(services_path.read_text()) or {}
        except yaml.YAMLError as e:
            logger.warning("Failed to parse services.yaml: %s", e)
            return {}
        return data

    def _save_services_yaml(data: dict[str, dict[str, str]]) -> None:
        """Save services data to services.yaml and restart the server to register new routes."""
        if not services_path:  # pragma: no cover - only callable after a load that requires services_path
            return
        import yaml
        services_path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
        if reload_services_fn:
            reload_services_fn()
        # Restart gunicorn to register new/removed routes
        import os
        import signal
        os.kill(os.getppid(), signal.SIGHUP)
        logger.info("Sent SIGHUP to gunicorn master (pid=%d) to reload routes", os.getppid())

    def _render_panel(auth_token: str, message: str = "", error: str = ""):
        token = _csrf_token()
        users_list = list(users.values())
        all_claims = _load_claims_registry()
        services_data = _load_services_yaml()
        # Flatten to a list of {protocol, path, url, token_duration}
        sp_list = []
        for protocol, paths in services_data.items():
            if isinstance(paths, dict):
                for path, val in paths.items():
                    if isinstance(val, dict):
                        url = val.get("url", "")
                        if protocol == "oauth":
                            duration = val.get("token_expiry_minutes", 60)
                        else:
                            duration = val.get("session_duration_hours", 1) * 60
                    else:
                        url = val
                        duration = 60
                    sp_list.append({"protocol": protocol, "path": path, "url": url, "token_duration": duration})
        backup_failing = False
        _bdir = data_dir if data_dir is not None else (users_path.parent if users_path else None)
        if _bdir is not None:
            backup_failing = bk.load_status(_bdir).is_failing
        resp = app.make_response(render_template_string(
            ADMIN_PANEL,
            users_list=users_list,
            all_claims=all_claims,
            sp_list=sp_list,
            backup_failing=backup_failing,
            csrf_token=token,
            auth_token=auth_token,
            message=message,
            error=error,
            csp_nonce=getattr(g, "csp_nonce", ""),
        ))
        resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return resp

    @app.get("/admin")
    def admin_get():
        # Check session cookie — skip login if user has idpadmin claim
        if verify_session_cookie_fn:
            session_user = verify_session_cookie_fn(request.cookies.get("idp_session", ""))
            if session_user and _has_claim(session_user, "idpadmin"):
                if audit_logger:
                    audit_logger.log(
                        username=session_user,
                        ip=request.remote_addr or "unknown",
                        service="admin",
                        protocol="admin",
                        result="session_reuse",
                        user_agent=request.headers.get("User-Agent", ""),
                    )
                auth_token = _issue_token(session_user)
                return _render_panel(auth_token)

        token = _csrf_token()
        question, ch_hash = make_challenge_fn()
        resp = app.make_response(render_template_string(
            ADMIN_LOGIN, error=None, csrf_token=token,
            challenge_question=question, challenge_hash=ch_hash,
            passkey_available=_admin_passkey_enabled(),
        ))
        resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return resp

    def _admin_passkey_enabled() -> bool:
        """True if admin passkey login is wired up and enabled."""
        return bool(
            webauthn_rp is not None
            and passkey_challenges is not None
            and passkey_available_fn is not None
            and passkey_available_fn()
        )

    def _admin_passkey_csrf_ok(payload: dict) -> bool:
        """Validate the CSRF double-submit token on a JSON passkey request."""
        form_token = payload.get("csrf_token", "")
        cookie_token = request.cookies.get("csrf_token", "")
        return bool(form_token) and hmac.compare_digest(str(form_token), cookie_token)

    @app.post("/admin/passkey/begin")
    def admin_passkey_begin():
        """Begin a username-first admin passkey authentication.

        Only accounts that hold the ``idpadmin`` claim and are otherwise usable
        may start the ceremony; ineligible or unknown users get the same generic
        error so admin membership isn't leaked.
        """
        if not _admin_passkey_enabled():
            return jsonify({"error": "Passkeys are not enabled."}), 404
        payload = request.get_json(silent=True) or {}
        if not _admin_passkey_csrf_ok(payload):
            return jsonify({"error": "Invalid request (CSRF)."}), 403
        username = payload.get("username", "")
        # Throttle per IP and per account, mirroring the password login path.
        if _rl_limited() or (username and _rl_limited(username)):
            return jsonify({"error": "Too many attempts. Try again later."}), 429
        user = users.get(username)
        eligible = bool(
            user
            and user.get("enabled") is not False
            and not user.get("must_set_password")
            and _has_claim(username, "idpadmin")
        )
        credentials = wf.get_credentials(user) if eligible else []
        if not credentials:
            return jsonify({"error": "No admin passkey for this account."}), 400
        options_json, challenge = wf.begin_authentication(webauthn_rp, credentials)
        handle = passkey_challenges.put(
            challenge=challenge, username=username, purpose="admin",
        )
        return jsonify({"handle": handle, "options": json.loads(options_json)})

    @app.post("/admin/passkey/finish")
    def admin_passkey_finish():
        """Verify an admin passkey assertion and establish the admin session."""
        if not _admin_passkey_enabled():
            return jsonify({"error": "Passkeys are not enabled."}), 404
        payload = request.get_json(silent=True) or {}
        if not _admin_passkey_csrf_ok(payload):
            return jsonify({"error": "Invalid request (CSRF)."}), 403
        # Per-IP throttle: the username is only known after the challenge is
        # consumed, so failures below also record the IP bucket.
        if _rl_limited():
            return jsonify({"error": "Too many attempts. Try again later."}), 429
        entry = passkey_challenges.consume(payload.get("handle", ""), purpose="admin")
        if entry is None:
            _rl_record()
            return jsonify({"error": "Authentication session expired."}), 400
        username = entry["username"]
        user = users.get(username)
        # Re-check idpadmin at finish (begin/finish are separate requests).
        if not user or not _has_claim(username, "idpadmin"):
            _rl_record()
            _rl_record(username)
            return jsonify({"error": "Unknown passkey."}), 400
        credential_json = json.dumps(payload.get("credential", {}))
        cred_id = wf.credential_id_from_response(credential_json)
        stored = wf.find_credential(user, cred_id) if cred_id else None
        if stored is None:
            _rl_record()
            _rl_record(username)
            return jsonify({"error": "Unknown passkey."}), 400
        try:
            new_sign_count = wf.finish_authentication(
                webauthn_rp, credential_json, entry["challenge"], stored,
            )
            wf.update_credential_usage(
                stored, new_sign_count=new_sign_count, now_iso=_now_iso(),
            )
        except wf.WebAuthnError:
            _rl_record()
            _rl_record(username)
            if audit_logger:
                audit_logger.log(
                    username=username, ip=request.remote_addr or "unknown",
                    service="admin", protocol="webauthn", result="failure",
                    reason="invalid_passkey",
                    user_agent=request.headers.get("User-Agent", ""),
                )
            return jsonify({"error": "Passkey authentication failed."}), 401
        if users_path:
            save_users_fn(users_path, users)
        if audit_logger:
            audit_logger.log(
                username=username, ip=request.remote_addr or "unknown",
                service="admin", protocol="webauthn", result="success",
                reason="passkey",
                user_agent=request.headers.get("User-Agent", ""),
            )
        resp = jsonify({"redirect": "/admin"})
        if set_session_cookie_fn:
            set_session_cookie_fn(resp, username)
        return resp

    @app.post("/admin")
    def admin_post():
        form_token = request.form.get("csrf_token", "")
        cookie_token = request.cookies.get("csrf_token", "")
        if not form_token or not hmac.compare_digest(form_token, cookie_token):
            token = _csrf_token()
            question, ch_hash = make_challenge_fn()
            resp = app.make_response(render_template_string(
                ADMIN_LOGIN, error="Invalid request (CSRF)", csrf_token=token,
                challenge_question=question, challenge_hash=ch_hash,
            ))
            resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
            return resp, 403

        action = request.form.get("action", "login")

        if action == "login":
            login_username = request.form.get("username", "")
            # Throttle admin credential guessing (per IP and per account).
            if _rl_limited() or (login_username and _rl_limited(login_username)):
                if audit_logger:
                    audit_logger.log(
                        username=login_username,
                        ip=request.remote_addr or "unknown",
                        service="admin",
                        protocol="admin",
                        result="failure",
                        reason="rate_limited",
                        user_agent=request.headers.get("User-Agent", ""),
                    )
                token = _csrf_token()
                question, ch_hash = make_challenge_fn()
                resp = app.make_response(render_template_string(
                    ADMIN_LOGIN, error="Too many attempts. Try again later.",
                    csrf_token=token,
                    challenge_question=question, challenge_hash=ch_hash,
                ))
                resp.set_cookie(
                    "csrf_token", token, httponly=True, samesite="Strict"
                )
                return resp, 429

            # Verify challenge
            challenge_answer = request.form.get("challenge_answer", "")
            challenge_hash_val = request.form.get("challenge_hash", "")
            if not verify_challenge_fn(challenge_answer, challenge_hash_val):
                _rl_record(login_username)
                if audit_logger:
                    audit_logger.log(
                        username=request.form.get("username", ""),
                        ip=request.remote_addr or "unknown",
                        service="admin",
                        protocol="admin",
                        result="failure",
                        reason="failed_captcha",
                        user_agent=request.headers.get("User-Agent", ""),
                    )
                token = _csrf_token()
                question, ch_hash = make_challenge_fn()
                resp = app.make_response(render_template_string(
                    ADMIN_LOGIN, error="Incorrect answer — please try again.",
                    csrf_token=token,
                    challenge_question=question, challenge_hash=ch_hash,
                ))
                resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                return resp, 401

            username = request.form.get("username", "")
            password = request.form.get("password", "")
            totp_code = request.form.get("totp_code", "")
            user = users.get(username)

            account_usable = bool(
                user
                and not user.get("must_set_password")
                and user.get("enabled") is not False
                and user.get("password")
            )
            if not account_usable or not check_password_fn(user["password"], password):
                _rl_record(username)
                if audit_logger:
                    audit_logger.log(
                        username=username,
                        ip=request.remote_addr or "unknown",
                        service="admin",
                        protocol="admin",
                        result="failure",
                        reason="invalid_credentials",
                        user_agent=request.headers.get("User-Agent", ""),
                    )
                token = _csrf_token()
                question, ch_hash = make_challenge_fn()
                resp = app.make_response(render_template_string(
                    ADMIN_LOGIN, error="Invalid credentials", csrf_token=token,
                    challenge_question=question, challenge_hash=ch_hash,
                ))
                resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                return resp, 401

            # Check MFA
            if user.get("totp_secret"):  # noqa: SIM102 - kept nested for auth-flow clarity
                if not totp_code or not verify_code(user["totp_secret"], totp_code):
                    _rl_record(username)
                    if audit_logger:
                        audit_logger.log(
                            username=username,
                            ip=request.remote_addr or "unknown",
                            service="admin",
                            protocol="admin",
                            result="failure",
                            reason="invalid_mfa",
                            user_agent=request.headers.get("User-Agent", ""),
                        )
                    token = _csrf_token()
                    question, ch_hash = make_challenge_fn()
                    resp = app.make_response(render_template_string(
                        ADMIN_LOGIN, error="Invalid MFA code", csrf_token=token,
                        challenge_question=question, challenge_hash=ch_hash,
                    ))
                    resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                    return resp, 401

            # Check idpadmin claim
            if not _has_claim(username, "idpadmin"):
                if audit_logger:
                    audit_logger.log(
                        username=username,
                        ip=request.remote_addr or "unknown",
                        service="admin",
                        protocol="admin",
                        result="failure",
                        reason="access_denied",
                        user_agent=request.headers.get("User-Agent", ""),
                    )
                token = _csrf_token()
                question, ch_hash = make_challenge_fn()
                resp = app.make_response(render_template_string(
                    ADMIN_LOGIN, error="Access denied. You need the 'idpadmin' claim.",
                    csrf_token=token,
                    challenge_question=question, challenge_hash=ch_hash,
                ))
                resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                return resp, 403

            auth_token = _issue_token(username)
            if audit_logger:
                audit_logger.log(
                    username=username,
                    ip=request.remote_addr or "unknown",
                    service="admin",
                    protocol="admin",
                    result="success",
                    user_agent=request.headers.get("User-Agent", ""),
                )
            resp = _render_panel(auth_token)
            if set_session_cookie_fn:
                set_session_cookie_fn(resp, username)
            return resp

        # All other actions require a valid auth token with idpadmin
        auth_token = request.form.get("auth_token", "")
        admin_user = _require_admin(auth_token)
        if not admin_user:
            token = _csrf_token()
            resp = app.make_response(render_template_string(
                ADMIN_LOGIN, error="Session expired. Please sign in again.",
                csrf_token=token,
            ))
            resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
            return resp, 401

        # Refresh token for continued use
        auth_token = _issue_token(admin_user)

        if action == "add_user":
            new_username = request.form.get("new_username", "").strip()
            new_password = request.form.get("new_user_password", "")
            new_email = request.form.get("new_user_email", "").strip()
            new_claims_str = request.form.get("new_user_claims", "").strip()

            if not new_username:
                return _render_panel(auth_token, error="Username is required.")
            if not _valid_username(new_username):
                return _render_panel(
                    auth_token,
                    error="Username may only contain letters, digits, . _ @ - characters.",
                )
            if new_username in users:
                return _render_panel(auth_token, error=f"User '{new_username}' already exists.")
            pw_err = _password_error(new_password)
            if pw_err:
                return _render_panel(auth_token, error=pw_err)

            claims = [c.strip() for c in new_claims_str.split(",") if c.strip()]
            bad_claim = next((c for c in claims if not _valid_claim(c)), None)
            if bad_claim is not None:
                return _render_panel(
                    auth_token, error=f"Invalid claim name: '{bad_claim}'."
                )

            import bcrypt
            hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

            new_user: dict = {
                "username": new_username,
                "password": hashed,
                "roles": [],
                "claims": claims,
                "created_at": _now_iso(),
                "enabled": True,
            }
            if new_email:
                new_user["email"] = new_email

            users[new_username] = new_user
            if users_path:
                save_users_fn(users_path, users)
            logger.info("Admin %s added user %s", admin_user, new_username)
            _audit_admin(admin_user, "add_user", new_username)
            if "idpadmin" in claims:
                _audit_admin(admin_user, "grant_idpadmin", new_username)
            return _render_panel(auth_token, message=f"User '{new_username}' created.")

        elif action == "delete_user":
            target = request.form.get("target_user", "")
            if target == admin_user:
                return _render_panel(auth_token, error="Cannot delete yourself.")
            if target in users:
                del users[target]
                if users_path:
                    save_users_fn(users_path, users)
                logger.info("Admin %s deleted user %s", admin_user, target)
                _audit_admin(admin_user, "delete_user", target)
                return _render_panel(auth_token, message=f"User '{target}' deleted.")
            return _render_panel(auth_token, error=f"User '{target}' not found.")

        elif action == "reset_password":
            target = request.form.get("target_user", "")
            new_pw = request.form.get("new_pw", "")
            pw_err = _password_error(new_pw)
            if pw_err:
                return _render_panel(auth_token, error=pw_err)
            user = users.get(target)
            if not user:
                return _render_panel(auth_token, error=f"User '{target}' not found.")
            import bcrypt
            user["password"] = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
            if users_path:
                save_users_fn(users_path, users)
            logger.info("Admin %s reset password for %s", admin_user, target)
            _audit_admin(admin_user, "reset_password", target)
            return _render_panel(auth_token, message=f"Password reset for '{target}'.")

        elif action == "remove_mfa":
            target = request.form.get("target_user", "")
            user = users.get(target)
            if not user:
                return _render_panel(auth_token, error=f"User '{target}' not found.")
            user.pop("totp_secret", None)
            if users_path:
                save_users_fn(users_path, users)
            logger.info("Admin %s removed MFA for %s", admin_user, target)
            _audit_admin(admin_user, "remove_mfa", target)
            return _render_panel(auth_token, message=f"MFA removed for '{target}'.")

        elif action == "set_claims":
            target = request.form.get("claims_user", "")
            claims_str = request.form.get("user_claims", "").strip()
            user = users.get(target)
            if not user:
                return _render_panel(auth_token, error=f"User '{target}' not found.")
            claims = [c.strip() for c in claims_str.split(",") if c.strip()]
            bad_claim = next((c for c in claims if not _valid_claim(c)), None)
            if bad_claim is not None:
                return _render_panel(
                    auth_token, error=f"Invalid claim name: '{bad_claim}'."
                )
            had_admin = "idpadmin" in user.get("claims", [])
            user["claims"] = claims
            if users_path:
                save_users_fn(users_path, users)
            logger.info("Admin %s set claims for %s: %s", admin_user, target, claims)
            _audit_admin(admin_user, "set_claims", target)
            if "idpadmin" in claims and not had_admin:
                _audit_admin(admin_user, "grant_idpadmin", target)
            return _render_panel(auth_token, message=f"Claims updated for '{target}'.")

        elif action == "add_claim":
            claim_name = request.form.get("claim_name", "").strip().lower()
            if not _valid_claim(claim_name):
                return _render_panel(auth_token, error="Claim name must be URL-safe (letters, numbers, hyphens, underscores).")
            registry = _load_claims_registry()
            if claim_name in registry:
                return _render_panel(auth_token, error=f"Claim '{claim_name}' already exists.")
            registry.append(claim_name)
            _save_claims_registry(registry)
            logger.info("Admin %s added claim: %s", admin_user, claim_name)
            _audit_admin(admin_user, "add_claim", claim_name)
            return _render_panel(auth_token, message=f"Claim '{claim_name}' added.")

        elif action == "delete_claim":
            claim_name = request.form.get("claim_name", "").strip()
            registry = _load_claims_registry()
            if claim_name not in registry:
                return _render_panel(auth_token, error=f"Claim '{claim_name}' not found.")
            registry.remove(claim_name)
            _save_claims_registry(registry)
            # Also remove from all users
            for u in users.values():
                if claim_name in u.get("claims", []):
                    u["claims"].remove(claim_name)
            if users_path:
                save_users_fn(users_path, users)
            logger.info("Admin %s deleted claim: %s (removed from all users)", admin_user, claim_name)
            _audit_admin(admin_user, "delete_claim", claim_name)
            return _render_panel(auth_token, message=f"Claim '{claim_name}' deleted and removed from all users.")

        elif action == "upsert_sp":
            sp_protocol = request.form.get("sp_protocol", "").strip().lower()
            sp_path = request.form.get("sp_path", "").strip().lower()
            sp_url = request.form.get("sp_url", "").strip()
            sp_duration_str = request.form.get("sp_token_duration", "60").strip()

            if sp_protocol not in ("saml", "oauth"):
                return _render_panel(auth_token, error="Protocol must be 'saml' or 'oauth'.")
            if not sp_path or not sp_path.replace("-", "").replace("_", "").isalnum():
                return _render_panel(auth_token, error="Path must be URL-safe (letters, numbers, hyphens, underscores).")
            if not sp_url or not sp_url.startswith("https://"):
                return _render_panel(auth_token, error="URL must start with https://.")

            try:
                sp_duration = int(sp_duration_str)
                if sp_duration < 1 or sp_duration > 720:
                    raise ValueError
            except ValueError:
                return _render_panel(auth_token, error="Token duration must be between 1 and 720 minutes.")

            data = _load_services_yaml()
            if sp_protocol not in data:
                data[sp_protocol] = {}
            is_update = sp_path in data.get(sp_protocol, {})

            # Use extended format to store duration
            if sp_protocol == "oauth":
                data[sp_protocol][sp_path] = {
                    "url": sp_url,
                    "token_expiry_minutes": sp_duration,
                }
            else:
                # SAML: store as hours (rounded up) for session_duration_hours
                duration_hours = max(1, (sp_duration + 59) // 60)
                if sp_duration == 60 and duration_hours == 1:
                    # Default — use short form
                    data[sp_protocol][sp_path] = sp_url
                else:
                    data[sp_protocol][sp_path] = {
                        "url": sp_url,
                        "session_duration_hours": duration_hours,
                    }

            _save_services_yaml(data)
            verb = "updated" if is_update else "added"
            logger.info(
                "Admin %s %s SP: %s/%s -> %s (%d min)",
                admin_user, verb, sp_protocol, sp_path, sp_url, sp_duration,
            )
            return _render_panel(
                auth_token,
                message=(
                    f"Service provider '/{sp_path}' ({sp_protocol}) {verb}."
                    f" Token duration: {sp_duration} min."
                ),
            )

        elif action == "update_sp_duration":
            sp_protocol = request.form.get("sp_protocol", "").strip().lower()
            sp_path = request.form.get("sp_path", "").strip()
            sp_duration_str = request.form.get("sp_token_duration", "60").strip()

            try:
                sp_duration = int(sp_duration_str)
                if sp_duration < 1 or sp_duration > 720:
                    raise ValueError
            except ValueError:
                return _render_panel(
                    auth_token,
                    error="Token duration must be between 1 and 720 minutes.",
                )

            data = _load_services_yaml()
            if sp_protocol not in data or sp_path not in data.get(sp_protocol, {}):
                return _render_panel(
                    auth_token,
                    error=f"Service provider '/{sp_path}' not found.",
                )

            current = data[sp_protocol][sp_path]
            sp_url = current if isinstance(current, str) else current.get("url", "")

            # Store in extended format with updated duration
            if sp_protocol == "oauth":
                entry: dict[str, Any] = {"url": sp_url, "token_expiry_minutes": sp_duration}
                # Preserve other fields
                if isinstance(current, dict):
                    for k, v in current.items():
                        if k not in ("url", "token_expiry_minutes"):
                            entry[k] = v
                data[sp_protocol][sp_path] = entry
            else:
                duration_hours = max(1, (sp_duration + 59) // 60)
                if sp_duration == 60 and duration_hours == 1:
                    # Default — use short form
                    data[sp_protocol][sp_path] = sp_url
                else:
                    entry = {"url": sp_url, "session_duration_hours": duration_hours}
                    # Preserve other fields
                    if isinstance(current, dict):
                        for k, v in current.items():
                            if k not in ("url", "session_duration_hours"):
                                entry[k] = v
                    data[sp_protocol][sp_path] = entry

            _save_services_yaml(data)
            logger.info(
                "Admin %s updated duration for %s/%s to %d min",
                admin_user, sp_protocol, sp_path, sp_duration,
            )
            return _render_panel(
                auth_token,
                message=f"Token duration for '/{sp_path}' updated to {sp_duration} minutes.",
            )

        elif action == "delete_sp":
            sp_protocol = request.form.get("sp_protocol", "").strip().lower()
            sp_path = request.form.get("sp_path", "").strip()

            data = _load_services_yaml()
            if sp_protocol in data and sp_path in data[sp_protocol]:
                del data[sp_protocol][sp_path]
                # Remove empty protocol sections
                if not data[sp_protocol]:
                    del data[sp_protocol]
                _save_services_yaml(data)
                logger.info("Admin %s deleted SP: %s/%s", admin_user, sp_protocol, sp_path)
                return _render_panel(auth_token, message=f"Service provider '/{sp_path}' deleted.")
            return _render_panel(auth_token, error=f"Service provider '/{sp_path}' not found.")

        return _render_panel(auth_token, error="Unknown action.")

    # --- User detail page ---
    def _render_user_detail(username: str, auth_token: str, message: str = "", error: str = "", recovery_url: str = ""):
        user = users.get(username)
        if not user:
            return _render_panel(auth_token, error=f"User '{username}' not found.")
        token = _csrf_token()
        registry = _load_claims_registry()
        user_claims = set(user.get("claims", []))
        available = [c for c in registry if c not in user_claims]
        resp = app.make_response(render_template_string(
            ADMIN_USER_DETAIL,
            user=user,
            available_claims=available,
            csrf_token=token,
            auth_token=auth_token,
            message=message,
            error=error,
            recovery_url=recovery_url,
        ))
        resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return resp

    # --- Audit log page ---
    ADMIN_AUDIT_LOG = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Access Audit Log</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
      Roboto, sans-serif; background: #f4f6f9; padding: 2rem; }
    .container { max-width: 1100px; margin: 0 auto; }
    h1 { font-size: 1.6rem; color: #232f3e; margin-bottom: 1.5rem; }
    .back-link { display: inline-block; margin-bottom: 1rem;
      color: #0073bb; text-decoration: none; font-size: 0.9rem; }
    .back-link:hover { text-decoration: underline; }
    .card { background: #fff; border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.06);
      padding: 1.5rem; margin-bottom: 1.5rem; overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
    th, td { text-align: left; padding: 0.4rem 0.6rem;
      border-bottom: 1px solid #eee; white-space: nowrap; }
    th { background: #f8f9fa; font-weight: 600; color: #555;
      position: sticky; top: 0; }
    .result-success { color: #1d8102; font-weight: 600; }
    .result-failure { color: #d13212; font-weight: 600; }
    .result-session { color: #0073bb; font-weight: 600; }
    .filter-bar { margin-bottom: 1rem; display: flex; gap: 0.5rem;
      flex-wrap: wrap; align-items: center; }
    .filter-bar input, .filter-bar select { padding: 0.4rem 0.6rem;
      border: 1px solid #ccc; border-radius: 4px; font-size: 0.85rem; }
    .filter-bar button { padding: 0.4rem 0.8rem; background: #0073bb;
      color: #fff; border: none; border-radius: 4px;
      font-size: 0.85rem; cursor: pointer; }
    .count { font-size: 0.85rem; color: #555; margin-bottom: 0.5rem; }
  </style>
</head>
<body>
<div class="container">
  <a href="/admin" class="back-link">&larr; Back to Admin Panel</a>
  <h1>Access Audit Log</h1>
  <p class="count">Showing {{ entries|length }} most recent entries</p>
  <div class="card">
    <table>
      <tr>
        <th>Timestamp (UTC)</th>
        <th>Username</th>
        <th>IP</th>
        <th>Service</th>
        <th>Protocol</th>
        <th>Result</th>
        <th>Reason</th>
      </tr>
      {% for e in entries %}
      <tr>
        <td>{{ e.timestamp[:19] }}</td>
        <td>{{ e.username or '—' }}</td>
        <td>{{ e.ip }}</td>
        <td>{{ e.service }}</td>
        <td>{{ e.protocol }}</td>
        <td class="{% if e.result == 'success' %}result-success{% elif e.result == 'failure' %}result-failure{% else %}result-session{% endif %}">{{ e.result }}</td>
        <td>{{ e.reason or '—' }}</td>
      </tr>
      {% endfor %}
      {% if not entries %}
      <tr><td colspan="7" style="text-align:center;color:#888;">
        No audit entries yet.</td></tr>
      {% endif %}
    </table>
  </div>
</div>
</body>
</html>
"""

    @app.get("/admin/audit-log")
    def admin_audit_log_get():
        # Check session cookie
        if verify_session_cookie_fn:
            session_user = verify_session_cookie_fn(
                request.cookies.get("idp_session", ""),
            )
            if session_user and _has_claim(session_user, "idpadmin"):
                entries = []
                if audit_logger:
                    entries = audit_logger.read_recent(500)
                return render_template_string(
                    ADMIN_AUDIT_LOG, entries=entries,
                )
        # No session — redirect to admin login
        return app.redirect("/admin")

    # --- Backups page ---
    ADMIN_BACKUPS = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Backups</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
      Roboto, sans-serif; background: #f4f6f9; padding: 2rem; }
    .container { max-width: 800px; margin: 0 auto; }
    h1 { font-size: 1.6rem; color: #232f3e; margin-bottom: 1rem; }
    h2 { font-size: 1.2rem; color: #232f3e; margin: 2rem 0 1rem;
      border-bottom: 2px solid #0073bb; padding-bottom: 0.5rem; }
    .back-link { display: inline-block; margin-bottom: 1rem;
      color: #0073bb; text-decoration: none; font-size: 0.9rem; }
    .back-link:hover { text-decoration: underline; }
    .card { background: #fff; border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.06); padding: 1.5rem; margin-bottom: 1.5rem; }
    label { display: block; font-size: 0.85rem; color: #555; margin-bottom: 0.3rem; }
    input[type="text"], input[type="password"], input[type="number"] {
      width: 100%; padding: 0.5rem 0.6rem; border: 1px solid #ccc;
      border-radius: 4px; font-size: 0.9rem; margin-bottom: 0.75rem; }
    .form-row { display: flex; gap: 0.75rem; }
    .form-row > div { flex: 1; }
    button, .btn { padding: 0.5rem 1rem; background: #0073bb; color: #fff;
      border: none; border-radius: 4px; font-size: 0.85rem; cursor: pointer;
      text-decoration: none; display: inline-block; }
    button:hover { background: #005a94; }
    .btn-warning { background: #ff9900; }
    .btn-danger { background: #d13212; }
    .success { color: #1d8102; font-size: 0.9rem; margin-bottom: 1rem;
      padding: 0.5rem; background: #e8f5e9; border-radius: 4px; }
    .error { color: #d13212; font-size: 0.9rem; margin-bottom: 1rem;
      padding: 0.5rem; background: #fde8e8; border-radius: 4px; }
    .banner { background: #fde8e8; border: 1px solid #f5b5b5; color: #d13212;
      padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1.5rem;
      font-size: 0.9rem; font-weight: 600; }
    .status-row { display: flex; gap: 1rem; font-size: 0.9rem;
      margin-bottom: 0.4rem; }
    .status-row .label { color: #555; min-width: 160px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #eee; }
    th { background: #f8f9fa; color: #555; }
    .muted { color: #888; font-size: 0.85rem; }
  </style>
</head>
<body>
<div class="container">
  <a href="/admin" class="back-link">&larr; Back to Admin Panel</a>
  <h1>Backups</h1>

  {% if status.is_failing %}
  <div class="banner">⚠ Last backup FAILED ({{ status.last_attempt[:19] }} UTC):
    {{ status.message }}{% if status.consecutive_failures > 1 %}
    — {{ status.consecutive_failures }} consecutive failures.{% endif %}</div>
  {% endif %}

  {% if message %}<p class="success">{{ message }}</p>{% endif %}
  {% if error %}<p class="error">{{ error }}</p>{% endif %}

  <h2>Status</h2>
  <div class="card">
    <div class="status-row"><span class="label">Last attempt:</span>
      {{ status.last_attempt[:19] or '—' }}{% if status.last_attempt %} UTC{% endif %}</div>
    <div class="status-row"><span class="label">Last success:</span>
      {{ status.last_success[:19] or '—' }}{% if status.last_success %} UTC{% endif %}</div>
    <div class="status-row"><span class="label">Result:</span> {{ status.result or '—' }}</div>
    <div class="status-row"><span class="label">Detail:</span> {{ status.message or '—' }}</div>
    <div class="status-row"><span class="label">Schedule:</span> Nightly at 02:30 (server time)</div>
    <form method="post" style="margin-top:1rem;">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="hidden" name="auth_token" value="{{ auth_token }}">
      <input type="hidden" name="action" value="run_backup_now">
      <button type="submit">Run backup now</button>
    </form>
  </div>

  <h2>SMB Destination</h2>
  <div class="card">
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="hidden" name="auth_token" value="{{ auth_token }}">
      <input type="hidden" name="action" value="save_backup_config">
      <div class="form-row">
        <div><label>SMB server</label>
          <input type="text" name="server" value="{{ config.server }}"
            placeholder="192.168.101.20"></div>
        <div><label>Share</label>
          <input type="text" name="share" value="{{ config.share }}"
            placeholder="idp-backups"></div>
      </div>
      <div class="form-row">
        <div><label>Username</label>
          <input type="text" name="username" value="{{ config.username }}"></div>
        <div><label>Password</label>
          <input type="password" name="password"
            placeholder="{% if config.password %}(unchanged){% else %}password{% endif %}"></div>
      </div>
      <label>Subpath within share</label>
      <input type="text" name="subpath" value="{{ config.subpath }}" placeholder="idp-backup">
      <div class="form-row">
        <div><label>Daily retention</label>
          <input type="number" name="daily_retention" min="1" max="365"
            value="{{ config.daily_retention }}"></div>
        <div><label>Weekly retention</label>
          <input type="number" name="weekly_retention" min="1" max="520"
            value="{{ config.weekly_retention }}"></div>
      </div>
      <label style="display:inline-flex;align-items:center;gap:0.4rem;margin-bottom:0.75rem;">
        <input type="checkbox" name="enabled" value="1" style="width:auto;"
          {% if config.enabled %}checked{% endif %}> Enabled
      </label>
      <div>
        <button type="submit">Save settings</button>
      </div>
    </form>
    <form method="post" style="margin-top:0.75rem;">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="hidden" name="auth_token" value="{{ auth_token }}">
      <input type="hidden" name="action" value="test_backup_connection">
      <button type="submit" class="btn-warning">Test connection</button>
    </form>
    <p class="muted" style="margin-top:0.75rem;">The password is stored on the
      server (file mode 600) and used only by the root backup job to mount the
      share. Leave the password blank to keep the existing one.</p>
  </div>

  <h2>Restore</h2>
  <div class="card">
    <p class="muted" style="margin-bottom:0.75rem;">Restoring overwrites all
      current IdP data with the selected archive, then restarts the service. A
      snapshot of the current data is taken first. This cannot be undone easily
      — you must re-enter your MFA/captcha to confirm.</p>
    {% if archives %}
    <form method="post" onsubmit="return confirm('Restore will OVERWRITE all current data and restart the IdP. Continue?');">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="hidden" name="auth_token" value="{{ auth_token }}">
      <input type="hidden" name="action" value="restore_backup">
      <label>Archive to restore</label>
      <select name="archive" style="width:100%;padding:0.5rem;border:1px solid #ccc;
        border-radius:4px;margin-bottom:0.75rem;">
        {% for a in archives %}<option value="{{ a }}">{{ a }}</option>{% endfor %}
      </select>
      <label>Confirm with your MFA code (or captcha answer): {{ challenge_question }}</label>
      <input type="hidden" name="challenge_hash" value="{{ challenge_hash }}">
      <input type="text" name="confirm_answer" placeholder="MFA code or captcha answer" required>
      <div style="margin-top:0.75rem;">
        <button type="submit" class="btn-danger">Restore selected archive</button>
      </div>
    </form>
    {% else %}
    <p class="muted">No archives available on the share (or the share is not
      reachable). Configure and test the connection above.</p>
    {% endif %}
  </div>
</div>
</body>
</html>
"""

    def _trigger_unit(unit: str) -> tuple[bool, str]:
        """Start a systemd unit via the narrow sudo rule. Returns (ok, detail)."""
        try:
            result = subprocess.run(  # nosec B603
                [_SUDO, "-n", _SYSTEMCTL, "start", unit],
                capture_output=True, text=True, check=False, timeout=120,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return False, str(exc)
        if result.returncode != 0:
            return False, result.stderr.strip() or f"exit {result.returncode}"
        return True, "started"

    def _backup_data_dir() -> Path | None:
        """Resolve the data directory for backup operations."""
        if data_dir is not None:
            return Path(data_dir)
        return users_path.parent if users_path else None

    def _list_share_archives(ddir: Path) -> list[str]:
        """List archives available for restore (from the cached listing).

        The share is only mounted by the root job, so the web app reads the
        listing that the backup job caches locally after each successful run.
        """
        return bk.read_archive_listing(ddir)

    def _render_backups(auth_token: str, message: str = "", error: str = ""):
        token = _csrf_token()
        ddir = _backup_data_dir()
        config = bk.load_config(ddir) if ddir else bk.BackupConfig()
        status = bk.load_status(ddir) if ddir else bk.BackupStatus()
        archives = _list_share_archives(ddir) if ddir else []
        question, ch_hash = make_challenge_fn()
        resp = app.make_response(render_template_string(
            ADMIN_BACKUPS,
            config=config,
            status=status,
            archives=archives,
            challenge_question=question,
            challenge_hash=ch_hash,
            csrf_token=token,
            auth_token=auth_token,
            message=message,
            error=error,
        ))
        resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return resp

    @app.get("/admin/backups")
    def admin_backups_get():
        if verify_session_cookie_fn:
            session_user = verify_session_cookie_fn(request.cookies.get("idp_session", ""))
            if session_user and _has_claim(session_user, "idpadmin"):
                auth_token = _issue_token(session_user)
                return _render_backups(auth_token)
        return app.redirect("/admin")

    @app.post("/admin/backups")
    def admin_backups_post():
        form_token = request.form.get("csrf_token", "")
        cookie_token = request.cookies.get("csrf_token", "")
        if not form_token or not hmac.compare_digest(form_token, cookie_token):
            return app.redirect("/admin")

        auth_token = request.form.get("auth_token", "")
        admin_user = _require_admin(auth_token)
        if not admin_user:
            return app.redirect("/admin")

        auth_token = _issue_token(admin_user)
        action = request.form.get("action", "")
        ddir = _backup_data_dir()
        if ddir is None:
            return _render_backups(auth_token, error="No data directory available.")

        ip = request.remote_addr or "unknown"
        ua = request.headers.get("User-Agent", "")

        if action == "save_backup_config":
            config = bk.load_config(ddir)
            config.server = request.form.get("server", "").strip()
            config.share = request.form.get("share", "").strip()
            config.username = request.form.get("username", "").strip()
            # Blank password means "keep existing".
            new_pw = request.form.get("password", "")
            if new_pw:
                config.password = new_pw
            raw_subpath = request.form.get("subpath", "idp-backup").strip() or "idp-backup"
            try:
                config.subpath = bk.validate_subpath(raw_subpath)
            except bk.InvalidSubpathError:
                return _render_backups(
                    auth_token,
                    error="Invalid backup subpath. Use letters, digits, . _ - and / only "
                          "(no leading / and no '..').",
                )
            config.enabled = request.form.get("enabled") == "1"
            try:
                config.daily_retention = max(1, int(request.form.get("daily_retention", "30")))
                config.weekly_retention = max(1, int(request.form.get("weekly_retention", "52")))
            except ValueError:
                return _render_backups(auth_token, error="Retention values must be numbers.")
            bk.save_config(ddir, config)
            logger.info("Admin %s updated backup config", admin_user)
            return _render_backups(auth_token, message="Backup settings saved.")

        if action == "test_backup_connection":
            ok, detail = _trigger_test(ddir)
            if ok:
                return _render_backups(auth_token, message=f"Connection OK. {detail}")
            return _render_backups(auth_token, error=f"Connection failed: {detail}")

        if action == "run_backup_now":
            ok, detail = _trigger_unit("idp-backup.service")
            if audit_logger:
                audit_logger.log(
                    username=admin_user, ip=ip, service="backup", protocol="admin",
                    result="success" if ok else "failure",
                    reason="" if ok else "trigger_failed", user_agent=ua,
                )
            if ok:
                return _render_backups(
                    auth_token,
                    message="Backup started. Refresh in a moment to see the result.",
                )
            return _render_backups(auth_token, error=f"Could not start backup: {detail}")

        if action == "restore_backup":
            archive = request.form.get("archive", "").strip()
            confirm = request.form.get("confirm_answer", "")
            # Restore overwrites all authentication state as root, so require a
            # FRESH TOTP code from the acting admin. The replayable captcha is no
            # longer accepted as an alternative confirmation for this action.
            user = users.get(admin_user, {})
            if not user.get("totp_secret"):
                if audit_logger:
                    audit_logger.log(
                        username=admin_user, ip=ip, service="restore", protocol="admin",
                        result="failure", reason="mfa_required", user_agent=ua,
                    )
                return _render_backups(
                    auth_token,
                    error="Restore requires MFA. Enrol MFA on your account first.",
                )
            if not verify_code(user["totp_secret"], confirm):
                if audit_logger:
                    audit_logger.log(
                        username=admin_user, ip=ip, service="restore", protocol="admin",
                        result="failure", reason="confirm_failed", user_agent=ua,
                    )
                return _render_backups(auth_token, error="Confirmation failed. Restore aborted.")
            # Guard the archive name before handing it to systemd.
            if "/" in archive or ".." in archive or not archive.endswith(".tar.gz"):
                return _render_backups(auth_token, error="Invalid archive name.")
            unit = f"idp-restore@{archive}.service"
            ok, detail = _trigger_unit(unit)
            if audit_logger:
                audit_logger.log(
                    username=admin_user, ip=ip, service="restore", protocol="admin",
                    result="success" if ok else "failure",
                    reason=archive if ok else f"trigger_failed:{detail}", user_agent=ua,
                )
            logger.warning("Admin %s triggered restore of %s (ok=%s)", admin_user, archive, ok)
            if ok:
                return _render_backups(
                    auth_token,
                    message=f"Restore of '{archive}' started. The service will restart.",
                )
            return _render_backups(auth_token, error=f"Could not start restore: {detail}")

        return _render_backups(auth_token, error="Unknown action.")

    def _trigger_test(ddir: Path) -> tuple[bool, str]:
        """Run the privileged connection test via sudo. Returns (ok, detail)."""
        cmd = [
            _SUDO, "-n",
            f"{Path('/opt/idp/.venv/bin/python')}",
            "-m", "identity_provider_server.backup_cli", "test",
            "--data-dir", str(ddir),
        ]
        try:
            result = subprocess.run(  # nosec B603
                cmd, capture_output=True, text=True, check=False, timeout=60,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return False, str(exc)
        detail = (result.stdout or result.stderr).strip()
        return result.returncode == 0, detail

    @app.get("/admin/user/<target_username>")
    def admin_user_detail_get(target_username: str):
        # Check session cookie
        if verify_session_cookie_fn:
            session_user = verify_session_cookie_fn(request.cookies.get("idp_session", ""))
            if session_user and _has_claim(session_user, "idpadmin"):
                auth_token = _issue_token(session_user)
                return _render_user_detail(target_username, auth_token)
        # No session — redirect to admin login
        return app.redirect("/admin")

    @app.post("/admin/user/<target_username>")
    def admin_user_detail_post(target_username: str):
        form_token = request.form.get("csrf_token", "")
        cookie_token = request.cookies.get("csrf_token", "")
        if not form_token or not hmac.compare_digest(form_token, cookie_token):
            return app.redirect("/admin")

        auth_token = request.form.get("auth_token", "")
        admin_user = _require_admin(auth_token)
        if not admin_user:
            return app.redirect("/admin")

        auth_token = _issue_token(admin_user)
        action = request.form.get("action", "")
        user = users.get(target_username)
        if not user:
            return _render_panel(auth_token, error=f"User '{target_username}' not found.")

        if action == "add_user_claim":
            claim_name = request.form.get("claim_name", "").strip()
            if claim_name and not _valid_claim(claim_name):
                return _render_user_detail(
                    target_username, auth_token, error=f"Invalid claim name: '{claim_name}'."
                )
            if claim_name and claim_name not in user.get("claims", []):
                user.setdefault("claims", []).append(claim_name)
                if users_path:
                    save_users_fn(users_path, users)
                logger.info("Admin %s added claim '%s' to user %s", admin_user, claim_name, target_username)
                _audit_admin(admin_user, "add_user_claim", f"{target_username}:{claim_name}")
                if claim_name == "idpadmin":
                    _audit_admin(admin_user, "grant_idpadmin", target_username)
                return _render_user_detail(target_username, auth_token, message=f"Claim '{claim_name}' added.")
            return _render_user_detail(target_username, auth_token, error="Claim already assigned or invalid.")

        elif action == "remove_user_claim":
            claim_name = request.form.get("claim_name", "").strip()
            if claim_name in user.get("claims", []):
                user["claims"].remove(claim_name)
                if users_path:
                    save_users_fn(users_path, users)
                logger.info("Admin %s removed claim '%s' from user %s", admin_user, claim_name, target_username)
                _audit_admin(admin_user, "remove_user_claim", f"{target_username}:{claim_name}")
                return _render_user_detail(target_username, auth_token, message=f"Claim '{claim_name}' removed.")
            return _render_user_detail(target_username, auth_token, error=f"Claim '{claim_name}' not found on user.")

        elif action == "generate_recovery":
            token = _generate_recovery_token(target_username)
            recovery_url = f"https://idp.botthouse.net/recover/{token}"
            logger.info("Admin %s generated recovery link for %s", admin_user, target_username)
            _audit_admin(admin_user, "generate_recovery", target_username)
            return _render_user_detail(target_username, auth_token, recovery_url=recovery_url)

        return _render_user_detail(target_username, auth_token)

    # Expose recovery token functions at module level for use by app.py
    import identity_provider_server.admin as _admin_module
    _admin_module.validate_recovery_token = _validate_recovery_token
    _admin_module.consume_recovery_token = _consume_recovery_token


# Module-level references set by register_admin_routes for use by recovery routes
validate_recovery_token = None
consume_recovery_token = None
