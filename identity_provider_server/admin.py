"""Admin panel for user and claims management.

Accessible at /admin to users with the 'idpadmin' claim.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
from pathlib import Path
from typing import Any

from flask import Flask, render_template_string, request

from .totp import verify_code

logger = logging.getLogger(__name__)

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
  <h1>Admin Panel</h1>
  {% if message %}<p class="success">{{ message }}</p>{% endif %}
  {% if error %}<p class="error">{{ error }}</p>{% endif %}

  <h2>Users</h2>
  <div class="card">
    <table>
      <tr><th>Username</th><th>Claims</th><th>MFA</th><th>Actions</th></tr>
      {% for u in users_list %}
      <tr>
        <td><strong>{{ u.username }}</strong></td>
        <td>{% for c in u.get('claims', []) %}<span class="badge">{{ c }}</span>{% endfor %}</td>
        <td>{% if u.get('totp_secret') %}<span class="badge badge-mfa">MFA</span>{% else %}—{% endif %}</td>
        <td class="actions">
          <form method="post" style="display:inline">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="hidden" name="auth_token" value="{{ auth_token }}">
            <input type="hidden" name="action" value="reset_password">
            <input type="hidden" name="target_user" value="{{ u.username }}">
            <button class="btn-sm btn-warning" onclick="this.form.elements.new_pw.value=prompt('New password for {{ u.username }}:');return !!this.form.elements.new_pw.value;">Reset PW</button>
            <input type="hidden" name="new_pw" value="">
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
          <form method="post" style="display:inline" onsubmit="return confirm('Delete user {{ u.username }}?')">
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
      <label>Claims (comma-separated)</label>
      <input type="text" name="new_user_claims" placeholder="e.g. idpadmin,developer">
      <button type="submit">Add User</button>
    </form>
  </div>

  <h2>Manage Claims</h2>
  <div class="card">
    <p style="font-size:0.85rem;color:#555;margin-bottom:1rem;">Modify claims for a user. Current claims are pre-filled when you select a user.</p>
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="hidden" name="auth_token" value="{{ auth_token }}">
      <input type="hidden" name="action" value="set_claims">
      <div class="form-row">
        <div>
          <label>User</label>
          <select name="claims_user" id="claims_user_select" onchange="prefillClaims()">
            {% for u in users_list %}<option value="{{ u.username }}" data-claims="{{ u.get('claims', [])|join(',') }}">{{ u.username }}</option>{% endfor %}
          </select>
        </div>
        <div><label>Claims (comma-separated)</label><input type="text" name="user_claims" id="user_claims_input" placeholder="idpadmin,developer"></div>
      </div>
      <button type="submit">Update Claims</button>
    </form>
    <script>
      function prefillClaims() {
        var sel = document.getElementById('claims_user_select');
        var input = document.getElementById('user_claims_input');
        var opt = sel.options[sel.selectedIndex];
        input.value = opt.getAttribute('data-claims') || '';
      }
      prefillClaims();
    </script>
    <p style="font-size:0.8rem;color:#888;margin-top:1rem;">All claims in use: {% for c in all_claims %}<span class="badge">{{ c }}</span> {% endfor %}</p>
  </div>

  <h2>Service Providers</h2>
  <div class="card">
    <table>
      <tr><th>Path</th><th>Protocol</th><th>URL</th><th>Actions</th></tr>
      {% for sp in sp_list %}
      <tr>
        <td><code>/{{ sp.path }}</code></td>
        <td><span class="badge">{{ sp.protocol }}</span></td>
        <td style="font-size:0.8rem;word-break:break-all;">{{ sp.url }}</td>
        <td class="actions">
          <form method="post" style="display:inline" onsubmit="return confirm('Delete service provider /{{ sp.path }}?')">
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
      <tr><td colspan="4" style="text-align:center;color:#888;">No service providers configured.</td></tr>
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
      <button type="submit">Add / Update SP</button>
    </form>
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
) -> None:
    """Register /admin routes on the Flask app."""

    def _csrf_token() -> str:
        return secrets.token_hex(32)

    def _issue_token(username: str) -> str:
        payload = f"{username}:{int(time.time())}"
        sig = hmac.new(app.secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}:{sig}"

    def _verify_token(token: str, max_age: int = 600) -> str | None:
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

    def _has_claim(username: str, claim: str) -> bool:
        user = users.get(username)
        if not user:
            return False
        return claim in user.get("claims", [])

    def _load_services_yaml() -> dict[str, dict[str, str]]:
        """Load services.yaml and return as {protocol: {path: url}}."""
        if not services_path or not services_path.is_file():
            return {}
        import yaml
        data = yaml.safe_load(services_path.read_text()) or {}
        return data

    def _save_services_yaml(data: dict[str, dict[str, str]]) -> None:
        """Save services data to services.yaml."""
        if not services_path:
            return
        import yaml
        services_path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
        if reload_services_fn:
            reload_services_fn()

    def _render_panel(auth_token: str, message: str = "", error: str = ""):
        token = _csrf_token()
        users_list = list(users.values())
        all_claims = sorted({c for u in users.values() for c in u.get("claims", [])})
        services_data = _load_services_yaml()
        # Flatten to a list of {protocol, path, url}
        sp_list = []
        for protocol, paths in services_data.items():
            if isinstance(paths, dict):
                for path, url in paths.items():
                    sp_list.append({"protocol": protocol, "path": path, "url": url})
        resp = app.make_response(render_template_string(
            ADMIN_PANEL,
            users_list=users_list,
            all_claims=all_claims,
            sp_list=sp_list,
            csrf_token=token,
            auth_token=auth_token,
            message=message,
            error=error,
        ))
        resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
        return resp

    @app.get("/admin")
    def admin_get():
        # Check session cookie — skip login if user has idpadmin claim
        if verify_session_cookie_fn:
            session_user = verify_session_cookie_fn(request.cookies.get("idp_session", ""))
            if session_user and _has_claim(session_user, "idpadmin"):
                auth_token = _issue_token(session_user)
                return _render_panel(auth_token)

        token = _csrf_token()
        question, ch_hash = make_challenge_fn()
        resp = app.make_response(render_template_string(
            ADMIN_LOGIN, error=None, csrf_token=token,
            challenge_question=question, challenge_hash=ch_hash,
        ))
        resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
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
            # Verify challenge
            challenge_answer = request.form.get("challenge_answer", "")
            challenge_hash_val = request.form.get("challenge_hash", "")
            if not verify_challenge_fn(challenge_answer, challenge_hash_val):
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

            if not user or not check_password_fn(user["password"], password):
                token = _csrf_token()
                question, ch_hash = make_challenge_fn()
                resp = app.make_response(render_template_string(
                    ADMIN_LOGIN, error="Invalid credentials", csrf_token=token,
                    challenge_question=question, challenge_hash=ch_hash,
                ))
                resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
                return resp, 401

            # Check MFA
            if user.get("totp_secret"):
                if not totp_code or not verify_code(user["totp_secret"], totp_code):
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
            return _render_panel(auth_token)

        # All other actions require a valid auth token with idpadmin
        auth_token = request.form.get("auth_token", "")
        admin_user = _verify_token(auth_token)
        if not admin_user or not _has_claim(admin_user, "idpadmin"):
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
            new_claims_str = request.form.get("new_user_claims", "").strip()

            if not new_username:
                return _render_panel(auth_token, error="Username is required.")
            if new_username in users:
                return _render_panel(auth_token, error=f"User '{new_username}' already exists.")
            if len(new_password) < 8:
                return _render_panel(auth_token, error="Password must be at least 8 characters.")

            import bcrypt
            hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
            claims = [c.strip() for c in new_claims_str.split(",") if c.strip()]

            users[new_username] = {
                "username": new_username,
                "password": hashed,
                "roles": [],
                "claims": claims,
            }
            if users_path:
                save_users_fn(users_path, users)
            logger.info("Admin %s added user %s", admin_user, new_username)
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
                return _render_panel(auth_token, message=f"User '{target}' deleted.")
            return _render_panel(auth_token, error=f"User '{target}' not found.")

        elif action == "reset_password":
            target = request.form.get("target_user", "")
            new_pw = request.form.get("new_pw", "")
            if not new_pw or len(new_pw) < 8:
                return _render_panel(auth_token, error="Password must be at least 8 characters.")
            user = users.get(target)
            if not user:
                return _render_panel(auth_token, error=f"User '{target}' not found.")
            import bcrypt
            user["password"] = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
            if users_path:
                save_users_fn(users_path, users)
            logger.info("Admin %s reset password for %s", admin_user, target)
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
            return _render_panel(auth_token, message=f"MFA removed for '{target}'.")

        elif action == "set_claims":
            target = request.form.get("claims_user", "")
            claims_str = request.form.get("user_claims", "").strip()
            user = users.get(target)
            if not user:
                return _render_panel(auth_token, error=f"User '{target}' not found.")
            claims = [c.strip() for c in claims_str.split(",") if c.strip()]
            user["claims"] = claims
            if users_path:
                save_users_fn(users_path, users)
            logger.info("Admin %s set claims for %s: %s", admin_user, target, claims)
            return _render_panel(auth_token, message=f"Claims updated for '{target}'.")

        elif action == "upsert_sp":
            sp_protocol = request.form.get("sp_protocol", "").strip().lower()
            sp_path = request.form.get("sp_path", "").strip().lower()
            sp_url = request.form.get("sp_url", "").strip()

            if sp_protocol not in ("saml", "oauth"):
                return _render_panel(auth_token, error="Protocol must be 'saml' or 'oauth'.")
            if not sp_path or not sp_path.replace("-", "").replace("_", "").isalnum():
                return _render_panel(auth_token, error="Path must be URL-safe (letters, numbers, hyphens, underscores).")
            if not sp_url or not sp_url.startswith("https://"):
                return _render_panel(auth_token, error="URL must start with https://.")

            data = _load_services_yaml()
            if sp_protocol not in data:
                data[sp_protocol] = {}
            is_update = sp_path in data.get(sp_protocol, {})
            data[sp_protocol][sp_path] = sp_url
            _save_services_yaml(data)
            verb = "updated" if is_update else "added"
            logger.info("Admin %s %s SP: %s/%s -> %s", admin_user, verb, sp_protocol, sp_path, sp_url)
            return _render_panel(auth_token, message=f"Service provider '/{sp_path}' ({sp_protocol}) {verb}.")

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
