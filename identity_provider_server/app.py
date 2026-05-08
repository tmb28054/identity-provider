from __future__ import annotations

import hmac
import json
import logging
import os
import secrets
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from flask import Flask, render_template_string, request

from .saml_builder import ACS_URL, build_saml_response

logger = logging.getLogger(__name__)

LOGIN_FORM = """
<!doctype html><title>AWS Login</title>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <input name="username" placeholder="Username" required><br>
  <input name="password" placeholder="Password" type="password" required><br>
  <button type="submit">Sign in</button>
  {% if error %}<p style="color:red">{{ error }}</p>{% endif %}
</form>
"""

SAML_POST = """
<!doctype html><title>Redirecting…</title>
<body onload="document.forms[0].submit()">
<form method="post" action="{{ acs }}">
  <input type="hidden" name="SAMLResponse" value="{{ saml }}">
  <input type="hidden" name="RelayState" value="">
</form></body>
"""


def _check_password(stored: str, provided: str) -> bool:
    """Check a password against a stored value.

    Supports both bcrypt hashes (starting with $2b$) and plaintext passwords
    (for backward compatibility). Plaintext comparison uses constant-time
    comparison to avoid timing attacks.
    """
    if stored.startswith("$2b$"):
        try:
            import bcrypt
            return bcrypt.checkpw(provided.encode(), stored.encode())
        except ImportError:
            logger.warning("bcrypt not installed — cannot verify hashed password")
            return False
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


def _load_users(data: Path) -> dict[str, Any]:
    """Load users from users.json."""
    return {u["username"]: u for u in json.loads((data / "users.json").read_text())}


def create_app(
    data_dir: str,
    *,
    host: str = "127.0.0.1",
    port: int = 5000,
    provider_name: str = "local-idp",
    session_duration_hours: int = 1,
) -> Flask:
    """Flask application factory.

    Args:
        data_dir: Path to directory containing users.json, idp.crt, idp.key.
        host: Bind host — used to derive the IdP entity ID.
        port: Bind port — used to derive the IdP entity ID.
        provider_name: SAML provider name registered in AWS IAM.
        session_duration_hours: SAML assertion validity in hours (1–12).
    """
    data = Path(data_dir)
    cert_pem = (data / "idp.crt").read_text()
    key_pem = (data / "idp.key").read_text()
    users = _load_users(data)
    users_file = data / "users.json"
    users_mtime = users_file.stat().st_mtime

    idp_entity_id = f"http://{host}:{port}/metadata"
    cert_b64 = "".join(cert_pem.strip().splitlines()[1:-1])

    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

    rate_limiter = _RateLimiter(max_attempts=5, window_seconds=60)

    # Store config on app for access in tests
    app.config["IDP_ENTITY_ID"] = idp_entity_id
    app.config["PROVIDER_NAME"] = provider_name
    app.config["SESSION_DURATION_HOURS"] = session_duration_hours

    def _generate_csrf_token() -> str:
        """Generate a CSRF token tied to the app secret."""
        return secrets.token_hex(32)

    def _reload_users_if_changed() -> None:
        """Reload users.json if the file has been modified."""
        nonlocal users, users_mtime
        try:
            current_mtime = users_file.stat().st_mtime
            if current_mtime > users_mtime:
                users = _load_users(data)
                users_mtime = current_mtime
                logger.info("Reloaded users.json (file changed)")
        except OSError:
            logger.warning("Could not stat users.json for hot-reload check")

    @app.before_request
    def _before_request() -> None:
        _reload_users_if_changed()

    @app.get("/health")
    def health():
        """Health check endpoint."""
        return {"status": "healthy"}, 200

    @app.get("/aws")
    def login_form():
        token = _generate_csrf_token()
        response = render_template_string(LOGIN_FORM, error=None, csrf_token=token)
        # Store token in a cookie for validation on POST
        resp = app.make_response(response)
        resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
        return resp

    @app.post("/aws")
    def login_post():
        # CSRF validation
        form_token = request.form.get("csrf_token", "")
        cookie_token = request.cookies.get("csrf_token", "")
        if not form_token or not hmac.compare_digest(form_token, cookie_token):
            return render_template_string(
                LOGIN_FORM, error="Invalid request (CSRF)", csrf_token=_generate_csrf_token()
            ), 403

        # Rate limiting
        client_ip = request.remote_addr or "unknown"
        if rate_limiter.is_limited(client_ip):
            logger.warning("Rate limited: %s", client_ip)
            token = _generate_csrf_token()
            return render_template_string(
                LOGIN_FORM, error="Too many attempts. Try again later.",
                csrf_token=token,
            ), 429

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = users.get(username)

        if not user or not _check_password(user["password"], password):
            rate_limiter.record(client_ip)
            logger.info("Failed login attempt for user=%s from ip=%s", username, client_ip)
            return render_template_string(
                LOGIN_FORM, error="Invalid credentials", csrf_token=_generate_csrf_token()
            ), 401

        logger.info("Successful login: user=%s from ip=%s", username, client_ip)
        saml_b64 = build_saml_response(
            username,
            user["roles"],
            cert_pem,
            key_pem,
            idp_entity_id,
            provider_name=provider_name,
            session_duration_hours=session_duration_hours,
        )
        return render_template_string(SAML_POST, acs=ACS_URL, saml=saml_b64)

    @app.get("/metadata")
    def metadata():
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
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="{idp_entity_id.replace('/metadata', '/aws')}"/>
  </IDPSSODescriptor>
</EntityDescriptor>"""
        return app.response_class(xml, mimetype="application/xml")

    return app
