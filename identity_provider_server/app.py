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

from flask import Flask, render_template_string, request

from .saml_builder import ACS_URL, build_saml_response

logger = logging.getLogger(__name__)

LOGIN_FORM = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AWS Login</title>
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
    <h1>AWS Console Login</h1>
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
    op_symbol, op_func = random.choice(ops)
    a = random.randint(1, 20)
    b = random.randint(1, 12)

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

    def _make_challenge() -> tuple[str, str]:
        """Generate a challenge question and its verification hash."""
        question, _answer, challenge_hash = _generate_challenge(app.secret_key)
        return question, challenge_hash

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
        question, challenge_hash = _make_challenge()
        response = render_template_string(
            LOGIN_FORM,
            error=None,
            csrf_token=token,
            challenge_question=question,
            challenge_hash=challenge_hash,
        )
        resp = app.make_response(response)
        resp.set_cookie("csrf_token", token, httponly=True, samesite="Strict")
        return resp

    @app.post("/aws")
    def login_post():
        # CSRF validation
        form_token = request.form.get("csrf_token", "")
        cookie_token = request.cookies.get("csrf_token", "")
        if not form_token or not hmac.compare_digest(form_token, cookie_token):
            question, challenge_hash = _make_challenge()
            return render_template_string(
                LOGIN_FORM,
                error="Invalid request (CSRF)",
                csrf_token=_generate_csrf_token(),
                challenge_question=question,
                challenge_hash=challenge_hash,
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
            ), 429

        # Human verification
        challenge_answer = request.form.get("challenge_answer", "")
        challenge_hash = request.form.get("challenge_hash", "")
        if not _verify_challenge(app.secret_key, challenge_answer, challenge_hash):
            rate_limiter.record(client_ip)
            logger.info("Failed challenge from ip=%s", client_ip)
            question, new_hash = _make_challenge()
            return render_template_string(
                LOGIN_FORM,
                error="Incorrect answer — please try again.",
                csrf_token=_generate_csrf_token(),
                challenge_question=question,
                challenge_hash=new_hash,
            ), 401

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = users.get(username)

        if not user or not _check_password(user["password"], password):
            rate_limiter.record(client_ip)
            logger.info("Failed login attempt for user=%s from ip=%s", username, client_ip)
            question, new_hash = _make_challenge()
            return render_template_string(
                LOGIN_FORM,
                error="Invalid credentials",
                csrf_token=_generate_csrf_token(),
                challenge_question=question,
                challenge_hash=new_hash,
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
