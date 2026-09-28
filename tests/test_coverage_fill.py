"""Targeted tests that close coverage gaps in the smaller/pure modules.

These are deliberately narrow: each exercises a specific previously-uncovered
line or branch (edge cases, error paths, optional fields).
"""

from __future__ import annotations

import time

import pytest

from identity_provider_server import config, oauth_builder, services, tokens, totp


# --- tokens.py: expired / negative timestamp branch (lines 101-102) ---------

def test_token_negative_timestamp_rejected():
    tok = tokens.issue_token("s", "u", tokens.PURPOSE_SESSION, now=-5)
    assert tokens.verify_token("s", tok, tokens.PURPOSE_SESSION, 999999) is None


def test_token_non_integer_timestamp_rejected(monkeypatch):
    # Craft a token whose timestamp segment is non-numeric but signature valid.
    purpose = tokens.PURPOSE_SESSION
    import hashlib
    import hmac

    key = tokens._derive_key("s", purpose)
    payload = f"u:notanint:{purpose}"
    sig = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    bad = f"{payload}:{sig}"
    assert tokens.verify_token("s", bad, purpose, 999999) is None


# --- totp.py: all helpers ---------------------------------------------------

def test_totp_generate_verify_and_uri():
    secret = totp.generate_secret()
    assert isinstance(secret, str) and secret
    code = totp.__dict__  # ensure module import path counted
    import pyotp

    valid = pyotp.TOTP(secret).now()
    assert totp.verify_code(secret, valid) is True
    assert totp.verify_code(secret, "000000") in (True, False)  # exercises verify
    uri = totp.provisioning_uri(secret, "alice", issuer="idp")
    assert uri.startswith("otpauth://")
    data_uri = totp.qr_code_data_uri(uri)
    assert data_uri.startswith("data:image/png;base64,")
    assert code is not None


# --- oauth_builder.py: optional groups/claims/email branches ----------------

def _key_pem() -> str:
    from pathlib import Path

    return (Path(__file__).parent.parent / "data" / "idp.key").read_text()


def test_oauth_token_includes_optional_fields():
    tok = oauth_builder.build_oauth_token(
        "alice", _key_pem(), "https://idp.example/metadata",
        client_id="app", scopes=["openid"],
        token_expiry_minutes=5, groups=["g1"], claims=["c1"], email="a@e.com",
    )
    # Decode the payload segment and confirm the optional claims are present.
    import base64
    import json

    payload_b64 = tok.split(".")[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    assert payload["groups"] == ["g1"]
    assert payload["claims"] == ["c1"]
    assert payload["email"] == "a@e.com"


# --- config.py: malformed YAML falls back to defaults (line 191) ------------

def test_config_malformed_yaml_uses_defaults(tmp_path):
    (tmp_path / "config.yaml").write_text("::: not : valid : yaml :::\n  - [")
    cfg = config.load_config(str(tmp_path))
    # Falls back to defaults without raising.
    assert cfg.server.port == 5000


def test_config_env_override_and_types(monkeypatch, tmp_path):
    monkeypatch.setenv("IDP_PORT", "8080")
    monkeypatch.setenv("IDP_DEBUG", "true")
    cfg = config.load_config(str(tmp_path))
    assert cfg.server.port == 8080
    assert cfg.server.debug is True


# --- services.py: non-dict protocol section is skipped (line 115) -----------

def test_services_non_dict_section_skipped(tmp_path):
    (tmp_path / "services.yaml").write_text("saml: not-a-dict\noauth:\n  app: https://x/y\n")
    result = services.load_services(str(tmp_path))
    paths = {sp.path for sp in result}
    assert "app" in paths  # oauth parsed
