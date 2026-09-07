"""Tests for the get-jwt CLI.

The smoke test exercises the primary happy path (login -> token) using a
mocked requests session so it stays fast and has no network dependency.
"""

from __future__ import annotations

import base64
import json
from unittest import mock

import pytest

from identity_provider_server import get_jwt


def _make_jwt(payload: dict) -> str:
    """Build a fake unsigned JWT with the given payload."""

    def _b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    body = _b64(json.dumps(payload).encode())
    return f"{header}.{body}.signature"


LOGIN_PAGE = """
<form method="post">
  <input type="hidden" name="csrf_token" value="csrf-abc">
  <input type="hidden" name="challenge_hash" value="hash-xyz">
  <div class="challenge-question">What is 3 + 4?</div>
  <input type="text" name="challenge_answer">
</form>
"""

TOTP_PAGE = """
<form method="post">
  <input type="hidden" name="csrf_token" value="csrf-def">
  <input type="hidden" name="totp_step" value="1">
  <input type="hidden" name="username" value="topaz">
  <input type="hidden" name="service_path" value="lint">
</form>
"""


def _resp(
    text: str = "",
    url: str = "https://idp.botthouse.net/lint",
    history=None,
    headers=None,
):
    r = mock.Mock()
    r.text = text
    r.url = url
    r.history = history or []
    r.headers = headers or {}
    r.raise_for_status = mock.Mock()
    return r


@pytest.mark.smoke
def test_get_jwt_happy_path(monkeypatch):
    """Login without MFA returns a token extracted from the redirect."""
    token = _make_jwt({"sub": "topaz", "claims": ["lint-user"]})
    session = mock.Mock()
    session.get.return_value = _resp(LOGIN_PAGE)
    # POST returns a 302 with the token in the Location header (redirects
    # are not followed by the CLI).
    session.post.return_value = _resp(
        text="",
        headers={"Location": f"https://lint.botthouse.net/callback?token={token}"},
    )

    prompts = iter(["topaz", "s3cret", "7"])
    monkeypatch.setattr(get_jwt, "_prompt", lambda *a, **k: next(prompts))

    result = get_jwt.fetch_jwt("https://idp.botthouse.net/lint", session=session)
    assert result == token
    payload = get_jwt._decode_jwt_payload(result)
    assert payload["claims"] == ["lint-user"]


def test_get_jwt_mfa_flow(monkeypatch):
    """When the TOTP form is returned, a second POST with the code succeeds."""
    token = _make_jwt({"sub": "topaz"})
    session = mock.Mock()
    session.get.return_value = _resp(LOGIN_PAGE)
    session.post.side_effect = [
        _resp(text=TOTP_PAGE),  # first POST -> MFA form, no token
        _resp(headers={"Location": f"https://lint.botthouse.net/callback?token={token}"}),
    ]

    prompts = iter(["topaz", "s3cret", "7", "123456"])
    monkeypatch.setattr(get_jwt, "_prompt", lambda *a, **k: next(prompts))

    result = get_jwt.fetch_jwt("https://idp.botthouse.net/lint", session=session)
    assert result == token


def test_get_jwt_token_from_history(monkeypatch):
    """Token is found in a redirect hop's Location header."""
    token = _make_jwt({"sub": "topaz"})
    hop = mock.Mock()
    hop.headers = {"Location": f"https://lint.botthouse.net/callback?token={token}"}
    session = mock.Mock()
    session.get.return_value = _resp(LOGIN_PAGE)
    session.post.return_value = _resp(url="https://lint.botthouse.net/callback", history=[hop])

    prompts = iter(["topaz", "s3cret", "7"])
    monkeypatch.setattr(get_jwt, "_prompt", lambda *a, **k: next(prompts))

    assert get_jwt.fetch_jwt("https://idp.botthouse.net/lint", session=session) == token


def test_get_jwt_no_token_raises(monkeypatch):
    """A response with neither a token nor a TOTP form raises RuntimeError."""
    session = mock.Mock()
    session.get.return_value = _resp(LOGIN_PAGE)
    session.post.return_value = _resp(text="<p>Invalid credentials</p>")

    prompts = iter(["topaz", "wrong", "7"])
    monkeypatch.setattr(get_jwt, "_prompt", lambda *a, **k: next(prompts))

    with pytest.raises(RuntimeError):
        get_jwt.fetch_jwt("https://idp.botthouse.net/lint", session=session)


def test_decode_jwt_payload_bad_token():
    with pytest.raises(ValueError):
        get_jwt._decode_jwt_payload("not-a-jwt")


def test_main_prints_decoded_payload(monkeypatch, capsys):
    token = _make_jwt({"sub": "topaz", "claims": ["lint-user"]})
    monkeypatch.setattr(get_jwt, "fetch_jwt", lambda url, **k: token)
    rc = get_jwt.main(["https://idp.botthouse.net/lint"])
    out = capsys.readouterr().out
    assert rc == 0
    assert '"sub": "topaz"' in out
    assert "lint-user" in out


def test_main_raw_prints_compact_token(monkeypatch, capsys):
    token = _make_jwt({"sub": "topaz"})
    monkeypatch.setattr(get_jwt, "fetch_jwt", lambda url, **k: token)
    rc = get_jwt.main(["https://idp.botthouse.net/lint", "--raw"])
    out = capsys.readouterr().out.strip()
    assert rc == 0
    assert out == token


def test_main_handles_failure(monkeypatch, capsys):
    def _boom(url, **k):
        raise RuntimeError("login failed")

    monkeypatch.setattr(get_jwt, "fetch_jwt", _boom)
    rc = get_jwt.main(["https://idp.botthouse.net/lint"])
    assert rc == 1
    assert "login failed" in capsys.readouterr().err
