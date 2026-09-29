"""Unit tests for the passkey core module (identity_provider_server.webauthn_flows).

Uses ``soft_webauthn`` as a software authenticator to drive real registration
and authentication ceremonies against ``py_webauthn`` verification, plus direct
tests of the credential data model and the single-use challenge store.
"""

from __future__ import annotations

import base64
import json

import pytest
from soft_webauthn import SoftWebauthnDevice

from identity_provider_server import webauthn_flows as wf
from identity_provider_server.webauthn_flows import (
    ChallengeStore,
    RelyingParty,
    WebAuthnError,
)

RP = RelyingParty(rp_id="example.test", rp_name="Test IdP",
                  expected_origin="https://example.test")


def _b64url_to_bytes(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _bytes_to_b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _options_json_to_soft(options_json: str) -> dict:
    """Convert py_webauthn options JSON into the dict soft_webauthn expects.

    py_webauthn emits base64url strings for challenge/user.id/credential ids;
    soft_webauthn wants raw bytes inside a ``{"publicKey": {...}}`` wrapper.
    """
    opts = json.loads(options_json)
    opts["challenge"] = _b64url_to_bytes(opts["challenge"])
    if "user" in opts and "id" in opts["user"]:
        opts["user"]["id"] = _b64url_to_bytes(opts["user"]["id"])
    for key in ("excludeCredentials", "allowCredentials"):
        for desc in opts.get(key, []) or []:
            desc["id"] = _b64url_to_bytes(desc["id"])
    return {"publicKey": opts}


def _soft_attestation_to_json(att: dict) -> str:
    """Serialise a soft_webauthn attestation/assertion into the JSON string
    ``py_webauthn`` verify functions accept."""

    def enc(b):
        return _bytes_to_b64url(b) if isinstance(b, (bytes, bytearray)) else b

    resp = att["response"]
    out = {
        "id": enc(att["rawId"]),
        "rawId": enc(att["rawId"]),
        "type": att["type"],
        "response": {k: enc(v) for k, v in resp.items()},
    }
    return json.dumps(out)


def _register_device(device: SoftWebauthnDevice) -> dict:
    """Run a full registration ceremony; return the stored credential dict."""
    options_json, challenge = wf.begin_registration(RP, "alice", [])
    att = device.create(_options_json_to_soft(options_json), RP.expected_origin)
    cred = wf.finish_registration(RP, _soft_attestation_to_json(att), challenge)
    return cred


# --- data model -------------------------------------------------------------

def test_credential_helpers_roundtrip():
    user: dict = {"username": "alice"}
    assert wf.has_passkey(user) is False
    assert wf.get_credentials(user) == []
    wf.add_credential(user, credential_id="abc", public_key="pk", sign_count=0,
                      transports=["internal"], label="Laptop", now_iso="t0")
    assert wf.has_passkey(user) is True
    assert wf.find_credential(user, "abc")["label"] == "Laptop"
    assert wf.find_credential(user, "nope") is None
    assert wf.remove_credential(user, "abc") is True
    assert wf.remove_credential(user, "abc") is False
    assert wf.has_passkey(user) is False


def test_get_credentials_ignores_non_list():
    assert wf.get_credentials({"webauthn_credentials": "bad"}) == []


def test_update_credential_usage_increments():
    cred = {"sign_count": 5}
    wf.update_credential_usage(cred, new_sign_count=6, now_iso="t1")
    assert cred["sign_count"] == 6
    assert cred["last_used"] == "t1"


def test_update_credential_usage_zero_counter_ok():
    cred = {"sign_count": 0}
    wf.update_credential_usage(cred, new_sign_count=0, now_iso="t1")
    assert cred["sign_count"] == 0


def test_update_credential_usage_regression_rejected():
    cred = {"sign_count": 10}
    with pytest.raises(WebAuthnError):
        wf.update_credential_usage(cred, new_sign_count=10, now_iso="t1")
    with pytest.raises(WebAuthnError):
        wf.update_credential_usage(cred, new_sign_count=3, now_iso="t1")


# --- account factor policy --------------------------------------------------

def _user_with_passkeys(n: int, **extra) -> dict:
    user = dict(extra)
    for i in range(n):
        wf.add_credential(user, credential_id=f"c{i}", public_key="pk",
                          sign_count=0)
    return user


def test_factor_predicates():
    assert wf.has_password({"password": "x"}) is True
    assert wf.has_password({}) is False
    assert wf.has_totp({"totp_secret": "s"}) is True
    assert wf.has_totp({}) is False


def test_is_passwordless_requires_flag_and_passkey():
    # Flag set but no passkey -> not passwordless (flag ignored).
    assert wf.is_passwordless({"passwordless": True}) is False
    # Passkey but no flag -> not passwordless.
    assert wf.is_passwordless(_user_with_passkeys(1)) is False
    # Flag + passkey -> passwordless.
    assert wf.is_passwordless(_user_with_passkeys(1, passwordless=True)) is True


def test_meets_passwordless_minimum():
    # No passkey at all -> never eligible.
    assert wf.meets_passwordless_minimum({"password": "x"}) is False
    # One passkey, no other factor -> refused (lockout risk).
    assert wf.meets_passwordless_minimum(_user_with_passkeys(1)) is False
    # One passkey + password -> ok.
    assert wf.meets_passwordless_minimum(_user_with_passkeys(1, password="x")) is True
    # One passkey + TOTP -> ok.
    assert wf.meets_passwordless_minimum(
        _user_with_passkeys(1, totp_secret="s")
    ) is True
    # Two passkeys, no other factor -> ok.
    assert wf.meets_passwordless_minimum(_user_with_passkeys(2)) is True


# --- challenge store --------------------------------------------------------

def test_challenge_store_put_consume():
    store = ChallengeStore(ttl_seconds=100)
    handle = store.put(challenge=b"chal", username="alice", purpose="register", now=0)
    entry = store.consume(handle, purpose="register", now=1)
    assert entry["challenge"] == b"chal"
    assert entry["username"] == "alice"


def test_challenge_store_single_use():
    store = ChallengeStore(ttl_seconds=100)
    handle = store.put(challenge=b"c", username="a", purpose="p", now=0)
    assert store.consume(handle, purpose="p", now=1) is not None
    assert store.consume(handle, purpose="p", now=1) is None  # replay rejected


def test_challenge_store_wrong_purpose():
    store = ChallengeStore(ttl_seconds=100)
    handle = store.put(challenge=b"c", username="a", purpose="register", now=0)
    assert store.consume(handle, purpose="authenticate", now=1) is None


def test_challenge_store_expiry():
    store = ChallengeStore(ttl_seconds=10)
    handle = store.put(challenge=b"c", username="a", purpose="p", now=0)
    assert store.consume(handle, purpose="p", now=100) is None


def test_challenge_store_unknown_handle():
    store = ChallengeStore()
    assert store.consume("nope", purpose="p") is None


# --- full ceremonies via soft_webauthn --------------------------------------

def test_registration_and_authentication_roundtrip():
    device = SoftWebauthnDevice()
    cred = _register_device(device)
    assert cred["credential_id"]
    assert cred["public_key"]
    assert cred["sign_count"] == 0

    # Now authenticate with the same device.
    stored = {
        "credential_id": cred["credential_id"],
        "public_key": cred["public_key"],
        "sign_count": cred["sign_count"],
        "transports": ["internal"],
    }
    options_json, challenge = wf.begin_authentication(RP, [stored])
    assertion = device.get(_options_json_to_soft(options_json), RP.expected_origin)
    new_count = wf.finish_authentication(
        RP, _soft_attestation_to_json(assertion), challenge, stored
    )
    assert new_count >= 0


def test_credential_id_from_response():
    payload = json.dumps({"id": "cred-abc", "type": "public-key"})
    assert wf.credential_id_from_response(payload) == "cred-abc"
    assert wf.credential_id_from_response("{not json") is None
    # rawId fallback
    assert wf.credential_id_from_response(json.dumps({"rawId": "raw-1"})) == "raw-1"
    assert wf.credential_id_from_response(json.dumps({"foo": "bar"})) is None


def test_finish_registration_bad_challenge_rejected():
    device = SoftWebauthnDevice()
    options_json, _challenge = wf.begin_registration(RP, "alice", [])
    att = device.create(_options_json_to_soft(options_json), RP.expected_origin)
    with pytest.raises(WebAuthnError):
        wf.finish_registration(RP, _soft_attestation_to_json(att), b"wrong-challenge")


def test_finish_registration_malformed_rejected():
    with pytest.raises(WebAuthnError):
        wf.finish_registration(RP, "{}", b"chal")


def test_finish_authentication_wrong_origin_rejected():
    device = SoftWebauthnDevice()
    cred = _register_device(device)
    stored = {
        "credential_id": cred["credential_id"],
        "public_key": cred["public_key"],
        "sign_count": cred["sign_count"],
    }
    options_json, challenge = wf.begin_authentication(RP, [stored])
    assertion = device.get(_options_json_to_soft(options_json), RP.expected_origin)
    bad_rp = RelyingParty(rp_id="evil.test", rp_name="x",
                          expected_origin="https://evil.test")
    with pytest.raises(WebAuthnError):
        wf.finish_authentication(
            bad_rp, _soft_attestation_to_json(assertion), challenge, stored
        )


def test_transports_coercion():
    assert wf._transports(["internal", "bogus", "hybrid"]) is not None
    assert wf._transports("notalist") is None
    assert wf._transports(["bogus-only"]) is None


def test_begin_registration_excludes_existing():
    device = SoftWebauthnDevice()
    cred = _register_device(device)
    existing = [{"credential_id": cred["credential_id"]}]
    options_json, _ = wf.begin_registration(RP, "alice", existing)
    opts = json.loads(options_json)
    assert opts["excludeCredentials"]
    assert opts["excludeCredentials"][0]["id"] == cred["credential_id"]
