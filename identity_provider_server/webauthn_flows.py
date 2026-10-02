"""Passkey (WebAuthn/FIDO2) support.

This module wraps ``py_webauthn`` to implement the two ceremonies — registration
and authentication — plus the per-user credential data model and a single-use,
time-bound challenge store. It deliberately holds no Flask state; the app layer
wires these helpers into routes (see ``app.py``).

Design: docs/passkey-design.md. The credential record mirrors ``totp_secret`` as
a second factor: presence of a non-empty ``webauthn_credentials`` list gates the
passkey path exactly as ``totp_secret`` gates TOTP.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

CREDENTIALS_FIELD = "webauthn_credentials"


class WebAuthnError(Exception):
    """Raised when a passkey ceremony fails verification."""


# --- Data model -------------------------------------------------------------


def get_credentials(user: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the user's stored passkey credentials (possibly empty)."""
    creds = user.get(CREDENTIALS_FIELD)
    return creds if isinstance(creds, list) else []


def has_passkey(user: dict[str, Any]) -> bool:
    """True if the user has at least one registered passkey."""
    return len(get_credentials(user)) > 0


def find_credential(user: dict[str, Any], credential_id: str) -> dict[str, Any] | None:
    """Find a stored credential by its base64url id, or None."""
    for cred in get_credentials(user):
        if cred.get("credential_id") == credential_id:
            return cred
    return None


def add_credential(
    user: dict[str, Any],
    *,
    credential_id: str,
    public_key: str,
    sign_count: int,
    transports: list[str] | None = None,
    label: str = "",
    now_iso: str = "",
) -> None:
    """Append a new credential to the user record (in place).

    Args:
        user: The user dict to mutate.
        credential_id: base64url credential id.
        public_key: base64url COSE public key.
        sign_count: Initial signature counter from the authenticator.
        transports: Reported transports (e.g. ``["internal", "hybrid"]``).
        label: Human-friendly name for the credential.
        now_iso: ISO-8601 creation timestamp.
    """
    creds = user.setdefault(CREDENTIALS_FIELD, [])
    creds.append(
        {
            "credential_id": credential_id,
            "public_key": public_key,
            "sign_count": sign_count,
            "transports": transports or [],
            "label": label or "passkey",
            "created_at": now_iso,
            "last_used": "",
        }
    )


def remove_credential(user: dict[str, Any], credential_id: str) -> bool:
    """Remove a credential by id. Returns True if one was removed."""
    creds = get_credentials(user)
    remaining = [c for c in creds if c.get("credential_id") != credential_id]
    if len(remaining) == len(creds):
        return False
    user[CREDENTIALS_FIELD] = remaining
    return True


def update_credential_usage(
    credential: dict[str, Any], *, new_sign_count: int, now_iso: str
) -> None:
    """Update a credential's sign count and last-used stamp after a successful auth.

    Args:
        credential: The stored credential dict to mutate.
        new_sign_count: The counter reported by the authenticator this time.
        now_iso: ISO-8601 timestamp of this authentication.

    Raises:
        WebAuthnError: If the counter went backwards (possible cloned key). A
            counter of 0 (authenticators that don't implement counters) is only
            accepted when the stored counter is also 0.
    """
    stored = int(credential.get("sign_count", 0))
    if new_sign_count == 0 and stored == 0:
        pass  # authenticator does not use a counter
    elif new_sign_count <= stored:
        raise WebAuthnError("Authenticator sign count did not increase (possible clone).")
    credential["sign_count"] = new_sign_count
    credential["last_used"] = now_iso


# --- Account factor policy (Phase 2) ---------------------------------------

PASSWORDLESS_FIELD = "passwordless"


def has_password(user: dict[str, Any]) -> bool:
    """True if the account has a usable stored password."""
    return bool(user.get("password"))


def has_totp(user: dict[str, Any]) -> bool:
    """True if the account has TOTP (a second factor) enrolled."""
    return bool(user.get("totp_secret"))


def is_passwordless(user: dict[str, Any]) -> bool:
    """True if the account is configured to authenticate without a password.

    A passwordless account authenticates with a passkey alone (username →
    passkey). The flag is only meaningful alongside a registered passkey; it is
    ignored for gating unless the account actually has one.
    """
    return bool(user.get(PASSWORDLESS_FIELD)) and has_passkey(user)


def meets_passwordless_minimum(user: dict[str, Any]) -> bool:
    """Whether an account may safely be made passwordless (anti-lockout).

    To avoid a single lost device permanently locking a user out (design §10),
    a passwordless account must retain a recovery path: either **two or more
    passkeys**, or **one passkey plus a retained password or TOTP**. A single
    passkey with no other factor is refused.

    Args:
        user: The user record.

    Returns:
        True if the account satisfies the minimum-factor policy.
    """
    credential_count = len(get_credentials(user))
    if credential_count == 0:
        return False
    if credential_count >= 2:
        return True
    return has_password(user) or has_totp(user)


# --- Challenge store --------------------------------------------------------


@dataclass
class ChallengeStore:
    """Single-use, time-bound store of in-flight ceremony challenges.

    Keyed by an opaque random handle the client echoes back on ``finish``. Each
    entry binds the challenge bytes to the username and ceremony purpose so a
    challenge minted for one user/purpose cannot be redeemed for another.
    """

    ttl_seconds: int = 120
    _entries: dict[str, dict[str, Any]] = field(default_factory=dict)

    def _prune(self, now: float) -> None:
        expired = [h for h, e in self._entries.items() if e["expires"] <= now]
        for handle in expired:
            del self._entries[handle]

    def put(
        self, *, challenge: bytes, username: str, purpose: str, now: float | None = None
    ) -> str:
        """Store a challenge and return the handle the client must echo back."""
        current = time.time() if now is None else now
        self._prune(current)
        handle = secrets.token_urlsafe(16)
        self._entries[handle] = {
            "challenge": challenge,
            "username": username,
            "purpose": purpose,
            "expires": current + self.ttl_seconds,
        }
        return handle

    def consume(
        self, handle: str, *, purpose: str, now: float | None = None
    ) -> dict[str, Any] | None:
        """Consume a challenge by handle (single use).

        Returns the entry (``challenge``/``username``) if the handle exists, is
        unexpired, and matches ``purpose``; otherwise None. The handle is always
        removed if present, so it can never be replayed.
        """
        current = time.time() if now is None else now
        self._prune(current)
        entry = self._entries.pop(handle, None)
        if entry is None:
            return None
        if entry["purpose"] != purpose:
            return None
        return entry


# --- Ceremonies -------------------------------------------------------------


@dataclass
class RelyingParty:
    """Relying-party parameters for the ceremonies."""

    rp_id: str
    rp_name: str
    expected_origin: str


def begin_registration(
    rp: RelyingParty, username: str, existing: list[dict[str, Any]]
) -> tuple[str, bytes]:
    """Build registration options JSON for ``navigator.credentials.create()``.

    Returns ``(options_json, challenge_bytes)``. The caller stores the challenge
    in a ``ChallengeStore`` and returns the JSON to the browser.
    """
    exclude = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id"]))
        for c in existing
        if c.get("credential_id")
    ]
    options = generate_registration_options(
        rp_id=rp.rp_id,
        rp_name=rp.rp_name,
        user_name=username,
        user_id=username.encode(),
        exclude_credentials=exclude or None,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    return options_to_json(options), options.challenge


def finish_registration(
    rp: RelyingParty, credential_json: str, expected_challenge: bytes
) -> dict[str, Any]:
    """Verify a registration response and return a storable credential dict.

    Raises:
        WebAuthnError: If verification fails for any reason.
    """
    try:
        verified = verify_registration_response(
            credential=credential_json,
            expected_challenge=expected_challenge,
            expected_rp_id=rp.rp_id,
            expected_origin=rp.expected_origin,
            require_user_verification=False,
        )
    except Exception as exc:  # noqa: BLE001 - library raises many types; treat all as failure
        raise WebAuthnError(f"Passkey registration failed: {exc}") from exc
    return {
        "credential_id": bytes_to_base64url(verified.credential_id),
        "public_key": bytes_to_base64url(verified.credential_public_key),
        "sign_count": verified.sign_count,
    }


def begin_authentication(
    rp: RelyingParty,
    credentials: list[dict[str, Any]],
    *,
    require_uv: bool = False,
) -> tuple[str, bytes]:
    """Build authentication options JSON for ``navigator.credentials.get()``.

    Args:
        rp: The relying-party configuration.
        credentials: The candidate stored credentials.
        require_uv: When True, request ``user_verification=REQUIRED`` so the
            assertion carries a verified PIN/biometric and the passkey counts as
            two factors. Used for the admin flow; the SP flow leaves it False
            (``PREFERRED``).

    Returns:
        ``(options_json, challenge_bytes)``.
    """
    allow = [
        PublicKeyCredentialDescriptor(
            id=base64url_to_bytes(c["credential_id"]),
            transports=_transports(c.get("transports")),
        )
        for c in credentials
        if c.get("credential_id")
    ]
    options = generate_authentication_options(
        rp_id=rp.rp_id,
        allow_credentials=allow or None,
        user_verification=(
            UserVerificationRequirement.REQUIRED
            if require_uv
            else UserVerificationRequirement.PREFERRED
        ),
    )
    return options_to_json(options), options.challenge


def begin_authentication_decoy(
    rp: RelyingParty, seed: str, *, require_uv: bool = False
) -> tuple[str, bytes]:
    """Build options over a deterministic *decoy* credential.

    Returned for unknown or ineligible accounts so the begin response is a
    valid HTTP 200 with options in every case, removing the 200-vs-400 oracle
    that leaked account existence / admin membership. The decoy credential id
    is derived deterministically from ``seed`` (username) so a repeated probe
    of the same name yields a stable id, matching the shape of a real response.
    The subsequent finish step still fails for these accounts, so no login is
    possible — only the enumeration signal is removed.
    """
    import hashlib

    digest = hashlib.sha256(f"decoy:{rp.rp_id}:{seed}".encode()).digest()
    decoy = [{"credential_id": bytes_to_base64url(digest), "transports": None}]
    return begin_authentication(rp, decoy, require_uv=require_uv)


def finish_authentication(
    rp: RelyingParty,
    credential_json: str,
    expected_challenge: bytes,
    stored_credential: dict[str, Any],
    *,
    require_uv: bool = False,
) -> int:
    """Verify an authentication assertion; return the new sign count.

    Args:
        rp: The relying-party configuration.
        credential_json: The client assertion JSON.
        expected_challenge: The challenge issued at begin.
        stored_credential: The stored credential record.
        require_uv: When True, reject assertions whose user-verification flag is
            not set, so the passkey counts as a verified second factor. The
            admin flow passes True; the SP flow leaves it False.

    Raises:
        WebAuthnError: If verification fails.
    """
    try:
        verified = verify_authentication_response(
            credential=credential_json,
            expected_challenge=expected_challenge,
            expected_rp_id=rp.rp_id,
            expected_origin=rp.expected_origin,
            credential_public_key=base64url_to_bytes(stored_credential["public_key"]),
            credential_current_sign_count=int(stored_credential.get("sign_count", 0)),
            require_user_verification=require_uv,
        )
    except Exception as exc:  # noqa: BLE001 - library raises many types; treat all as failure
        raise WebAuthnError(f"Passkey authentication failed: {exc}") from exc
    return verified.new_sign_count


def credential_id_from_response(credential_json: str) -> str | None:
    """Extract the credential id (base64url) from a client assertion JSON.

    Used to locate which stored credential to verify against. Returns None if
    the payload is malformed.
    """
    import json

    try:
        data = json.loads(credential_json) if isinstance(credential_json, str) else credential_json
        cred_id = data.get("id") or data.get("rawId")
        return cred_id if isinstance(cred_id, str) else None
    except (ValueError, AttributeError):
        return None


def _transports(values: Any) -> list[AuthenticatorTransport] | None:
    """Coerce stored transport strings into library enums, ignoring unknowns."""
    if not isinstance(values, list):
        return None
    out: list[AuthenticatorTransport] = []
    for v in values:
        try:
            out.append(AuthenticatorTransport(v))
        except ValueError:
            continue
    return out or None
