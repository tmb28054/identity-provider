"""OAuth 2.0 JWT token builder.

Issues signed JWT access tokens for OAuth service providers.
Tokens are signed with the same RSA key used for SAML assertions.
"""

from __future__ import annotations

import base64
import json
import time
import uuid


def _b64url(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _rsa_sign_sha256(message: bytes, key_pem: str) -> bytes:
    """Sign a message with RSA-SHA256 using the PEM private key."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    private_key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr]


def build_oauth_token(
    username: str,
    key_pem: str,
    idp_entity_id: str,
    *,
    client_id: str = "",
    scopes: list[str] | None = None,
    token_expiry_minutes: int = 60,
    groups: list[str] | None = None,
    claims: list[str] | None = None,
    email: str | None = None,
) -> str:
    """Build a signed JWT access token.

    Args:
        username: Authenticated user's name (becomes the 'sub' claim).
        key_pem: PEM-encoded RSA private key for signing.
        idp_entity_id: Issuer identifier (becomes the 'iss' claim).
        client_id: OAuth client ID (becomes the 'aud' claim).
        scopes: List of granted scopes (becomes the 'scope' claim).
        token_expiry_minutes: Token validity in minutes.
        groups: Optional list of group memberships (becomes the 'groups' claim).
        claims: Optional list of user claims (becomes the 'claims' claim).
        email: Optional user email address (becomes the 'email' claim).

    Returns:
        Signed JWT string (header.payload.signature).
    """
    now = int(time.time())
    exp = now + (token_expiry_minutes * 60)

    header = {
        "alg": "RS256",
        "typ": "JWT",
    }

    payload: dict = {
        "iss": idp_entity_id,
        "sub": username,
        "aud": client_id or idp_entity_id,
        "iat": now,
        "exp": exp,
        "jti": str(uuid.uuid4()),
        "scope": " ".join(scopes or ["openid", "profile", "email"]),
    }

    if groups:
        payload["groups"] = groups
    if claims:
        payload["claims"] = claims
    if email:
        payload["email"] = email

    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())

    message = f"{header_b64}.{payload_b64}".encode()
    signature = _rsa_sign_sha256(message, key_pem)
    signature_b64 = _b64url(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"
