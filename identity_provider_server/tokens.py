"""Signed, purpose-scoped HMAC tokens for the identity provider.

All short-lived credentials the IdP mints (session cookie, admin authorization
token, self-service step-up token, and the intermediate "password proven"
MFA ticket) are HMAC-signed strings of the form::

    <username>:<issued_at>:<purpose>:<signature>

Two properties make these tokens non-interchangeable, which earlier versions
lacked:

* **Purpose binding** — the purpose string is part of the signed payload and is
  checked on verification, so a token minted for one context cannot satisfy a
  gate expecting another.
* **Per-purpose key derivation** — each purpose signs with a key derived from
  the root secret via HMAC, so a signature produced for one purpose is not a
  valid signature for any other purpose even if the payload were reshaped.

The module also provides a small single-use nonce store used by the MFA ticket
so a captured ticket cannot be replayed within its short validity window.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, field

# Purpose tags. These are part of the signed payload; changing a value
# invalidates every previously issued token of that purpose.
PURPOSE_SESSION = "session"
PURPOSE_ADMIN = "stepup-admin"
PURPOSE_USER = "stepup-user"
PURPOSE_MFA_PENDING = "mfa-pending"

_SEP = ":"


def _derive_key(secret: str, purpose: str) -> bytes:
    """Derive a per-purpose signing key from the root secret.

    Args:
        secret: The application root secret.
        purpose: The purpose tag the key is scoped to.

    Returns:
        A 32-byte key unique to ``purpose``.
    """
    return hmac.new(secret.encode(), f"purpose:{purpose}".encode(), hashlib.sha256).digest()


def issue_token(secret: str, username: str, purpose: str, *, now: int | None = None) -> str:
    """Issue a signed, purpose-scoped token for ``username``.

    Args:
        secret: The application root secret.
        username: The subject the token authenticates.
        purpose: One of the ``PURPOSE_*`` constants.
        now: Optional issue timestamp override (seconds); defaults to wall clock.

    Returns:
        The encoded token string.
    """
    issued_at = int(time.time()) if now is None else now
    payload = f"{username}{_SEP}{issued_at}{_SEP}{purpose}"
    sig = hmac.new(_derive_key(secret, purpose), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}{_SEP}{sig}"


def verify_token(secret: str, token: str, purpose: str, max_age: int) -> str | None:
    """Verify a token's signature, purpose, and age.

    Args:
        secret: The application root secret.
        token: The token string to verify.
        purpose: The purpose the caller requires; a token minted for any other
            purpose is rejected.
        max_age: Maximum token age in seconds.

    Returns:
        The username if the token is valid, not expired, and matches
        ``purpose``; otherwise ``None``.
    """
    if not token:
        return None
    parts = token.split(_SEP)
    if len(parts) != 4:
        return None
    username, ts_str, tok_purpose, sig = parts
    if not hmac.compare_digest(tok_purpose, purpose):
        return None
    payload = f"{username}{_SEP}{ts_str}{_SEP}{tok_purpose}"
    expected = hmac.new(
        _derive_key(secret, purpose), payload.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        ts = int(ts_str)
    except ValueError:
        return None
    if ts < 0 or time.time() - ts > max_age:
        return None
    return username


@dataclass
class NonceStore:
    """A tiny in-memory single-use nonce store with time-based expiry.

    Used to make the short-lived MFA "password proven" ticket single-use so an
    observed ticket cannot be replayed inside its validity window. Entries are
    pruned lazily on each ``consume`` call.
    """

    ttl_seconds: int = 120
    _seen: dict[str, float] = field(default_factory=dict)

    def _prune(self, now: float) -> None:
        expired = [n for n, exp in self._seen.items() if exp <= now]
        for nonce in expired:
            del self._seen[nonce]

    def consume(self, nonce: str, *, now: float | None = None) -> bool:
        """Record ``nonce`` as used. Returns False if it was already used.

        Args:
            nonce: The unique value to consume.
            now: Optional current time override (seconds).

        Returns:
            True on first use, False if the nonce was seen before (replay).
        """
        current = time.time() if now is None else now
        self._prune(current)
        if nonce in self._seen:
            return False
        self._seen[nonce] = current + self.ttl_seconds
        return True
