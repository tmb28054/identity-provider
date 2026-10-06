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


def safe_compare(a: str, b: str) -> bool:
    """Constant-time string comparison that tolerates non-ASCII input.

    ``hmac.compare_digest`` raises ``TypeError`` when either ``str`` operand
    contains a non-ASCII character. Since several comparison sites feed raw,
    attacker-controlled request values (token fields, CSRF tokens), we encode
    both operands to bytes first — byte comparison has no ASCII restriction —
    so a crafted non-ASCII value fails the check cleanly instead of raising an
    unhandled exception / HTTP 500 (finding idp-20261003 F2).
    """
    return hmac.compare_digest(
        a.encode("utf-8", "surrogatepass"), b.encode("utf-8", "surrogatepass")
    )


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
    if not safe_compare(tok_purpose, purpose):
        return None
    payload = f"{username}{_SEP}{ts_str}{_SEP}{tok_purpose}"
    expected = hmac.new(
        _derive_key(secret, purpose), payload.encode(), hashlib.sha256
    ).hexdigest()
    if not safe_compare(sig, expected):
        return None
    try:
        ts = int(ts_str)
    except ValueError:
        return None
    if ts < 0 or time.time() - ts > max_age:
        return None
    return username


# Session tokens carry two extra fields beyond the plain token subject so the
# server can enforce an absolute lifetime and revoke outstanding cookies:
#
#   * ``auth_time`` — the wall-clock second the session was first established.
#     It is preserved verbatim when the cookie is re-minted on each request, so
#     the idle window can slide while the absolute cap stays fixed.
#   * ``epoch`` — a per-user revocation counter copied from the user record at
#     issue time. Bumping the stored counter (on disable / password reset /
#     claim change) invalidates every cookie minted with the old value.
#
# These are packed into the token *subject* with ``|`` as the separator. The
# username charset (see ``app._USERNAME_RE``) excludes ``|`` and ``:``, so the
# outer four-field ``:`` token format is unaffected.
_SESSION_SEP = "|"


def issue_session_token(
    secret: str,
    username: str,
    *,
    auth_time: int,
    epoch: int,
    now: int | None = None,
) -> str:
    """Issue a session token binding ``auth_time`` and the revocation ``epoch``.

    Args:
        secret: The application root secret.
        username: The subject the session authenticates.
        auth_time: The second the session was first established (absolute-cap
            anchor); preserved across re-mints.
        epoch: The user's current revocation counter.
        now: Optional issue timestamp override (seconds) for the idle window.

    Returns:
        The encoded session token string.
    """
    subject = f"{username}{_SESSION_SEP}{int(auth_time)}{_SESSION_SEP}{int(epoch)}"
    return issue_token(secret, subject, PURPOSE_SESSION, now=now)


def verify_session_token(
    secret: str,
    token: str,
    idle_max_age: int,
    absolute_max_age: int,
) -> tuple[str, int, int] | None:
    """Verify a session token against the idle *and* absolute lifetime limits.

    The signed issue timestamp is treated as the last-activity marker (the
    cookie is re-minted on each authenticated request) and is checked against
    ``idle_max_age``. The embedded ``auth_time`` is checked against
    ``absolute_max_age`` so an actively-used session still faces a hard ceiling.

    Args:
        secret: The application root secret.
        token: The session token string.
        idle_max_age: Maximum seconds since last activity.
        absolute_max_age: Maximum seconds since the session was established.

    Returns:
        ``(username, auth_time, epoch)`` if valid, else ``None``.
    """
    subject = verify_token(secret, token, PURPOSE_SESSION, idle_max_age)
    if subject is None:
        return None
    parts = subject.split(_SESSION_SEP)
    if len(parts) != 3:
        return None
    username, auth_time_str, epoch_str = parts
    try:
        auth_time = int(auth_time_str)
        epoch = int(epoch_str)
    except ValueError:
        return None
    if auth_time < 0 or time.time() - auth_time > absolute_max_age:
        return None
    return username, auth_time, epoch


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
