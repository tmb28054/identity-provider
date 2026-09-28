#!/usr/bin/env python3
"""Mint a password-recovery token for a user and print its recovery URL.

This writes a token into the IdP's ``recovery_tokens.json`` using the exact
schema the running server validates against, so the printed URL is live on
that host. Run it ON the IdP host against the real data directory, e.g.:

    python3 scripts/mint_recovery.py topaz \
        --data-dir /opt/idp/data \
        --base-url https://idp.botthouse.net

The token is single-use and expires after 24 hours (matching the server's
``RECOVERY_TOKEN_EXPIRY``). The target username must exist in the data
directory's ``users.json``; minting a token for an unknown user is refused so
you don't hand out a link that resolves to nobody.

A recovery URL is a password-reset credential. Treat it like a secret: send it
over a private channel and let it expire rather than reusing it.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
from pathlib import Path

# Matches identity_provider_server.admin.RECOVERY_TOKEN_EXPIRY.
RECOVERY_TOKEN_EXPIRY = 24 * 3600


def load_usernames(data_dir: Path) -> set[str]:
    """Return the set of usernames defined in ``<data_dir>/users.json``.

    Args:
        data_dir: The IdP data directory.

    Returns:
        Set of usernames. Empty if the file is missing or unreadable.
    """
    users_path = data_dir / "users.json"
    if not users_path.is_file():
        return set()
    raw = json.loads(users_path.read_text())
    records = raw.values() if isinstance(raw, dict) else raw
    return {r.get("username", "") for r in records if r.get("username")}


def mint_token(
    username: str,
    data_dir: Path,
    now: float | None = None,
    token: str | None = None,
) -> str:
    """Create and persist a recovery token for ``username``.

    Prunes expired tokens, stores the new one with the same schema the server
    uses (``username``/``created``/``expires``), and returns the raw token.

    Args:
        username: The account to mint a recovery token for.
        data_dir: The IdP data directory containing ``recovery_tokens.json``.
        now: Current epoch seconds (injectable for testing).
        token: Explicit token value (injectable for testing).

    Returns:
        The raw recovery token string.
    """
    now = time.time() if now is None else now
    token = secrets.token_urlsafe(48) if token is None else token

    tokens_path = data_dir / "recovery_tokens.json"
    existing: dict[str, dict] = {}
    if tokens_path.is_file():
        existing = json.loads(tokens_path.read_text())

    # Prune expired entries, then add the new token.
    existing = {
        k: v for k, v in existing.items() if v.get("expires", 0) > now
    }
    existing[token] = {
        "username": username,
        "created": now,
        "expires": now + RECOVERY_TOKEN_EXPIRY,
    }
    tokens_path.write_text(json.dumps(existing, indent=2) + "\n")
    return token


def build_url(base_url: str, token: str) -> str:
    """Build the full recovery URL.

    Args:
        base_url: The IdP base URL, e.g. ``https://idp.botthouse.net``.
        token: The raw recovery token.

    Returns:
        The full ``.../recover/<token>`` URL.
    """
    return f"{base_url.rstrip('/')}/recover/{token}"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Optional argument vector (defaults to ``sys.argv``).

    Returns:
        Process exit code (0 on success, non-zero on error).
    """
    parser = argparse.ArgumentParser(description="Mint an IdP recovery URL.")
    parser.add_argument("username", help="Account to mint a recovery token for")
    parser.add_argument(
        "--data-dir", default="/opt/idp/data",
        help="IdP data directory (default: /opt/idp/data)",
    )
    parser.add_argument(
        "--base-url", default="https://idp.botthouse.net",
        help="IdP base URL (default: https://idp.botthouse.net)",
    )
    parser.add_argument(
        "--allow-unknown", action="store_true",
        help="Mint even if the username is not in users.json (not advised)",
    )
    args = parser.parse_args(argv)

    data_dir = Path(args.data_dir)
    if not data_dir.is_dir():
        print(f"error: data directory not found: {data_dir}", file=sys.stderr)
        return 2

    known = load_usernames(data_dir)
    if not args.allow_unknown and args.username not in known:
        print(
            f"error: user '{args.username}' not found in {data_dir/'users.json'}. "
            f"Known users: {', '.join(sorted(known)) or '(none)'}. "
            f"Use --allow-unknown to override.",
            file=sys.stderr,
        )
        return 1

    token = mint_token(args.username, data_dir)
    print(build_url(args.base_url, token))
    print(
        f"(valid 24h, single-use, for user '{args.username}')",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
