"""TOTP (Time-based One-Time Password) support for MFA."""

from __future__ import annotations

import io
import base64

import pyotp
import qrcode


def generate_secret() -> str:
    """Generate a new random TOTP secret (base32-encoded)."""
    return pyotp.random_base32()


def verify_code(secret: str, code: str) -> bool:
    """Verify a TOTP code against a secret.

    Allows a 2-step window (60 seconds before/after) to account for clock drift.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=2)


def provisioning_uri(secret: str, username: str, issuer: str = "IdP") -> str:
    """Build the otpauth:// URI for QR code enrollment."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def qr_code_data_uri(uri: str) -> str:
    """Generate a QR code as a base64 data URI (PNG) for embedding in HTML."""
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"
