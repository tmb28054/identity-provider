"""CLI to inspect and verify a JWT issued by the identity provider.

Usage:
    verify-jwt <token>                     # verify against the IdP metadata
    verify-jwt <token> --cert data/idp.crt # verify against a local cert/PEM
    verify-jwt <token> --no-verify         # decode and print only
    cat token.txt | verify-jwt -           # read the token from stdin

The tool prints the decoded JWT header and claims (the "context"), then
validates the RS256 signature using the IdP's RSA public key. The public key
is taken from a certificate or public-key PEM file (``--cert``), or fetched
from the IdP's SAML metadata endpoint (``--metadata-url``) by extracting the
embedded ``X509Certificate``.

Exit codes:
    0  signature valid (or --no-verify)
    1  decode error, fetch error, or bad arguments
    2  signature invalid or expired
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from typing import Any

import requests

DEFAULT_METADATA_URL = "https://idp.botthouse.net/metadata"
_X509_RE_START = "<ds:X509Certificate>"
_X509_RE_END = "</ds:X509Certificate>"
# The metadata may use the ``ds:`` prefix or no prefix at all.
_X509_RE_START_PLAIN = "<X509Certificate>"
_X509_RE_END_PLAIN = "</X509Certificate>"


class VerificationError(Exception):
    """Raised when a JWT signature or structure fails verification."""


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, restoring any stripped padding."""
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def decode_segments(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """Split a compact JWT into its decoded parts.

    Args:
        token: Compact JWT string (``header.payload.signature``).

    Returns:
        A tuple of ``(header, payload, signature, signing_input)`` where
        ``signing_input`` is the ASCII ``header.payload`` bytes that were
        signed.

    Raises:
        VerificationError: If the token is not a well-formed JWT.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise VerificationError("not a valid JWT (expected three segments)")
    header_b64, payload_b64, signature_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(signature_b64)
    except (ValueError, json.JSONDecodeError) as exc:
        raise VerificationError(f"could not decode JWT segments: {exc}") from exc
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return header, payload, signature, signing_input


def _public_key_from_cert_pem(pem: str) -> Any:
    """Load an RSA public key from a certificate or public-key PEM string."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.x509 import load_pem_x509_certificate

    text = pem.strip()
    if "CERTIFICATE" in text:
        cert = load_pem_x509_certificate(text.encode())
        return cert.public_key()
    return load_pem_public_key(text.encode())


def _public_key_from_der_b64(cert_b64: str) -> Any:
    """Load an RSA public key from base64 DER certificate bytes."""
    from cryptography.x509 import load_der_x509_certificate

    der = base64.b64decode("".join(cert_b64.split()))
    cert = load_der_x509_certificate(der)
    return cert.public_key()


def load_public_key_from_file(path: str) -> Any:
    """Load an RSA public key from a PEM certificate or public-key file."""
    try:
        with open(path, encoding="utf-8") as handle:
            pem = handle.read()
    except OSError as exc:
        raise VerificationError(f"could not read key file {path}: {exc}") from exc
    try:
        return _public_key_from_cert_pem(pem)
    except ValueError as exc:
        raise VerificationError(f"could not load public key from {path}: {exc}") from exc


def _extract_x509_from_metadata(xml: str) -> str:
    """Return the first base64 X509Certificate body found in metadata XML."""
    for start_tag, end_tag in (
        (_X509_RE_START, _X509_RE_END),
        (_X509_RE_START_PLAIN, _X509_RE_END_PLAIN),
    ):
        start = xml.find(start_tag)
        if start == -1:
            continue
        start += len(start_tag)
        end = xml.find(end_tag, start)
        if end != -1:
            return xml[start:end].strip()
    raise VerificationError("no X509Certificate found in IdP metadata")


def load_public_key_from_metadata(
    metadata_url: str, *, session: requests.Session | None = None
) -> Any:
    """Fetch IdP metadata and extract its signing public key.

    Args:
        metadata_url: URL of the SAML metadata document.
        session: Optional requests session (used for testing).

    Returns:
        The RSA public key object.

    Raises:
        VerificationError: If the metadata cannot be fetched or parsed.
    """
    session = session or requests.Session()
    try:
        resp = session.get(metadata_url, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise VerificationError(f"could not fetch metadata: {exc}") from exc
    cert_b64 = _extract_x509_from_metadata(resp.text)
    try:
        return _public_key_from_der_b64(cert_b64)
    except ValueError as exc:
        raise VerificationError(
            f"metadata certificate is not valid: {exc}"
        ) from exc


def verify_signature(signing_input: bytes, signature: bytes, public_key: Any) -> None:
    """Verify an RS256 signature.

    Args:
        signing_input: The ``header.payload`` bytes that were signed.
        signature: The raw signature bytes.
        public_key: An RSA public key object.

    Raises:
        VerificationError: If the signature does not verify.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise VerificationError("public key is not an RSA key (RS256 required)")
    try:
        public_key.verify(
            signature, signing_input, padding.PKCS1v15(), hashes.SHA256()
        )
    except InvalidSignature as exc:
        raise VerificationError("signature is invalid") from exc


def check_expiry(payload: dict[str, Any], *, now: int | None = None) -> str | None:
    """Return a human-readable expiry warning, or None if the token is current.

    Args:
        payload: The decoded JWT claims.
        now: Current epoch seconds (defaults to ``time.time()``).

    Returns:
        A warning string if the token is expired or not yet valid, else None.
    """
    now = int(time.time()) if now is None else now
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and now > exp:
        return f"token expired at {_fmt_time(int(exp))} ({now - int(exp)}s ago)"
    nbf = payload.get("nbf")
    if isinstance(nbf, (int, float)) and now < nbf:
        return f"token not valid until {_fmt_time(int(nbf))}"
    return None


def _fmt_time(epoch: int) -> str:
    """Format an epoch timestamp as a UTC ISO-8601 string."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _read_token(raw: str) -> str:
    """Resolve the token argument, reading stdin when it is ``-``."""
    if raw == "-":
        return sys.stdin.read().strip()
    return raw.strip()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verify-jwt",
        description=(
            "Decode a JWT, print its header and claims, and validate the "
            "RS256 signature against the IdP public key."
        ),
    )
    parser.add_argument(
        "token",
        help="The compact JWT string, or '-' to read it from stdin.",
    )
    parser.add_argument(
        "--cert",
        metavar="PATH",
        help=(
            "Path to a certificate or public-key PEM file to verify against "
            "(e.g. data/idp.crt). Skips the metadata fetch."
        ),
    )
    parser.add_argument(
        "--metadata-url",
        default=DEFAULT_METADATA_URL,
        help=(
            "IdP SAML metadata URL to fetch the signing key from "
            f"(default: {DEFAULT_METADATA_URL})."
        ),
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Only decode and print the token; do not check the signature.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of a formatted report.",
    )
    return parser


def _resolve_public_key(args: argparse.Namespace) -> Any:
    """Load the public key per the CLI arguments."""
    if args.cert:
        return load_public_key_from_file(args.cert)
    return load_public_key_from_metadata(args.metadata_url)


def _emit_human(
    header: dict[str, Any],
    payload: dict[str, Any],
    *,
    verified: bool | None,
    expiry_warning: str | None,
) -> None:
    """Print the decoded context and verification result for humans."""
    print("Header:")
    print(json.dumps(header, indent=2, sort_keys=True))
    print("\nClaims:")
    print(json.dumps(payload, indent=2, sort_keys=True))
    print()
    if expiry_warning:
        print(f"warning: {expiry_warning}", file=sys.stderr)
    if verified is None:
        print("Signature: not checked (--no-verify)")
    elif verified:
        print("Signature: VALID")
    else:
        print("Signature: INVALID")


def _emit_json(
    header: dict[str, Any],
    payload: dict[str, Any],
    *,
    verified: bool | None,
    expiry_warning: str | None,
) -> None:
    """Print the decoded context and verification result as JSON."""
    print(
        json.dumps(
            {
                "header": header,
                "claims": payload,
                "signature_valid": verified,
                "expiry_warning": expiry_warning,
            },
            indent=2,
            sort_keys=True,
        )
    )


def main(argv: list[str] | None = None) -> int:
    """Entry point for the verify-jwt console script."""
    args = _build_parser().parse_args(argv)
    token = _read_token(args.token)

    try:
        header, payload, signature, signing_input = decode_segments(token)
    except VerificationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    expiry_warning = check_expiry(payload)

    verified: bool | None
    verify_error: str | None = None
    if args.no_verify:
        verified = None
    else:
        try:
            public_key = _resolve_public_key(args)
            verify_signature(signing_input, signature, public_key)
            verified = True
        except VerificationError as exc:
            verified = False
            verify_error = str(exc)

    emit = _emit_json if args.json else _emit_human
    emit(header, payload, verified=verified, expiry_warning=expiry_warning)

    if verified is False and verify_error:
        print(f"error: {verify_error}", file=sys.stderr)

    if verified is False or expiry_warning:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
