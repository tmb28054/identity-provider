"""Tests for the verify-jwt CLI.

A real RSA keypair is generated once per session and used to sign tokens the
same way the IdP does (``oauth_builder.build_oauth_token``), so the signature
verification path is exercised end-to-end without any network dependency.
"""

from __future__ import annotations

import base64
import datetime
import json
import time
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from identity_provider_server import verify_jwt
from identity_provider_server.oauth_builder import build_oauth_token


@pytest.fixture(scope="module")
def rsa_keypair() -> tuple[str, str]:
    """Return (private_key_pem, certificate_pem) for a throwaway RSA key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "idp.botthouse.net")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


@pytest.fixture
def cert_file(tmp_path, rsa_keypair) -> str:
    _, cert_pem = rsa_keypair
    path = tmp_path / "idp.crt"
    path.write_text(cert_pem)
    return str(path)


@pytest.fixture
def valid_token(rsa_keypair) -> str:
    key_pem, _ = rsa_keypair
    return build_oauth_token(
        "topaz",
        key_pem,
        "https://idp.botthouse.net/metadata",
        client_id="lint",
        scopes=["openid", "profile"],
    )


def _metadata_xml(cert_pem: str, *, plain: bool = False) -> str:
    body = "".join(cert_pem.strip().splitlines()[1:-1])
    tag = "X509Certificate" if plain else "ds:X509Certificate"
    return f"<EntityDescriptor><{tag}>{body}</{tag}></EntityDescriptor>"


# --- decode_segments ---


def test_decode_segments_round_trip(valid_token):
    header, payload, signature, signing_input = verify_jwt.decode_segments(valid_token)
    assert header["alg"] == "RS256"
    assert payload["sub"] == "topaz"
    assert signature
    assert signing_input.count(b".") == 1


def test_decode_segments_wrong_part_count():
    with pytest.raises(verify_jwt.VerificationError):
        verify_jwt.decode_segments("only.two")


def test_decode_segments_bad_json():
    bad = base64.urlsafe_b64encode(b"not json").rstrip(b"=").decode()
    with pytest.raises(verify_jwt.VerificationError):
        verify_jwt.decode_segments(f"{bad}.{bad}.{bad}")


# --- key loading ---


def test_load_public_key_from_cert_file(cert_file):
    key = verify_jwt.load_public_key_from_file(cert_file)
    assert isinstance(key, rsa.RSAPublicKey)


def test_load_public_key_from_public_key_pem(tmp_path, rsa_keypair):
    key_pem, _ = rsa_keypair
    private = serialization.load_pem_private_key(key_pem.encode(), password=None)
    pub_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path = tmp_path / "pub.pem"
    path.write_bytes(pub_pem)
    key = verify_jwt.load_public_key_from_file(str(path))
    assert isinstance(key, rsa.RSAPublicKey)


def test_load_public_key_from_file_missing():
    with pytest.raises(verify_jwt.VerificationError):
        verify_jwt.load_public_key_from_file("/no/such/file.pem")


def test_load_public_key_from_file_garbage(tmp_path):
    path = tmp_path / "junk.pem"
    path.write_text("-----BEGIN CERTIFICATE-----\nnotbase64\n-----END CERTIFICATE-----")
    with pytest.raises(verify_jwt.VerificationError):
        verify_jwt.load_public_key_from_file(str(path))


# --- metadata loading ---


def _mock_session(text: str):
    resp = mock.Mock()
    resp.text = text
    resp.raise_for_status = mock.Mock()
    session = mock.Mock()
    session.get.return_value = resp
    return session


def test_load_public_key_from_metadata_ds_prefix(rsa_keypair):
    _, cert_pem = rsa_keypair
    session = _mock_session(_metadata_xml(cert_pem))
    key = verify_jwt.load_public_key_from_metadata("https://x/metadata", session=session)
    assert isinstance(key, rsa.RSAPublicKey)


def test_load_public_key_from_metadata_plain_tag(rsa_keypair):
    _, cert_pem = rsa_keypair
    session = _mock_session(_metadata_xml(cert_pem, plain=True))
    key = verify_jwt.load_public_key_from_metadata("https://x/metadata", session=session)
    assert isinstance(key, rsa.RSAPublicKey)


def test_load_public_key_from_metadata_no_cert():
    session = _mock_session("<EntityDescriptor/>")
    with pytest.raises(verify_jwt.VerificationError):
        verify_jwt.load_public_key_from_metadata("https://x/metadata", session=session)


def test_load_public_key_from_metadata_bad_cert_bytes():
    session = _mock_session("<ds:X509Certificate>bad-b64!!</ds:X509Certificate>")
    with pytest.raises(verify_jwt.VerificationError):
        verify_jwt.load_public_key_from_metadata("https://x/metadata", session=session)


def test_load_public_key_from_metadata_fetch_error():
    import requests

    session = mock.Mock()
    session.get.side_effect = requests.RequestException("boom")
    with pytest.raises(verify_jwt.VerificationError):
        verify_jwt.load_public_key_from_metadata("https://x/metadata", session=session)


def test_extract_x509_start_tag_without_end():
    with pytest.raises(verify_jwt.VerificationError):
        verify_jwt._extract_x509_from_metadata("<ds:X509Certificate>abc")


# --- verify_signature ---


def test_verify_signature_valid(valid_token, rsa_keypair):
    _, cert_pem = rsa_keypair
    _, _, signature, signing_input = verify_jwt.decode_segments(valid_token)
    key = verify_jwt._public_key_from_cert_pem(cert_pem)
    verify_jwt.verify_signature(signing_input, signature, key)  # no raise


def test_verify_signature_tampered(valid_token, rsa_keypair):
    _, cert_pem = rsa_keypair
    _, _, signature, signing_input = verify_jwt.decode_segments(valid_token)
    key = verify_jwt._public_key_from_cert_pem(cert_pem)
    with pytest.raises(verify_jwt.VerificationError):
        verify_jwt.verify_signature(signing_input + b"x", signature, key)


def test_verify_signature_rejects_non_rsa_key():
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(verify_jwt.VerificationError):
        verify_jwt.verify_signature(b"a.b", b"sig", key)


# --- check_expiry ---


def test_check_expiry_current():
    assert verify_jwt.check_expiry({"exp": 2_000}, now=1_000) is None


def test_check_expiry_expired():
    assert "expired" in verify_jwt.check_expiry({"exp": 1_000}, now=2_000)


def test_check_expiry_not_yet_valid():
    assert "not valid until" in verify_jwt.check_expiry({"nbf": 3_000}, now=2_000)


def test_check_expiry_defaults_to_now():
    assert verify_jwt.check_expiry({"exp": int(time.time()) + 3600}) is None


# --- _read_token ---


def test_read_token_stdin(monkeypatch):
    monkeypatch.setattr("sys.stdin", mock.Mock(read=lambda: "  tok \n"))
    assert verify_jwt._read_token("-") == "tok"


def test_read_token_plain():
    assert verify_jwt._read_token("  abc ") == "abc"


# --- main ---


@pytest.mark.smoke
def test_main_verifies_valid_token(valid_token, cert_file, capsys):
    rc = verify_jwt.main([valid_token, "--cert", cert_file])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Signature: VALID" in out
    assert '"sub": "topaz"' in out
    assert '"alg": "RS256"' in out


def test_main_json_output(valid_token, cert_file, capsys):
    rc = verify_jwt.main([valid_token, "--cert", cert_file, "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data["signature_valid"] is True
    assert data["claims"]["sub"] == "topaz"


def test_main_no_verify(valid_token, capsys):
    rc = verify_jwt.main([valid_token, "--no-verify"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "not checked" in out


def test_main_invalid_signature(valid_token, rsa_keypair, tmp_path, capsys):
    # Sign with one key, verify against a different key -> invalid.
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = other.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path = tmp_path / "other.pem"
    path.write_bytes(pub_pem)
    rc = verify_jwt.main([valid_token, "--cert", str(path)])
    captured = capsys.readouterr()
    assert rc == 2
    assert "Signature: INVALID" in captured.out
    assert "invalid" in captured.err


def test_main_bad_token(capsys):
    rc = verify_jwt.main(["not-a-jwt", "--no-verify"])
    assert rc == 1
    assert "error" in capsys.readouterr().err


def test_main_expired_token_returns_2(rsa_keypair, cert_file, capsys):
    key_pem, _ = rsa_keypair
    token = build_oauth_token(
        "topaz",
        key_pem,
        "https://idp.botthouse.net/metadata",
        token_expiry_minutes=-1,  # already expired
    )
    rc = verify_jwt.main([token, "--cert", cert_file])
    captured = capsys.readouterr()
    assert rc == 2
    assert "Signature: VALID" in captured.out
    assert "expired" in captured.err


def test_main_from_metadata(valid_token, rsa_keypair, capsys):
    _, cert_pem = rsa_keypair
    session = _mock_session(_metadata_xml(cert_pem))
    with mock.patch.object(
        verify_jwt.requests, "Session", return_value=session
    ):
        rc = verify_jwt.main([valid_token])
    assert rc == 0
    assert "Signature: VALID" in capsys.readouterr().out
