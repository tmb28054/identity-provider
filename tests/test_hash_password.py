"""Tests for the hash_password CLI utility."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from identity_provider_server.hash_password import main


def test_hash_password_inline(capsys):
    """Inline password argument produces a bcrypt hash."""
    with patch("sys.argv", ["idp-hash-password", "testpass"]):
        main()

    output = capsys.readouterr().out.strip()
    assert output.startswith("$2b$12$")


def test_hash_password_custom_rounds(capsys):
    """Custom rounds parameter is respected."""
    with patch("sys.argv", ["idp-hash-password", "--rounds", "4", "testpass"]):
        main()

    output = capsys.readouterr().out.strip()
    assert output.startswith("$2b$04$")


def test_hash_password_interactive(capsys):
    """Interactive mode prompts and hashes."""
    with patch("sys.argv", ["idp-hash-password"]):
        with patch("getpass.getpass", side_effect=["mypassword", "mypassword"]):
            main()

    output = capsys.readouterr().out.strip()
    assert output.startswith("$2b$12$")


def test_hash_password_interactive_mismatch():
    """Interactive mode exits on password mismatch."""
    with patch("sys.argv", ["idp-hash-password"]):
        with patch("getpass.getpass", side_effect=["pass1", "pass2"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
    assert exc_info.value.code == 1


def test_hash_password_verifies_correctly(capsys):
    """Generated hash can be verified with bcrypt."""
    import bcrypt

    with patch("sys.argv", ["idp-hash-password", "verify-me"]):
        main()

    hashed = capsys.readouterr().out.strip()
    assert bcrypt.checkpw(b"verify-me", hashed.encode())
