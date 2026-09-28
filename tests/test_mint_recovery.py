"""Tests for the scripts/mint_recovery.py recovery-URL minter."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "mint_recovery.py"


def _load_module():
    """Import scripts/mint_recovery.py as a module."""
    spec = importlib.util.spec_from_file_location("mint_recovery", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mint = _load_module()


def _write_users(data_dir: Path, usernames: list[str]) -> None:
    (data_dir / "users.json").write_text(
        json.dumps([{"username": u} for u in usernames])
    )


def test_mint_token_persists_expected_schema(tmp_path):
    """A minted token is stored with username/created/expires and 24h expiry."""
    _write_users(tmp_path, ["topaz"])
    token = mint.mint_token("topaz", tmp_path, now=1000.0, token="tok123")
    assert token == "tok123"
    stored = json.loads((tmp_path / "recovery_tokens.json").read_text())
    assert stored["tok123"]["username"] == "topaz"
    assert stored["tok123"]["created"] == 1000.0
    assert stored["tok123"]["expires"] == 1000.0 + mint.RECOVERY_TOKEN_EXPIRY


def test_mint_token_prunes_expired(tmp_path):
    """Expired tokens are pruned when a new one is minted."""
    _write_users(tmp_path, ["topaz"])
    (tmp_path / "recovery_tokens.json").write_text(json.dumps({
        "old": {"username": "topaz", "created": 0, "expires": 500},
    }))
    mint.mint_token("topaz", tmp_path, now=1000.0, token="fresh")
    stored = json.loads((tmp_path / "recovery_tokens.json").read_text())
    assert "old" not in stored
    assert "fresh" in stored


def test_build_url_strips_trailing_slash():
    """The recovery URL is well-formed regardless of base-url slash."""
    assert (
        mint.build_url("https://idp.botthouse.net/", "abc")
        == "https://idp.botthouse.net/recover/abc"
    )


def test_load_usernames_missing_file(tmp_path):
    """A missing users.json yields an empty username set."""
    assert mint.load_usernames(tmp_path) == set()


def test_main_refuses_unknown_user(tmp_path, capsys):
    """Minting for a user not in users.json exits non-zero."""
    _write_users(tmp_path, ["someoneelse"])
    rc = mint.main(["topaz", "--data-dir", str(tmp_path)])
    assert rc == 1
    assert "not found" in capsys.readouterr().err


def test_main_missing_data_dir(capsys):
    """A missing data directory exits with code 2."""
    rc = mint.main(["topaz", "--data-dir", "/no/such/dir"])
    assert rc == 2
    assert "data directory not found" in capsys.readouterr().err


def test_main_success_prints_url(tmp_path, capsys):
    """A known user yields a printed recovery URL and exit 0."""
    _write_users(tmp_path, ["topaz"])
    rc = mint.main([
        "topaz", "--data-dir", str(tmp_path),
        "--base-url", "https://idp.botthouse.net",
    ])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("https://idp.botthouse.net/recover/")
    token = out.rsplit("/", 1)[-1]
    stored = json.loads((tmp_path / "recovery_tokens.json").read_text())
    assert token in stored


def test_main_allow_unknown_override(tmp_path, capsys):
    """--allow-unknown mints even for a user absent from users.json."""
    _write_users(tmp_path, ["someoneelse"])
    rc = mint.main([
        "topaz", "--data-dir", str(tmp_path), "--allow-unknown",
    ])
    assert rc == 0
    assert capsys.readouterr().out.strip().startswith("https://")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
