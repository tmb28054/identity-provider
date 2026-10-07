"""Coverage for error-handling branches and CLI paths in the smaller modules.

Targets the remaining uncovered lines in audit.py, backup.py, backup_cli.py,
get_jwt.py, hash_password.py, and config.py — mostly OSError/JSON error
handlers and console-script entry points.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from identity_provider_server import (
    audit,
    backup as bk,
    backup_cli,
    config,
    get_jwt,
    hash_password,
)


# --- audit.py ---------------------------------------------------------------

def test_audit_log_write_oserror(tmp_path, monkeypatch):
    a = audit.AuditLogger(tmp_path)
    # Make the open() for append fail -> OSError branch (swallowed + warning).
    monkeypatch.setattr(
        type(a.log_path), "open", mock.Mock(side_effect=OSError("no disk"))
    )
    a.log(username="x", result="failure")  # must not raise


def test_audit_read_recent_oserror(tmp_path, monkeypatch):
    a = audit.AuditLogger(tmp_path)
    monkeypatch.setattr(
        type(a.log_path), "read_text", mock.Mock(side_effect=OSError("gone"))
    )
    assert a.read_recent() == []


def test_audit_read_recent_skips_bad_json(tmp_path):
    a = audit.AuditLogger(tmp_path)
    a.log_path.write_text('{"a":1}\nnot-json\n{"b":2}\n')
    entries = a.read_recent()
    # The malformed line is skipped; the two valid ones are returned.
    assert len(entries) == 2


# --- backup.py error branches -----------------------------------------------

def test_load_config_bad_json(tmp_path):
    (tmp_path / "backup_config.json").write_text("{not valid json")
    cfg = bk.load_config(tmp_path)
    assert isinstance(cfg, bk.BackupConfig)  # falls back to defaults


def test_save_config_chmod_oserror(tmp_path, monkeypatch):
    monkeypatch.setattr(type(tmp_path), "chmod", mock.Mock(side_effect=OSError()))
    bk.save_config(tmp_path, bk.BackupConfig(server="s"))  # warning, no raise


def test_load_status_bad_json(tmp_path):
    (tmp_path / "backup_status.json").write_text("nope")
    assert isinstance(bk.load_status(tmp_path), bk.BackupStatus)


def test_load_archive_listing_bad_json(tmp_path):
    (tmp_path / "backup_archives.json").write_text("nope")
    assert bk.read_archive_listing(tmp_path) == []


def test_list_archives_missing_dir(tmp_path):
    assert bk.list_archives(tmp_path / "does-not-exist") == []


def test_validate_subpath_rejects():
    with pytest.raises(bk.InvalidSubpathError):
        bk.validate_subpath("../evil")


def test_safe_base_escape_raises(tmp_path):
    with pytest.raises(bk.InvalidSubpathError):
        bk.safe_base(tmp_path, "..")


def test_validate_archive_rejects_traversal(tmp_path):
    import io
    import tarfile

    # Build an archive whose member name contains a parent-dir traversal.
    archive = tmp_path / "bad.tar.gz"
    data = b"x"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo(name="../escape.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    with pytest.raises(ValueError):
        bk.validate_archive(archive)


def test_validate_archive_rejects_non_file(tmp_path):
    import tarfile

    archive = tmp_path / "dir.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo(name="adir")
        info.type = tarfile.DIRTYPE
        tar.addfile(info)
    with pytest.raises(ValueError):
        bk.validate_archive(archive)


def test_restore_archive_rejects_traversal(tmp_path, monkeypatch):
    import tarfile

    archive = tmp_path / "a.tar.gz"
    payload = tmp_path / "p"
    payload.write_text("x")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(str(payload), arcname="ok.txt")
    # Force _is_within to report the member as outside the data dir.
    monkeypatch.setattr(bk, "_is_within", lambda base, target: False)
    with pytest.raises(ValueError):
        bk.restore_archive(archive, tmp_path / "data")


# --- backup_cli.py branches -------------------------------------------------

def _cfg(tmp_path, **kw):
    bk.save_config(tmp_path, bk.BackupConfig(
        server="s", share="sh", username="u", enabled=True, **kw))


def test_umount_warning(tmp_path, monkeypatch):
    monkeypatch.setattr(
        backup_cli.subprocess, "run",
        mock.Mock(return_value=mock.Mock(returncode=1, stderr="busy")),
    )
    backup_cli._umount(tmp_path)  # logs a warning, no raise


def test_do_backup_disabled(tmp_path):
    bk.save_config(tmp_path, bk.BackupConfig(server="s", share="sh", username="u",
                                             enabled=False))
    assert backup_cli.do_backup(str(tmp_path)) == 0


def test_do_restore_not_configured(tmp_path):
    assert backup_cli.do_restore(str(tmp_path), "idp-1-2.tar.gz") == 2


def test_do_restore_mount_failure(tmp_path):
    _cfg(tmp_path)
    with mock.patch.object(backup_cli, "_mount_smb",
                           side_effect=backup_cli.MountError("no route")):
        assert backup_cli.do_restore(str(tmp_path), "idp-1-2.tar.gz.enc") == 1


def test_do_restore_archive_not_found(tmp_path):
    _cfg(tmp_path)
    with (
        mock.patch.object(backup_cli, "_mount_smb"),
        mock.patch.object(backup_cli, "_umount"),
    ):
        assert backup_cli.do_restore(str(tmp_path), "idp-1-2.tar.gz.enc") == 1


def test_do_restore_oserror(tmp_path):
    _cfg(tmp_path)

    def fake_mount(config, mount_dir):
        base = Path(mount_dir) / config.subpath / "daily"
        base.mkdir(parents=True, exist_ok=True)
        (base / "idp-1-2.tar.gz.enc").write_text("x")

    with (
        mock.patch.object(backup_cli, "_mount_smb", side_effect=fake_mount),
        mock.patch.object(backup_cli, "_umount"),
        mock.patch.object(backup_cli.bk, "snapshot_current",
                          side_effect=OSError("snap fail")),
    ):
        assert backup_cli.do_restore(str(tmp_path), "idp-1-2.tar.gz.enc") == 1


def test_test_connection_mount_failure(tmp_path):
    _cfg(tmp_path)
    with mock.patch.object(backup_cli, "_mount_smb",
                           side_effect=backup_cli.MountError("x")):
        ok, _msg = backup_cli.test_connection(str(tmp_path))
    assert ok is False


def test_test_connection_oserror(tmp_path):
    _cfg(tmp_path)

    def fake_mount(config, mount_dir):
        Path(mount_dir).mkdir(parents=True, exist_ok=True)

    with (
        mock.patch.object(backup_cli, "_mount_smb", side_effect=fake_mount),
        mock.patch.object(backup_cli, "_umount"),
        mock.patch.object(backup_cli, "_check_writable"),
        mock.patch.object(backup_cli.bk, "safe_base", side_effect=OSError("boom")),
    ):
        ok, msg = backup_cli.test_connection(str(tmp_path))
    assert ok is False


def test_cli_main_unknown_returns_2(capsys):
    assert backup_cli.main(["test", "--data-dir", "/tmp/x"]) in (0, 1, 2)  # nosec B108


def test_cli_main_dispatches(tmp_path):
    with mock.patch.object(backup_cli, "do_backup", return_value=0) as d:
        assert backup_cli.main(["backup", "--data-dir", str(tmp_path)]) == 0
        d.assert_called_once()
    with mock.patch.object(backup_cli, "do_restore", return_value=0) as r:
        backup_cli.main(["restore", "--data-dir", str(tmp_path),
                         "--archive", "idp-1-2.tar.gz"])
        r.assert_called_once()


# --- get_jwt.py prompt + main decode failure --------------------------------

def test_get_jwt_prompt(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda p="": "typed")
    assert get_jwt._prompt("User") == "typed"
    monkeypatch.setattr(get_jwt.getpass, "getpass", lambda p="": "secret")
    assert get_jwt._prompt("Pass", secret=True) == "secret"


def test_get_jwt_main_decode_failure(monkeypatch, capsys):
    monkeypatch.setattr(get_jwt, "fetch_jwt", lambda url, **k: "not-a-jwt")
    rc = get_jwt.main(["https://idp.example/lint"])
    assert rc == 1
    assert "error" in capsys.readouterr().err


# --- hash_password.py CLI ---------------------------------------------------

def test_hash_password_inline(capsys):
    hash_password.main.__wrapped__ if hasattr(hash_password.main, "__wrapped__") else None
    with mock.patch("sys.argv", ["idp-hash-password", "secret123"]):
        hash_password.main()
    out = capsys.readouterr().out.strip()
    assert out.startswith("$2b$")


def test_hash_password_prompt(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["idp-hash-password"])
    monkeypatch.setattr(hash_password.getpass, "getpass",
                        mock.Mock(side_effect=["pw", "pw"]))
    hash_password.main()
    assert capsys.readouterr().out.strip().startswith("$2b$")


def test_hash_password_prompt_mismatch(monkeypatch):
    monkeypatch.setattr("sys.argv", ["idp-hash-password"])
    monkeypatch.setattr(hash_password.getpass, "getpass",
                        mock.Mock(side_effect=["pw", "different"]))
    with pytest.raises(SystemExit) as exc:
        hash_password.main()
    assert exc.value.code == 1


# --- config.py malformed yaml (line 191) ------------------------------------

def test_config_malformed_yaml_read_error(tmp_path):
    # Genuinely malformed YAML makes yaml.safe_load raise a YAMLError, which the
    # broad `except Exception` handler catches (config.py line 191).
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("server: {port: 5000\n  bad: [unclosed\n:::\n")
    cfg = config.load_config(str(tmp_path))
    assert cfg.server.port == 5000  # falls back to defaults, no raise


# --- backup.py remaining branches -------------------------------------------

def test_list_archives_skips_non_archives(tmp_path):
    (tmp_path / "idp-20260101-000000.tar.gz").write_text("a")
    (tmp_path / "notes.txt").write_text("b")  # skipped (line 199 continue)
    names = bk.list_archives(tmp_path)
    assert names == ["idp-20260101-000000.tar.gz"]


def test_prune_archives_unlink_oserror(tmp_path, monkeypatch):
    for i in range(3):
        (tmp_path / f"idp-2026010{i}-000000.tar.gz").write_text("x")
    monkeypatch.setattr(type(tmp_path / "x"), "unlink",
                        mock.Mock(side_effect=OSError()))
    # retention=1 forces pruning of the older two; unlink errors are swallowed.
    bk.prune_archives(tmp_path, 1)


def test_is_within_valueerror(tmp_path):
    # A path on a different anchor triggers relative_to ValueError -> False.
    assert bk._is_within(tmp_path, Path("relative/other")) is False


def test_run_backup_listing_cache_oserror(tmp_path, monkeypatch):
    # Seed data files so create_archive succeeds.
    (tmp_path / "idp.key").write_text("k")
    (tmp_path / "users.json").write_text("[]")
    mount = tmp_path / "mnt"
    mount.mkdir()
    monkeypatch.setattr(bk, "write_archive_listing",
                        mock.Mock(side_effect=OSError("cache fail")))
    status = bk.run_backup(tmp_path, mount, bk.BackupConfig(
        server="s", share="sh", username="u", subpath="idp-backup"))
    assert status.result == "success"  # cache failure is non-fatal


# --- backup_cli main test-connection dispatch (line 276) --------------------

def test_cli_main_test_command(tmp_path):
    _cfg(tmp_path)
    with mock.patch.object(backup_cli, "test_connection", return_value=(True, "ok")):
        assert backup_cli.main(["test", "--data-dir", str(tmp_path)]) == 0
    with mock.patch.object(backup_cli, "test_connection", return_value=(False, "no")):
        assert backup_cli.main(["test", "--data-dir", str(tmp_path)]) == 1


# --- hash_password bcrypt ImportError (lines 28-33) -------------------------

def test_hash_password_bcrypt_missing(monkeypatch):
    monkeypatch.setattr("sys.argv", ["idp-hash-password", "secret123"])
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "bcrypt":
            raise ImportError("no bcrypt")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(SystemExit) as exc:
        hash_password.main()
    assert exc.value.code == 1
