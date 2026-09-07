"""Tests for the backup/restore logic (identity_provider_server.backup).

These cover the pure file-manipulation logic — archive round-trip,
retention pruning, config/status persistence, and path-traversal
rejection — with no SMB or systemd involvement.
"""

from __future__ import annotations

import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from identity_provider_server import backup as bk


def _seed_data_dir(tmp: Path) -> None:
    """Write a representative set of IdP data files."""
    (tmp / "idp.key").write_text("PRIVATE KEY")
    (tmp / "idp.crt").write_text("CERT")
    (tmp / "users.json").write_text(json.dumps([{"username": "a", "password": "x"}]))
    (tmp / "services.yaml").write_text("oauth: {}\n")
    (tmp / "config.yaml").write_text("server: {}\n")
    # Files that must NOT be backed up:
    (tmp / "audit.log").write_text("secret audit trail\n")
    (tmp / "backup_status.json").write_text("{}")


@pytest.mark.smoke
def test_backup_restore_round_trip(tmp_path):
    """A backup archive restores byte-for-byte into a fresh data dir."""
    src = tmp_path / "data"
    src.mkdir()
    _seed_data_dir(src)

    archive = tmp_path / "backup.tar.gz"
    size = bk.create_archive(src, archive)
    assert size > 0
    assert archive.is_file()

    # Restore into an empty directory and compare the critical files.
    dest = tmp_path / "restored"
    dest.mkdir()
    restored = bk.restore_archive(archive, dest)

    assert (dest / "idp.key").read_text() == "PRIVATE KEY"
    assert (dest / "users.json").read_text() == src.joinpath("users.json").read_text()
    # Excluded files must not be in the archive.
    assert "audit.log" not in restored
    assert "backup_status.json" not in restored
    assert not (dest / "audit.log").exists()


def test_create_archive_excludes_audit_log(tmp_path):
    src = tmp_path / "data"
    src.mkdir()
    _seed_data_dir(src)
    archive = tmp_path / "b.tar.gz"
    bk.create_archive(src, archive)
    with tarfile.open(archive) as tar:
        names = tar.getnames()
    assert "idp.key" in names
    assert "audit.log" not in names
    assert "backup_status.json" not in names


def test_create_archive_no_files_raises(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(FileNotFoundError):
        bk.create_archive(empty, tmp_path / "x.tar.gz")


def test_prune_archives_keeps_newest(tmp_path):
    dest = tmp_path / "daily"
    dest.mkdir()
    # Create archives with sortable timestamped names.
    names = [
        "idp-20260101-000000.tar.gz",
        "idp-20260102-000000.tar.gz",
        "idp-20260103-000000.tar.gz",
        "idp-20260104-000000.tar.gz",
    ]
    for n in names:
        (dest / n).write_text("x")
    deleted = bk.prune_archives(dest, keep=2)
    remaining = bk.list_archives(dest)
    assert remaining == [
        "idp-20260104-000000.tar.gz",
        "idp-20260103-000000.tar.gz",
    ]
    assert set(deleted) == {
        "idp-20260101-000000.tar.gz",
        "idp-20260102-000000.tar.gz",
    }


def test_prune_archives_keep_zero_deletes_all(tmp_path):
    dest = tmp_path / "daily"
    dest.mkdir()
    (dest / "idp-20260101-000000.tar.gz").write_text("x")
    bk.prune_archives(dest, keep=0)
    assert bk.list_archives(dest) == []


def test_list_archives_ignores_non_archives(tmp_path):
    dest = tmp_path / "daily"
    dest.mkdir()
    (dest / "idp-20260101-000000.tar.gz").write_text("x")
    (dest / "notes.txt").write_text("x")
    (dest / "pre-restore-20260101-000000.tar.gz").write_text("x")  # not idp- prefix
    assert bk.list_archives(dest) == ["idp-20260101-000000.tar.gz"]


def test_config_round_trip_and_password_redaction(tmp_path):
    cfg = bk.BackupConfig(
        server="10.0.0.5", share="idp", username="svc",
        password="s3cret", daily_retention=30, weekly_retention=52,
        enabled=True,
    )
    bk.save_config(tmp_path, cfg)
    loaded = bk.load_config(tmp_path)
    assert loaded.server == "10.0.0.5"
    assert loaded.password == "s3cret"
    assert loaded.is_configured is True
    assert loaded.unc_path() == "//10.0.0.5/idp"
    # Redacted view hides the password.
    assert loaded.redacted()["password"] == "********"
    # File permissions restricted to owner.
    mode = (tmp_path / bk.CONFIG_FILENAME).stat().st_mode & 0o777
    assert mode == 0o600


def test_config_defaults_when_absent(tmp_path):
    cfg = bk.load_config(tmp_path)
    assert cfg.is_configured is False
    assert cfg.daily_retention == bk.DEFAULT_DAILY_RETENTION
    assert cfg.weekly_retention == bk.DEFAULT_WEEKLY_RETENTION


def test_status_round_trip(tmp_path):
    status = bk.BackupStatus(result="success", message="ok", archive_bytes=123)
    bk.save_status(tmp_path, status)
    loaded = bk.load_status(tmp_path)
    assert loaded.result == "success"
    assert loaded.archive_bytes == 123
    assert loaded.is_failing is False


def test_run_backup_success_updates_status_and_listing(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    _seed_data_dir(data)
    mount = tmp_path / "mnt"
    mount.mkdir()
    cfg = bk.BackupConfig(server="s", share="sh", username="u", subpath="idp-backup")

    # A Wednesday (not weekly).
    when = datetime(2026, 9, 9, 2, 30, tzinfo=timezone.utc)
    status = bk.run_backup(data, mount, cfg, when=when)

    assert status.result == "success"
    assert status.archive_name.startswith("idp-")
    daily = mount / "idp-backup" / "daily"
    assert len(bk.list_archives(daily)) == 1
    # No weekly archive on a Wednesday.
    assert not (mount / "idp-backup" / "weekly").exists()
    # Listing cached for the portal.
    assert bk.read_archive_listing(data) == bk.list_archives(daily)


def test_run_backup_sunday_also_writes_weekly(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    _seed_data_dir(data)
    mount = tmp_path / "mnt"
    mount.mkdir()
    cfg = bk.BackupConfig(server="s", share="sh", username="u")

    # 2026-09-13 is a Sunday.
    when = datetime(2026, 9, 13, 2, 30, tzinfo=timezone.utc)
    bk.run_backup(data, mount, cfg, when=when)

    assert len(bk.list_archives(mount / "idp-backup" / "daily")) == 1
    assert len(bk.list_archives(mount / "idp-backup" / "weekly")) == 1


def test_run_backup_failure_when_source_empty(tmp_path):
    data = tmp_path / "data"
    data.mkdir()  # no files
    mount = tmp_path / "mnt"
    mount.mkdir()
    cfg = bk.BackupConfig(server="s", share="sh", username="u")
    status = bk.run_backup(data, mount, cfg)
    assert status.result == "failure"
    assert status.is_failing is True
    assert status.consecutive_failures == 1


def test_snapshot_current(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    _seed_data_dir(data)
    snap_dir = tmp_path / "snaps"
    snap_dir.mkdir()
    name = bk.snapshot_current(data, snap_dir)
    assert name.startswith("pre-restore-")
    assert (snap_dir / name).is_file()


def test_validate_archive_rejects_absolute_path(tmp_path):
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(bad, "w:gz") as tar:
        info = tarfile.TarInfo(name="/etc/passwd")
        info.size = 0
        tar.addfile(info)
    with pytest.raises(ValueError):
        bk.validate_archive(bad)


def test_validate_archive_rejects_traversal(tmp_path):
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(bad, "w:gz") as tar:
        info = tarfile.TarInfo(name="../../escape.txt")
        info.size = 0
        tar.addfile(info)
    with pytest.raises(ValueError):
        bk.validate_archive(bad)


def test_restore_rejects_unsafe_archive(tmp_path):
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(bad, "w:gz") as tar:
        info = tarfile.TarInfo(name="../escape.txt")
        info.size = 0
        tar.addfile(info)
    dest = tmp_path / "dest"
    dest.mkdir()
    with pytest.raises(ValueError):
        bk.restore_archive(bad, dest)
    assert not (tmp_path / "escape.txt").exists()
