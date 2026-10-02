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


def test_backup_config_not_archived(tmp_path):
    """backup_config.json (SMB creds) must never be swept into the archive."""
    src = tmp_path / "data"
    src.mkdir()
    _seed_data_dir(src)
    (src / "backup_config.json").write_text('{"password": "smbsecret"}')
    archive = tmp_path / "b.tar.gz"
    bk.create_archive(src, archive)
    with tarfile.open(archive) as tar:
        assert "backup_config.json" not in tar.getnames()


@pytest.mark.smoke
def test_encrypted_backup_round_trip(tmp_path):
    """Encrypted archive + detached digest decrypts and restores correctly."""
    from cryptography.fernet import Fernet

    src = tmp_path / "data"
    src.mkdir()
    _seed_data_dir(src)
    key = Fernet.generate_key()
    base = tmp_path / "idp-20260101-000000.tar.gz"
    size = bk.create_encrypted_archive(src, base, key)
    enc = tmp_path / ("idp-20260101-000000.tar.gz" + bk.ENCRYPTED_SUFFIX)
    assert size > 0
    assert enc.is_file()
    # The ciphertext must not contain the plaintext secret.
    assert b"PRIVATE KEY" not in enc.read_bytes()
    # Detached digest sidecar exists.
    assert (tmp_path / (enc.name + bk.DIGEST_SUFFIX)).is_file()

    dest = tmp_path / "restored"
    dest.mkdir()
    bk.restore_encrypted_archive(enc, dest, key)
    assert (dest / "idp.key").read_text() == "PRIVATE KEY"


def test_encrypted_restore_rejects_tamper(tmp_path):
    """A tampered ciphertext fails the digest check and is refused."""
    from cryptography.fernet import Fernet

    src = tmp_path / "data"
    src.mkdir()
    _seed_data_dir(src)
    key = Fernet.generate_key()
    base = tmp_path / "idp-20260101-000000.tar.gz"
    bk.create_encrypted_archive(src, base, key)
    enc = tmp_path / ("idp-20260101-000000.tar.gz" + bk.ENCRYPTED_SUFFIX)
    enc.write_bytes(enc.read_bytes() + b"tampered")  # digest will mismatch
    dest = tmp_path / "restored"
    dest.mkdir()
    with pytest.raises(ValueError):
        bk.restore_encrypted_archive(enc, dest, key)


def test_encrypted_restore_rejects_wrong_key(tmp_path):
    """A valid-digest archive still fails Fernet auth under the wrong key."""
    from cryptography.fernet import Fernet

    src = tmp_path / "data"
    src.mkdir()
    _seed_data_dir(src)
    bk.create_encrypted_archive(src, tmp_path / "a.tar.gz", Fernet.generate_key())
    enc = tmp_path / ("a.tar.gz" + bk.ENCRYPTED_SUFFIX)
    dest = tmp_path / "restored"
    dest.mkdir()
    with pytest.raises(ValueError):
        bk.restore_encrypted_archive(enc, dest, Fernet.generate_key())


def test_resolve_backup_key_generates_and_reuses(tmp_path, monkeypatch):
    """Key is generated outside the data dir on first use, then reused."""
    monkeypatch.delenv(bk.BACKUP_KEY_ENV, raising=False)
    data = tmp_path / "data"
    data.mkdir()
    k1 = bk.resolve_backup_key(data)
    k2 = bk.resolve_backup_key(data)
    assert k1 == k2
    key_file = tmp_path / bk.BACKUP_KEY_FILENAME  # parent of data dir
    assert key_file.is_file()
    # The key file is NOT inside the backed-up data dir.
    assert not (data / bk.BACKUP_KEY_FILENAME).exists()


def test_resolve_backup_key_from_env(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet

    key = Fernet.generate_key().decode()
    monkeypatch.setenv(bk.BACKUP_KEY_ENV, key)
    assert bk.resolve_backup_key(tmp_path / "data").decode() == key


def test_resolve_backup_key_rejects_bad_env(tmp_path, monkeypatch):
    monkeypatch.setenv(bk.BACKUP_KEY_ENV, "not-a-fernet-key")
    with pytest.raises(bk.BackupKeyError):
        bk.resolve_backup_key(tmp_path / "data")


def test_prune_removes_digest_sidecars(tmp_path):
    """Pruning an encrypted archive also deletes its detached .sha256 sidecar."""
    d = tmp_path / "daily"
    d.mkdir()
    # Two encrypted archives with digest sidecars; keep only the newest.
    for stamp in ("20260101-000000", "20260102-000000"):
        name = f"idp-{stamp}.tar.gz{bk.ENCRYPTED_SUFFIX}"
        (d / name).write_text("cipher")
        (d / (name + bk.DIGEST_SUFFIX)).write_text("deadbeef")
    deleted = bk.prune_archives(d, keep=1)
    assert len(deleted) == 1
    old = deleted[0]
    # Both the archive and its digest sidecar are gone.
    assert not (d / old).exists()
    assert not (d / (old + bk.DIGEST_SUFFIX)).exists()


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


def test_run_backup_creates_missing_subpath(tmp_path):
    """The configured subpath is created on the share if it doesn't exist."""
    data = tmp_path / "data"
    data.mkdir()
    _seed_data_dir(data)
    mount = tmp_path / "mnt"
    mount.mkdir()  # share root exists, but subpath does not
    cfg = bk.BackupConfig(
        server="s", share="sh", username="u", subpath="deep/nested/idp-backup",
    )
    assert not (mount / "deep").exists()

    when = datetime(2026, 9, 9, 2, 30, tzinfo=timezone.utc)  # Wednesday
    status = bk.run_backup(data, mount, cfg, when=when)

    assert status.result == "success"
    daily = mount / "deep" / "nested" / "idp-backup" / "daily"
    assert daily.is_dir()
    assert len(bk.list_archives(daily)) == 1


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
