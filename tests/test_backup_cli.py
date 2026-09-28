"""Tests for the privileged backup CLI runner (backup_cli).

The actual mount/umount subprocess calls are mocked, so these run
without root or a real SMB share.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from identity_provider_server import backup as bk
from identity_provider_server import backup_cli


def _seed(data: Path) -> None:
    (data / "idp.key").write_text("KEY")
    (data / "users.json").write_text(json.dumps([{"username": "a", "password": "x"}]))


@pytest.mark.smoke
def test_do_backup_happy_path(tmp_path):
    """do_backup mounts, runs a backup, and unmounts (all mocked mount)."""
    data = tmp_path / "data"
    data.mkdir()
    _seed(data)
    bk.save_config(data, bk.BackupConfig(server="s", share="sh", username="u", enabled=True))

    # Simulate a successful mount by writing into the mount dir when _mount_smb
    # is called; the real backup then archives into it.
    def fake_mount(config, mount_dir):
        Path(mount_dir).mkdir(parents=True, exist_ok=True)

    with mock.patch.object(backup_cli, "_mount_smb", side_effect=fake_mount), \
         mock.patch.object(backup_cli, "_umount") as umount:
        rc = backup_cli.do_backup(str(data))

    assert rc == 0
    assert umount.called  # always unmounts
    status = bk.load_status(data)
    assert status.result == "success"


def test_do_backup_not_configured(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    _seed(data)
    # No config saved -> not configured.
    rc = backup_cli.do_backup(str(data))
    assert rc == 2
    assert bk.load_status(data).result == "failure"


def test_do_backup_readonly_share_records_clear_status(tmp_path):
    """A read-only mount yields an actionable failure message, not Errno 30."""
    data = tmp_path / "data"
    data.mkdir()
    _seed(data)
    bk.save_config(data, bk.BackupConfig(server="s", share="sh", username="u", enabled=True))

    # Simulate a successful mount onto a read-only directory: mount creates the
    # dir, then we make it unwritable so the write-probe fails.
    def fake_mount(config, mount_dir):
        md = Path(mount_dir)
        md.mkdir(parents=True, exist_ok=True)
        md.chmod(0o500)  # read + execute, no write

    with mock.patch.object(backup_cli, "_mount_smb", side_effect=fake_mount), \
         mock.patch.object(backup_cli, "_umount"):
        rc = backup_cli.do_backup(str(data))

    assert rc == 1
    status = bk.load_status(data)
    assert status.result == "failure"
    assert "read-only" in status.message.lower()
    assert "write permission" in status.message.lower()


def test_check_writable_raises_on_readonly(tmp_path):
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        with pytest.raises(backup_cli.ReadOnlyShareError):
            backup_cli._check_writable(ro)
    finally:
        ro.chmod(0o700)  # allow cleanup


def test_check_writable_ok_on_writable(tmp_path):
    # Should not raise, and must clean up its probe file.
    backup_cli._check_writable(tmp_path)
    assert not (tmp_path / ".idp-write-test").exists()


def test_test_connection_readonly(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    _seed(data)
    bk.save_config(data, bk.BackupConfig(server="s", share="sh", username="u"))

    def fake_mount(config, mount_dir):
        md = Path(mount_dir)
        md.mkdir(parents=True, exist_ok=True)
        md.chmod(0o500)

    with mock.patch.object(backup_cli, "_mount_smb", side_effect=fake_mount), \
         mock.patch.object(backup_cli, "_umount"):
        ok, msg = backup_cli.test_connection(str(data))
    assert ok is False
    assert "read-only" in msg.lower()


def test_do_backup_mount_failure_records_status(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    _seed(data)
    bk.save_config(data, bk.BackupConfig(server="s", share="sh", username="u", enabled=True))

    with mock.patch.object(
        backup_cli, "_mount_smb", side_effect=backup_cli.MountError("no route")
    ):
        rc = backup_cli.do_backup(str(data))
    assert rc == 1
    status = bk.load_status(data)
    assert status.result == "failure"
    assert "no route" in status.message


def test_do_restore_rejects_bad_archive_name(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    _seed(data)
    bk.save_config(data, bk.BackupConfig(server="s", share="sh", username="u"))
    rc = backup_cli.do_restore(str(data), "../evil")
    assert rc == 2


def test_do_restore_happy_path(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    _seed(data)
    bk.save_config(
        data,
        bk.BackupConfig(server="s", share="sh", username="u", subpath="idp-backup"),
    )

    archive = "idp-20260101-000000.tar.gz"

    def fake_mount(config, mount_dir):
        # Lay down a valid archive on the "share".
        daily = Path(mount_dir) / "idp-backup" / "daily"
        daily.mkdir(parents=True, exist_ok=True)
        # Build an archive from a different data set to prove restore overwrites.
        other = Path(mount_dir) / "src"
        other.mkdir()
        (other / "users.json").write_text(json.dumps([{"username": "restored"}]))
        (other / "idp.key").write_text("RESTORED-KEY")
        bk.create_archive(other, daily / archive)

    with mock.patch.object(backup_cli, "_mount_smb", side_effect=fake_mount), \
         mock.patch.object(backup_cli, "_umount"):
        rc = backup_cli.do_restore(str(data), archive)

    assert rc == 0
    assert (data / "idp.key").read_text() == "RESTORED-KEY"
    # A pre-restore snapshot was taken.
    snaps = list((data / "pre-restore-snapshots").glob("pre-restore-*.tar.gz"))
    assert len(snaps) == 1


def test_test_connection_reports_archive_count(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    _seed(data)
    bk.save_config(
        data,
        bk.BackupConfig(server="s", share="sh", username="u", subpath="idp-backup"),
    )

    def fake_mount(config, mount_dir):
        daily = Path(mount_dir) / "idp-backup" / "daily"
        daily.mkdir(parents=True, exist_ok=True)
        (daily / "idp-20260101-000000.tar.gz").write_text("x")

    with mock.patch.object(backup_cli, "_mount_smb", side_effect=fake_mount), \
         mock.patch.object(backup_cli, "_umount"):
        ok, msg = backup_cli.test_connection(str(data))
    assert ok is True
    assert "1 daily archive" in msg


def test_test_connection_not_configured(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    ok, msg = backup_cli.test_connection(str(data))
    assert ok is False
    assert "Missing SMB settings" in msg


def test_mount_smb_builds_cifs_command(tmp_path):
    """_mount_smb invokes mount -t cifs with a credentials file, no inline pw."""
    cfg = bk.BackupConfig(server="10.0.0.5", share="idp", username="svc", password="pw")
    mount_dir = tmp_path / "mnt"
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        # The credentials file must exist at mount time and contain the creds.
        cred_path = cmd[cmd.index("-o") + 1].split("credentials=")[1].split(",")[0]
        captured["creds"] = Path(cred_path).read_text()
        return mock.Mock(returncode=0, stderr="")

    with mock.patch.object(backup_cli.subprocess, "run", side_effect=fake_run):
        backup_cli._mount_smb(cfg, mount_dir)

    assert captured["cmd"][0] == backup_cli.MOUNT_CMD
    assert "cifs" in captured["cmd"]
    assert "//10.0.0.5/idp" in captured["cmd"]
    # Must request read-write with the bare "rw" flag, never "ro=false"
    # (mount.cifs treats "ro=false" as read-only).
    opts = captured["cmd"][captured["cmd"].index("-o") + 1]
    assert ",rw," in f",{opts},"
    assert "ro=false" not in opts
    # Password is in the temp creds file, never on the command line.
    assert "pw" not in " ".join(captured["cmd"])
    assert "password=pw" in captured["creds"]


def test_mount_smb_raises_on_failure(tmp_path):
    cfg = bk.BackupConfig(server="s", share="sh", username="u", password="p")
    fake = mock.Mock(returncode=32, stderr="mount error(13): Permission denied")
    with mock.patch.object(backup_cli.subprocess, "run", return_value=fake):  # noqa: SIM117
        with pytest.raises(backup_cli.MountError):
            backup_cli._mount_smb(cfg, tmp_path / "mnt")


def test_umount_ignores_not_mounted(tmp_path):
    fake = mock.Mock(returncode=1, stderr="umount: /mnt: not mounted.")
    with mock.patch.object(backup_cli.subprocess, "run", return_value=fake):
        # Should not raise.
        backup_cli._umount(tmp_path / "mnt")


def test_main_backup_dispatch(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    _seed(data)
    with mock.patch.object(backup_cli, "do_backup", return_value=0) as do:
        rc = backup_cli.main(["backup", "--data-dir", str(data)])
    assert rc == 0
    do.assert_called_once_with(str(data))


def test_main_restore_dispatch(tmp_path):
    with mock.patch.object(backup_cli, "do_restore", return_value=0) as do:
        rc = backup_cli.main(["restore", "--data-dir", "/d", "--archive", "a.tar.gz"])
    assert rc == 0
    do.assert_called_once_with("/d", "a.tar.gz")


def test_main_test_dispatch(capsys):
    with mock.patch.object(backup_cli, "test_connection", return_value=(True, "ok")):
        rc = backup_cli.main(["test", "--data-dir", "/d"])
    assert rc == 0
    assert "ok" in capsys.readouterr().out
