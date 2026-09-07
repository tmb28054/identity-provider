"""Root-side CLI for backup and restore, invoked by systemd units.

This module is executed as root by ``idp-backup.service`` and
``idp-restore@.service``. It performs the privileged steps that the
unprivileged web app cannot:

- Mount the configured SMB share (``mount.cifs`` needs root).
- Run the backup or restore against the mounted share.
- Unmount the share (always, even on failure).

The mount credentials are read from ``backup_config.json`` in the data
directory (written by the admin portal). Backup/restore *logic* lives in
``backup.py`` and is unit-tested independently; this module is the thin
privileged wrapper and is intentionally kept minimal.

Usage:
    python -m identity_provider_server.backup_cli backup  --data-dir /opt/idp/data
    python -m identity_provider_server.backup_cli restore --data-dir /opt/idp/data \
        --archive idp-20260907-023000.tar.gz
"""

from __future__ import annotations

import argparse
import contextlib
import logging
import subprocess  # nosec
import sys
import tempfile
from pathlib import Path

from . import backup as bk

logger = logging.getLogger(__name__)

MOUNT_CMD = "/bin/mount"
UMOUNT_CMD = "/bin/umount"


class MountError(RuntimeError):
    """Raised when mounting or unmounting the SMB share fails."""


def _mount_smb(config: bk.BackupConfig, mount_dir: Path) -> None:
    """Mount the configured CIFS/SMB share at ``mount_dir`` (requires root).

    Credentials are passed via a temporary credentials file (mode 600)
    rather than the command line, so they never appear in the process
    table.
    """
    mount_dir.mkdir(parents=True, exist_ok=True)
    cred_file = tempfile.NamedTemporaryFile(  # noqa: SIM115
        mode="w", prefix="idp-smb-", suffix=".cred", delete=False
    )
    try:
        cred_file.write(f"username={config.username}\n")
        cred_file.write(f"password={config.password}\n")
        cred_file.close()
        Path(cred_file.name).chmod(0o600)

        options = f"credentials={cred_file.name},ro=false,uid=0,gid=0,file_mode=0600,dir_mode=0700"
        cmd = [
            MOUNT_CMD,
            "-t",
            "cifs",
            config.unc_path(),
            str(mount_dir),
            "-o",
            options,
        ]
        # Fixed argv, no shell; mount target/options are validated config.
        result = subprocess.run(  # nosec B603
            cmd, capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            raise MountError(
                f"mount failed ({result.returncode}): {result.stderr.strip()}"
            )
    finally:
        # Remove the credentials file immediately after mount; the kernel
        # has already read it.
        with contextlib.suppress(OSError):
            Path(cred_file.name).unlink()


def _umount(mount_dir: Path) -> None:
    """Unmount the share, ignoring 'not mounted' errors."""
    # Fixed argv, no shell.
    result = subprocess.run(  # nosec B603
        [UMOUNT_CMD, str(mount_dir)], capture_output=True, text=True, check=False
    )
    if result.returncode != 0 and "not mounted" not in result.stderr.lower():
        logger.warning("umount warning: %s", result.stderr.strip())


def do_backup(data_dir: str) -> int:
    """Mount, run a backup, unmount. Returns a process exit code."""
    config = bk.load_config(data_dir)
    if not config.is_configured:
        # Record a failure status so the portal can show the banner.
        status = bk.load_status(data_dir)
        status.result = "failure"
        status.message = "Backup not configured (missing SMB settings)."
        status.consecutive_failures += 1
        status.last_attempt = bk._now().isoformat()
        bk.save_status(data_dir, status)
        logger.error("Backup not configured")
        return 2

    with tempfile.TemporaryDirectory(prefix="idp-mnt-") as mnt:
        mount_dir = Path(mnt)
        try:
            _mount_smb(config, mount_dir)
        except MountError as exc:
            status = bk.load_status(data_dir)
            status.result = "failure"
            status.message = f"Backup failed: {exc}"
            status.consecutive_failures += 1
            status.last_attempt = bk._now().isoformat()
            bk.save_status(data_dir, status)
            logger.error("%s", exc)
            return 1
        try:
            status = bk.run_backup(data_dir, mount_dir, config)
        finally:
            _umount(mount_dir)
    return 0 if status.result == "success" else 1


def do_restore(data_dir: str, archive: str) -> int:
    """Mount, snapshot current data, restore the named archive, unmount.

    The service restart after restore is handled by the systemd unit
    (ExecStartPost), not here.
    """
    config = bk.load_config(data_dir)
    if not config.is_configured:
        logger.error("Restore not configured (missing SMB settings)")
        return 2

    # Guard the archive name against path traversal before touching the share.
    if "/" in archive or ".." in archive or not archive.endswith(".tar.gz"):
        logger.error("Invalid archive name: %s", archive)
        return 2

    with tempfile.TemporaryDirectory(prefix="idp-mnt-") as mnt:
        mount_dir = Path(mnt)
        try:
            _mount_smb(config, mount_dir)
        except MountError as exc:
            logger.error("%s", exc)
            return 1
        try:
            base = mount_dir / config.subpath
            # Look in daily first, then weekly.
            candidates = [base / "daily" / archive, base / "weekly" / archive]
            src = next((c for c in candidates if c.is_file()), None)
            if src is None:
                logger.error("Archive not found on share: %s", archive)
                return 1

            # Snapshot current data locally before overwriting.
            snap_dir = Path(data_dir) / "pre-restore-snapshots"
            snap_dir.mkdir(parents=True, exist_ok=True)
            snap = bk.snapshot_current(data_dir, snap_dir)
            logger.info("Pre-restore snapshot written: %s", snap)

            bk.restore_archive(src, data_dir)
            logger.info("Restore complete from %s", archive)
        except (OSError, ValueError) as exc:
            logger.error("Restore failed: %s", exc)
            return 1
        finally:
            _umount(mount_dir)
    return 0


def test_connection(data_dir: str) -> tuple[bool, str]:
    """Attempt to mount the share and list the backup dir. Returns (ok, msg).

    Used by the portal's "Test connection" button (invoked as root).
    """
    config = bk.load_config(data_dir)
    if not config.is_configured:
        return False, "Missing SMB settings."
    with tempfile.TemporaryDirectory(prefix="idp-mnt-") as mnt:
        mount_dir = Path(mnt)
        try:
            _mount_smb(config, mount_dir)
        except MountError as exc:
            return False, str(exc)
        try:
            base = mount_dir / config.subpath
            base.mkdir(parents=True, exist_ok=True)
            count = len(bk.list_archives(base / "daily"))
            return True, f"Connected. {count} daily archive(s) present."
        except OSError as exc:
            return False, f"Mounted but could not access {config.subpath}: {exc}"
        finally:
            _umount(mount_dir)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="idp-backup-cli",
        description="Privileged backup/restore runner (invoked by systemd).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_backup = sub.add_parser("backup", help="Run a backup to the SMB share.")
    p_backup.add_argument("--data-dir", required=True)

    p_restore = sub.add_parser("restore", help="Restore an archive from the share.")
    p_restore.add_argument("--data-dir", required=True)
    p_restore.add_argument("--archive", required=True)

    p_test = sub.add_parser("test", help="Test the SMB connection.")
    p_test.add_argument("--data-dir", required=True)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the privileged backup/restore CLI."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = _build_parser().parse_args(argv)

    if args.command == "backup":
        return do_backup(args.data_dir)
    if args.command == "restore":
        return do_restore(args.data_dir, args.archive)
    if args.command == "test":
        ok, msg = test_connection(args.data_dir)
        print(msg)
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
