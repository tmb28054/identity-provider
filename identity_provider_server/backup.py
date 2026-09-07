"""Backup and restore for the identity provider's critical state.

The identity provider keeps state that is not stored in git: the signing
key/certificate, users (with bcrypt hashes and TOTP secrets), and the
service/claims configuration. This module archives those files to an SMB
share and restores them on demand.

Design notes:
- The archive is a plain (uncompressed-by-name, gzip-compressed) tarball
  of the rebuild-critical files only. The append-only audit log is
  deliberately excluded.
- The file-manipulation logic (archive creation, retention pruning,
  pre-restore snapshot, extraction) is pure and testable and does not
  touch SMB or systemd. Mounting the share and scheduling are handled by
  root-owned systemd units (see scripts/deploy.py); this module operates
  on an already-mounted destination directory.
- Configuration (SMB server/share/credentials) is entered through the
  admin portal and stored in ``backup_config.json`` under the data dir.
  The backup *status* is written to ``backup_status.json`` so the portal
  can show the last result and raise a failure banner.
"""

from __future__ import annotations

import json
import logging
import tarfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Files that must be captured to rebuild the IdP. Missing files are skipped
# (not every deployment has every file, e.g. claim_roles.yaml is optional).
BACKUP_FILES: tuple[str, ...] = (
    "idp.key",
    "idp.crt",
    "users.json",
    "services.yaml",
    "config.yaml",
    "claims.json",
    "claim_roles.yaml",
    "group_roles.yaml",
    "adfs_config.yaml",
    "recovery_tokens.json",
    "backup_config.json",
)

# Never include these in an archive even if present in the data dir.
EXCLUDED_FILES: frozenset[str] = frozenset(
    {"audit.log", "backup_status.json", "backup_archives.json"}
)

CONFIG_FILENAME = "backup_config.json"
STATUS_FILENAME = "backup_status.json"
ARCHIVE_LISTING_FILENAME = "backup_archives.json"

DEFAULT_DAILY_RETENTION = 30
DEFAULT_WEEKLY_RETENTION = 52

_ARCHIVE_PREFIX = "idp-"
_ARCHIVE_SUFFIX = ".tar.gz"
# idp-YYYYMMDD-HHMMSS.tar.gz
_ARCHIVE_RE = _ARCHIVE_PREFIX + "%Y%m%d-%H%M%S" + _ARCHIVE_SUFFIX


@dataclass
class BackupConfig:
    """SMB destination + retention settings, entered via the admin portal."""

    server: str = ""  # e.g. "192.168.101.20" or "fileserver.local"
    share: str = ""  # e.g. "idp-backups"
    username: str = ""
    password: str = ""
    subpath: str = "idp-backup"  # directory within the share
    daily_retention: int = DEFAULT_DAILY_RETENTION
    weekly_retention: int = DEFAULT_WEEKLY_RETENTION
    enabled: bool = False

    @property
    def is_configured(self) -> bool:
        """True when the minimum SMB settings are present."""
        return bool(self.server and self.share and self.username)

    def unc_path(self) -> str:
        """Return the //server/share UNC path (no subpath)."""
        return f"//{self.server}/{self.share}"

    def redacted(self) -> dict:
        """Return config as a dict with the password masked (for display)."""
        data = asdict(self)
        data["password"] = "********" if self.password else ""
        return data


@dataclass
class BackupStatus:
    """Result of the most recent backup attempt (shown in the portal)."""

    last_attempt: str = ""
    last_success: str = ""
    result: str = ""  # "success" | "failure" | ""
    message: str = ""
    archive_name: str = ""
    archive_bytes: int = 0
    consecutive_failures: int = 0

    @property
    def is_failing(self) -> bool:
        """True when the most recent attempt failed (drives the banner)."""
        return self.result == "failure"


def load_config(data_dir: str | Path) -> BackupConfig:
    """Load backup config from the data directory (defaults if absent)."""
    path = Path(data_dir) / CONFIG_FILENAME
    if not path.is_file():
        return BackupConfig()
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        logger.warning("Could not read %s; using defaults", CONFIG_FILENAME)
        return BackupConfig()
    known = {f for f in BackupConfig().__dataclass_fields__}  # type: ignore[attr-defined]
    return BackupConfig(**{k: v for k, v in raw.items() if k in known})


def save_config(data_dir: str | Path, config: BackupConfig) -> None:
    """Persist backup config to the data directory with 0600 permissions."""
    path = Path(data_dir) / CONFIG_FILENAME
    path.write_text(json.dumps(asdict(config), indent=2) + "\n")
    # Credentials live here — restrict to owner read/write only.
    try:
        path.chmod(0o600)
    except OSError:
        logger.warning("Could not chmod 600 %s", path)


def load_status(data_dir: str | Path) -> BackupStatus:
    """Load the most recent backup status (empty status if absent)."""
    path = Path(data_dir) / STATUS_FILENAME
    if not path.is_file():
        return BackupStatus()
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return BackupStatus()
    known = {f for f in BackupStatus().__dataclass_fields__}  # type: ignore[attr-defined]
    return BackupStatus(**{k: v for k, v in raw.items() if k in known})


def save_status(data_dir: str | Path, status: BackupStatus) -> None:
    """Persist the backup status to the data directory."""
    path = Path(data_dir) / STATUS_FILENAME
    path.write_text(json.dumps(asdict(status), indent=2) + "\n")


def write_archive_listing(data_dir: str | Path, names: list[str]) -> None:
    """Cache the list of available archive names for the admin portal."""
    path = Path(data_dir) / ARCHIVE_LISTING_FILENAME
    path.write_text(json.dumps(names, indent=2) + "\n")


def read_archive_listing(data_dir: str | Path) -> list[str]:
    """Read the cached archive listing (empty if absent)."""
    path = Path(data_dir) / ARCHIVE_LISTING_FILENAME
    if not path.is_file():
        return []
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_archive(data_dir: str | Path, dest_path: str | Path) -> int:
    """Create a gzip tarball of the rebuild-critical files.

    Args:
        data_dir: Directory containing the IdP data files.
        dest_path: Full path of the archive to create.

    Returns:
        The size of the created archive in bytes.

    Raises:
        FileNotFoundError: If no backup-eligible files are present.
    """
    data_dir = Path(data_dir)
    dest_path = Path(dest_path)
    included: list[Path] = []
    for name in BACKUP_FILES:
        if name in EXCLUDED_FILES:
            continue
        src = data_dir / name
        if src.is_file():
            included.append(src)

    if not included:
        raise FileNotFoundError(
            f"No backup-eligible files found in {data_dir}"
        )

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(dest_path, "w:gz") as tar:
        for src in included:
            # arcname is just the filename so restore lands back in data/.
            tar.add(src, arcname=src.name)
    return dest_path.stat().st_size


def archive_name(when: datetime | None = None) -> str:
    """Return a timestamped archive filename."""
    return (when or _now()).strftime(_ARCHIVE_RE)


def list_archives(dest_dir: str | Path) -> list[str]:
    """List backup archive filenames in a directory, newest first."""
    dest_dir = Path(dest_dir)
    if not dest_dir.is_dir():
        return []
    names = [
        p.name
        for p in dest_dir.iterdir()
        if p.is_file()
        and p.name.startswith(_ARCHIVE_PREFIX)
        and p.name.endswith(_ARCHIVE_SUFFIX)
    ]
    return sorted(names, reverse=True)


def prune_archives(dest_dir: str | Path, keep: int) -> list[str]:
    """Delete all but the newest ``keep`` archives in a directory.

    Args:
        dest_dir: Directory holding archives.
        keep: Number of newest archives to retain.

    Returns:
        The list of archive names that were deleted.
    """
    dest_dir = Path(dest_dir)
    archives = list_archives(dest_dir)
    to_delete = archives[keep:] if keep >= 0 else []
    deleted: list[str] = []
    for name in to_delete:
        try:
            (dest_dir / name).unlink()
            deleted.append(name)
        except OSError:
            logger.warning("Could not delete old archive %s", name)
    return deleted


def _is_weekly(when: datetime) -> bool:
    """Sunday backups are promoted to the weekly set."""
    return when.weekday() == 6  # Monday=0 ... Sunday=6


def run_backup(
    data_dir: str | Path,
    mount_dir: str | Path,
    config: BackupConfig,
    *,
    when: datetime | None = None,
) -> BackupStatus:
    """Create a backup into an already-mounted destination and update status.

    The destination is expected to be a mounted SMB share. Writes to
    ``<mount_dir>/<subpath>/daily`` and, on Sundays, also to ``weekly``.
    Prunes each set to its retention limit, then records status.

    Args:
        data_dir: The IdP data directory (source of files + status file).
        mount_dir: The mounted SMB share root.
        config: Backup configuration (subpath + retention).
        when: Override the timestamp (for testing).

    Returns:
        The updated BackupStatus (also persisted to data_dir).
    """
    when = when or _now()
    status = load_status(data_dir)
    status.last_attempt = when.isoformat()

    try:
        base = Path(mount_dir) / config.subpath
        # Ensure the configured subpath (and its daily set) exists on the share.
        daily_dir = base / "daily"
        daily_dir.mkdir(parents=True, exist_ok=True)
        name = archive_name(when)
        size = create_archive(data_dir, daily_dir / name)
        prune_archives(daily_dir, config.daily_retention)

        if _is_weekly(when):
            weekly_dir = base / "weekly"
            weekly_dir.mkdir(parents=True, exist_ok=True)
            create_archive(data_dir, weekly_dir / name)
            prune_archives(weekly_dir, config.weekly_retention)

        status.result = "success"
        status.last_success = when.isoformat()
        status.message = f"Backup written: {name} ({size} bytes)"
        status.archive_name = name
        status.archive_bytes = size
        status.consecutive_failures = 0
        logger.info("Backup succeeded: %s (%d bytes)", name, size)

        # Cache the archive listing locally so the (unprivileged) admin portal
        # can offer archives for restore without mounting the share itself.
        try:
            merged = list_archives(daily_dir)
            if _is_weekly(when):
                merged = sorted(set(merged) | set(list_archives(base / "weekly")), reverse=True)
            write_archive_listing(data_dir, merged)
        except OSError:
            logger.warning("Could not write archive listing cache")
    except (OSError, FileNotFoundError, tarfile.TarError) as exc:
        status.result = "failure"
        status.message = f"Backup failed: {exc}"
        status.consecutive_failures += 1
        logger.error("Backup failed: %s", exc)

    save_status(data_dir, status)
    return status


def snapshot_current(data_dir: str | Path, snapshot_dir: str | Path) -> str:
    """Archive the current data files before a restore (rollback safety).

    Returns the name of the created snapshot archive.
    """
    when = _now()
    name = f"pre-restore-{when.strftime('%Y%m%d-%H%M%S')}{_ARCHIVE_SUFFIX}"
    create_archive(data_dir, Path(snapshot_dir) / name)
    return name


def _is_within(base: Path, target: Path) -> bool:
    """Return True if ``target`` is inside ``base`` (path traversal guard)."""
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def validate_archive(archive_path: str | Path) -> list[str]:
    """Validate an archive is safe to extract and return its member names.

    Rejects absolute paths, parent-directory traversal, and non-file
    members (symlinks, devices).

    Raises:
        ValueError: If the archive contains an unsafe member.
        tarfile.TarError / OSError: If the archive cannot be read.
    """
    names: list[str] = []
    with tarfile.open(archive_path, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                raise ValueError(
                    f"Unsafe archive member (not a regular file): {member.name}"
                )
            member_path = Path(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ValueError(
                    f"Unsafe archive member path: {member.name}"
                )
            names.append(member.name)
    return names


def restore_archive(
    archive_path: str | Path,
    data_dir: str | Path,
) -> list[str]:
    """Extract a validated archive into the data directory (all-or-nothing).

    Args:
        archive_path: Path to the archive to restore.
        data_dir: Destination data directory.

    Returns:
        The list of restored filenames.

    Raises:
        ValueError: If the archive contains unsafe members.
    """
    data_dir = Path(data_dir)
    names = validate_archive(archive_path)  # raises on anything unsafe
    with tarfile.open(archive_path, "r:gz") as tar:
        for member in tar.getmembers():
            dest = data_dir / member.name
            if not _is_within(data_dir, dest):
                raise ValueError(f"Refusing to extract outside data dir: {member.name}")
            # Members are validated by validate_archive() (regular files only,
            # no absolute paths, no traversal) and _is_within() re-checks each.
            tar.extract(member, path=data_dir)  # nosec B202
    logger.info("Restored %d files from %s", len(names), archive_path)
    return names
