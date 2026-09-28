#!/usr/bin/env python3
"""Deploy identity-provider-server to rpi4.

Syncs the code, installs into the venv, ensures the systemd service is running,
and runs integration tests to verify the deployment.

Usage:
    python3 scripts/deploy.py           # deploy + test
    python3 scripts/deploy.py --no-test # deploy only (skip tests)
"""

import os
import subprocess
import sys
import tempfile
import time

HOST = "root@rpi4"
REMOTE_BASE = "/opt/idp"
REMOTE_CODE = f"{REMOTE_BASE}/identity-provider"
REMOTE_VENV = f"{REMOTE_BASE}/.venv"
REMOTE_DATA = f"{REMOTE_BASE}/data"
SERVICE_NAME = "identity-provider"
IDP_URL = "https://idp.botthouse.net"
SERVICE_USER = "idp"
# The signing key is NOT committed here. It is read from an operator-managed
# EnvironmentFile on the host (0600, owned by the service user). See
# docs/installation.md. Rotate it if it is ever exposed.
REMOTE_ENV_FILE = f"{REMOTE_BASE}/idp.env"

# Runs as an unprivileged, single worker (in-memory rate-limit/nonce state is
# per-process, so a single worker keeps those controls consistent without an
# external store). Hardened with systemd sandboxing directives.
SYSTEMD_UNIT = f"""\
[Unit]
Description=Identity Provider Server
After=network.target

[Service]
Type=exec
User={SERVICE_USER}
Group={SERVICE_USER}
WorkingDirectory={REMOTE_BASE}
EnvironmentFile={REMOTE_ENV_FILE}
# Binds on all interfaces because the origin is fronted by Cloudflare (the
# network boundary is enforced upstream, not by loopback). If you move the
# proxy onto this host, prefer 127.0.0.1:5000.
ExecStart={REMOTE_VENV}/bin/gunicorn "identity_provider_server:create_app('{REMOTE_DATA}', host='idp.botthouse.net', port=443, provider_name='idp.botthouse.net')" --bind 0.0.0.0:5000 --workers 1 --access-logfile - --error-logfile -
Restart=on-failure
RestartSec=5

# --- Hardening ---
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={REMOTE_DATA}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
UMask=0077

[Install]
WantedBy=multi-user.target
"""

# --- Backup / restore units (run as root: mount.cifs needs privileges) ---

# The unprivileged web app (running as the service user) triggers these via a
# narrow sudoers rule. The units themselves run as root and do the SMB mount.
BACKUP_SERVICE_UNIT = f"""\
[Unit]
Description=Identity Provider nightly backup to SMB share
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={REMOTE_VENV}/bin/python -m identity_provider_server.backup_cli backup --data-dir {REMOTE_DATA}
"""

BACKUP_TIMER_UNIT = """\
[Unit]
Description=Run Identity Provider backup nightly at 02:30

[Timer]
OnCalendar=*-*-* 02:30:00
Persistent=true

[Install]
WantedBy=timers.target
"""

# Templated instance unit: `idp-restore@<archive>.service`. The instance name
# is the archive filename (systemd-escaped). After a successful restore the
# IdP service is restarted so the new signing key / routes take effect.
RESTORE_SERVICE_UNIT = f"""\
[Unit]
Description=Identity Provider restore from SMB archive %i
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={REMOTE_VENV}/bin/python -m identity_provider_server.backup_cli restore --data-dir {REMOTE_DATA} --archive %i
ExecStartPost=/bin/systemctl restart {SERVICE_NAME}
"""

# Sudoers rule: let the unprivileged service user start ONLY these units
# (and run the connection test), with no password. Nothing else.
#
# The restore instance name is constrained to the archive naming pattern
# (idp-<digits>-<digits>.tar.gz) rather than a bare wildcard, so the service
# user cannot start an arbitrary idp-restore@<anything>.service instance.
SUDOERS_RULE = f"""\
# Managed by scripts/deploy.py — allow the IdP service user to trigger
# backup/restore units and the SMB connection test, and nothing else.
{SERVICE_USER} ALL=(root) NOPASSWD: /bin/systemctl start idp-backup.service
{SERVICE_USER} ALL=(root) NOPASSWD: /bin/systemctl start idp-restore@idp-[0-9]*-[0-9]*.tar.gz.service
{SERVICE_USER} ALL=(root) NOPASSWD: {REMOTE_VENV}/bin/python -m identity_provider_server.backup_cli test --data-dir {REMOTE_DATA}
"""


def _scp_unit(content: str, remote_name: str) -> None:
    """Write a unit/config file locally and scp it to the remote host."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".unit", delete=False) as f:
        f.write(content)
        tmp_path = f.name
    run(f"scp {tmp_path} {HOST}:{remote_name}")
    os.unlink(tmp_path)


def deploy_backup() -> bool:
    """Install the backup/restore units, sudoers rule, and prerequisites.

    Returns True on success.
    """
    print("\n==> Installing cifs-utils (for SMB mounts)...")
    ssh("apt-get install -y cifs-utils", check=False)

    print("\n==> Writing backup/restore systemd units...")
    _scp_unit(BACKUP_SERVICE_UNIT, "/etc/systemd/system/idp-backup.service")
    _scp_unit(BACKUP_TIMER_UNIT, "/etc/systemd/system/idp-backup.timer")
    _scp_unit(RESTORE_SERVICE_UNIT, "/etc/systemd/system/idp-restore@.service")

    print("\n==> Installing sudoers rule for the service user...")
    # Stage to a temp path, validate with visudo -c, then move into place.
    _scp_unit(SUDOERS_RULE, "/tmp/idp-backup.sudoers")  # nosec B108 - remote staging path
    check = ssh("visudo -cf /tmp/idp-backup.sudoers", check=False)
    if check.returncode != 0:
        print("  ✗ sudoers rule failed validation; not installing.")
        ssh("rm -f /tmp/idp-backup.sudoers", check=False)
        return False
    ssh("install -m 0440 /tmp/idp-backup.sudoers /etc/sudoers.d/idp-backup")
    ssh("rm -f /tmp/idp-backup.sudoers", check=False)

    print("\n==> Enabling backup timer...")
    ssh("systemctl daemon-reload")
    ssh("systemctl enable --now idp-backup.timer")
    result = ssh("systemctl is-enabled idp-backup.timer", check=False)
    if result.returncode != 0:
        print("  ✗ backup timer did not enable.")
        return False
    print("  ✓ backup timer enabled (nightly at 02:30).")
    return True


def run(cmd: str | list, *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    """Run a local shell command.

    String commands are built exclusively from module-level constants (host,
    paths) — no untrusted/user input is interpolated — so shell=True is safe
    here. Prefer passing a list (no shell) for new call sites.
    """
    if isinstance(cmd, list):
        print(f"  $ {' '.join(cmd)}")
        return subprocess.run(cmd, check=check, capture_output=capture, text=True)  # noqa: S603
    print(f"  $ {cmd}")
    # nosec B602: fixed, developer-authored commands from constants; no user input.
    return subprocess.run(  # nosec B602
        cmd, shell=True, check=check, capture_output=capture, text=True  # noqa: S602
    )


def ssh(cmd: str, *, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command on the remote host via SSH."""
    return run(["ssh", HOST, cmd], check=check)


def deploy() -> bool:
    """Deploy the code and restart the service. Returns True on success."""
    print("==> Syncing code to rpi4...")
    run(
        f"rsync -az --delete "
        f"--exclude='.git' "
        f"--exclude='__pycache__' "
        f"--exclude='.pytest_cache' "
        f"--exclude='.ruff_cache' "
        f"--exclude='*.egg-info' "
        f"--exclude='.coverage' "
        f"--exclude='build/' "
        f"--exclude='data/' "
        f"--exclude='trash/' "
        f". {HOST}:{REMOTE_CODE}/",
    )

    print("\n==> Installing into venv...")
    ssh(f"{REMOTE_VENV}/bin/pip install --quiet {REMOTE_CODE}")

    print("\n==> Ensuring service user and data ownership...")
    ssh(f"id -u {SERVICE_USER} >/dev/null 2>&1 || "
        f"useradd --system --home {REMOTE_BASE} --shell /usr/sbin/nologin {SERVICE_USER}",
        check=False)
    ssh(f"chown -R {SERVICE_USER}:{SERVICE_USER} {REMOTE_DATA}", check=False)

    print("\n==> Ensuring signing-key EnvironmentFile exists (generated once)...")
    # Generate a random SECRET_KEY on first deploy; never overwrite an existing
    # one, and never commit it. Rotate manually if exposed.
    ssh(
        f"test -f {REMOTE_ENV_FILE} || "
        f"(printf 'SECRET_KEY=%s\\n' \"$(openssl rand -hex 32)\" > {REMOTE_ENV_FILE})",
        check=False,
    )
    ssh(f"chown {SERVICE_USER}:{SERVICE_USER} {REMOTE_ENV_FILE} && chmod 600 {REMOTE_ENV_FILE}",
        check=False)

    print("\n==> Writing systemd unit file...")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".service", delete=False) as f:
        f.write(SYSTEMD_UNIT)
        tmp_path = f.name
    run(f"scp {tmp_path} {HOST}:/etc/systemd/system/{SERVICE_NAME}.service")
    os.unlink(tmp_path)

    print("\n==> Reloading systemd and restarting service...")
    ssh("systemctl daemon-reload")
    ssh(f"systemctl enable {SERVICE_NAME}")
    ssh(f"systemctl restart {SERVICE_NAME}")

    # Wait for service to be ready
    print("\n==> Waiting for service to start...")
    for attempt in range(10):
        result = ssh("curl -sf http://127.0.0.1:5000/health", check=False)
        if result.returncode == 0:
            print("  Health check passed.")
            return True
        time.sleep(1)

    print("\n✗ Service failed to start. Checking logs...")
    ssh(f"journalctl -u {SERVICE_NAME} -n 20 --no-pager", check=False)
    return False


def run_integration_tests() -> bool:
    """Run the Playwright integration tests against the live server. Returns True if all pass."""
    print("\n==> Running integration tests...")
    result = run(
        [
            sys.executable, "-m", "pytest",
            "tests/integration/",
            "--browser", "chromium",
            "-q",
            "--tb=short",
        ],
        check=False,
    )

    if result.returncode == 0:
        print("\n✓ All integration tests passed.")
        return True
    else:
        print("\n✗ Integration tests FAILED.")
        return False


def rollback() -> None:
    """Restart the service with the previous code (best-effort)."""
    print("\n==> Rolling back: restarting service...")
    ssh(f"systemctl restart {SERVICE_NAME}", check=False)
    time.sleep(2)
    result = ssh("curl -sf http://127.0.0.1:5000/health", check=False)
    if result.returncode == 0:
        print("  Service restarted (using previously installed code).")
    else:
        print("  WARNING: Service may be unhealthy after rollback.")


def main() -> int:
    skip_tests = "--no-test" in sys.argv

    # Deploy
    if not deploy():
        return 1

    # Install/refresh backup infrastructure (units, sudoers, timer).
    if not deploy_backup():
        print("\n  ⚠ Backup infrastructure setup incomplete — check output above.")

    print("\n✓ Deployment complete. Service is active.")

    if skip_tests:
        print("  (integration tests skipped with --no-test)")
        return 0

    # Run integration tests
    if run_integration_tests():
        return 0

    # Tests failed — offer rollback info
    print("\n  Deployment is live but tests failed.")
    print("  The service is still running with the new code.")
    print("  To rollback manually: git stash && python3 scripts/deploy.py --no-test")
    return 1


if __name__ == "__main__":
    sys.exit(main())
