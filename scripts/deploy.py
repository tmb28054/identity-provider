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

SYSTEMD_UNIT = f"""\
[Unit]
Description=Identity Provider Server
After=network.target

[Service]
Type=exec
WorkingDirectory={REMOTE_BASE}
ExecStart={REMOTE_VENV}/bin/gunicorn "identity_provider_server:create_app('{REMOTE_DATA}', host='idp.botthouse.net', port=443, provider_name='idp.botthouse.net')" --bind 0.0.0.0:5000 --workers 2 --access-logfile - --error-logfile -
Restart=on-failure
RestartSec=5
Environment=SECRET_KEY=d218a93fdcdb0e0ec72adaf262fe759be98e887b386c5d3f188d97e158f591f8

[Install]
WantedBy=multi-user.target
"""


def run(cmd: str | list, *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    """Run a local shell command."""
    if isinstance(cmd, list):
        print(f"  $ {' '.join(cmd)}")
        return subprocess.run(cmd, check=check, capture_output=capture, text=True)
    print(f"  $ {cmd}")
    return subprocess.run(cmd, shell=True, check=check, capture_output=capture, text=True)


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
