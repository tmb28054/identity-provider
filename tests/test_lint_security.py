"""Smoke tests that enforce code quality and security scanning.

These tests run ruff (linting), bandit (security), and pip-audit
(dependency vulnerabilities) against the source code and fail if
any issues are found.
"""

import subprocess
import sys

import pytest

PACKAGE_DIR = "identity_provider_server"


@pytest.mark.smoke
def test_ruff_lint_passes():
    """All source code must pass ruff linting without errors."""
    result = subprocess.run(
        [sys.executable, "-m", "ruff", "check", PACKAGE_DIR],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"ruff lint failed:\n{result.stdout}\n{result.stderr}")


@pytest.mark.smoke
def test_bandit_security_passes():
    """All source code must pass bandit security scanning without issues."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            PACKAGE_DIR,
            "-q",
            "--severity-level",
            "low",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(
            f"bandit security scan found issues:\n{result.stdout}\n{result.stderr}"
        )


@pytest.mark.smoke
def test_pip_audit_no_vulnerabilities():
    """All dependencies must be free of known vulnerabilities."""
    result = subprocess.run(
        [
            "pip-audit",
            "--strict",
            "--desc",
        ],
        capture_output=True,
        text=True,
    )
    # pip-audit exits 0 when no vulnerabilities found.
    # It may warn about local packages not on PyPI — that's fine.
    # Only fail on actual vulnerabilities (exit code 1).
    if result.returncode != 0:
        # Filter out "not found on PyPI" lines which are just warnings
        lines = result.stderr.splitlines() + result.stdout.splitlines()
        vuln_lines = [
            l for l in lines if "not found on PyPI" not in l and l.strip()
        ]
        if vuln_lines:
            pytest.fail(
                f"pip-audit found dependency vulnerabilities:\n"
                f"{chr(10).join(vuln_lines)}"
            )
