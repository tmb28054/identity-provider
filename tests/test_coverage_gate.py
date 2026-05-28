"""Smoke test that enforces a minimum code coverage threshold.

This test runs the full test suite with coverage measurement and
fails if total coverage drops below 95%.
"""

import subprocess
import sys

import pytest


@pytest.mark.smoke
def test_coverage_minimum_95_percent():
    """Ensure overall code coverage stays at or above 95%."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/",
            "--ignore=tests/test_coverage_gate.py",
            "--cov=identity_provider_server",
            "--cov-fail-under=95",
            "-q",
            "--no-header",
            "--tb=no",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # Include output for debugging
        pytest.fail(
            f"Coverage dropped below 95%.\n\n"
            f"stdout:\n{result.stdout[-2000:]}\n\n"
            f"stderr:\n{result.stderr[-2000:]}"
        )
