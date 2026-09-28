"""Smoke test that enforces a minimum code coverage threshold.

This test runs the full test suite with coverage measurement and
fails if total coverage drops below the required threshold.
"""

import subprocess
import sys

import pytest

# Project policy: 100% line coverage is required.
REQUIRED_COVERAGE = 100


@pytest.mark.smoke
def test_coverage_minimum_threshold():
    """Ensure overall code coverage stays at or above the required threshold."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/",
            "--ignore=tests/test_coverage_gate.py",
            "--cov=identity_provider_server",
            f"--cov-fail-under={REQUIRED_COVERAGE}",
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
            f"Coverage dropped below {REQUIRED_COVERAGE}%.\n\n"
            f"stdout:\n{result.stdout[-2000:]}\n\n"
            f"stderr:\n{result.stderr[-2000:]}"
        )
