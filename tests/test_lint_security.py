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
    """Source code must pass bandit at medium severity and above.

    Low-severity findings here are false positives (defensive password-related
    UI strings and empty template kwargs); the project standard is no issues of
    medium severity or above.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            PACKAGE_DIR,
            "-q",
            "--severity-level",
            "medium",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(
            f"bandit security scan found issues:\n{result.stdout}\n{result.stderr}"
        )


@pytest.mark.smoke
def test_bandit_scans_scripts_tree():
    """The scripts/ tree (deploy tooling) must also pass bandit."""
    result = subprocess.run(
        [sys.executable, "-m", "bandit", "-r", "scripts", "-q",
         "--severity-level", "medium"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"bandit scan of scripts/ found issues:\n{result.stdout}\n{result.stderr}")


@pytest.mark.smoke
def test_no_committed_secrets_in_tree():
    """Guard against committed credentials/secrets across the whole tree.

    This is a lightweight backstop for the pentest finding about committed
    production credentials — not a replacement for a dedicated secret scanner,
    but enough to fail CI on the obvious cases.
    """
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent
    # High-signal patterns only (near-zero false positives). A dedicated scanner
    # (gitleaks/trufflehog) belongs in CI for broader coverage; this is a backstop.
    # - A private-key header immediately followed by real base64 (not a "...placeholder...").
    # - A SECRET_KEY assigned a long hex literal (the previously committed key shape).
    key_block = re.compile(
        r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----\s*\n[A-Za-z0-9+/=\s]*[A-Za-z0-9+/=]{40,}"
    )
    secret_key = re.compile(r"SECRET_KEY\s*=\s*[\"']?[0-9a-fA-F]{32,}[\"']?")
    patterns = [key_block, secret_key]
    # Directories that legitimately contain key material or are not source.
    skip_parts = {
        ".git", "__pycache__", ".pytest_cache", ".ruff_cache", "trash",
        "node_modules", "identity_provider_server.egg-info",
    }
    allow_files = {
        "idp.key", "idp.crt",          # local dev signing material
        "secret.yaml",                 # k8s example with REPLACE placeholders
        "test_lint_security.py",       # this file (contains the patterns)
    }
    offenders: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if skip_parts & set(path.parts):
            continue
        if path.name in allow_files or path.suffix in {".pdf", ".png", ".jpg"}:
            continue
        if path.suffix not in {".py", ".json", ".yaml", ".yml", ".md", ".sh", ".toml", ".env"}:
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for pat in patterns:
            if pat.search(text):
                offenders.append(f"{path.relative_to(root)}: matched {pat.pattern[:40]}...")
    if offenders:
        pytest.fail("Possible committed secrets found:\n" + "\n".join(offenders))


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
