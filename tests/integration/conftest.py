"""Shared fixtures for integration tests against the live IdP."""

from __future__ import annotations

import os
import re

import pyotp
import pytest


IDP_BASE = os.environ.get("IDP_BASE_URL", "https://idp.botthouse.net")
USERNAME = os.environ.get("IDP_TEST_USER", "topaz")
PASSWORD = os.environ.get("IDP_TEST_PASSWORD", ":3-i&^MsPMzc")
TOTP_SECRET = os.environ.get("IDP_TEST_TOTP_SECRET", "P422OG7E3IJIL23SNS3DW6JWG6PCCJER")


@pytest.fixture(scope="session")
def idp_base():
    """Base URL for the IdP under test."""
    return IDP_BASE


@pytest.fixture(scope="session")
def credentials():
    """Test user credentials."""
    return {"username": USERNAME, "password": PASSWORD, "totp_secret": TOTP_SECRET}


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """Playwright browser context args — ignore TLS errors for self-signed certs."""
    return {**browser_context_args, "ignore_https_errors": True}


def solve_challenge(text: str) -> int:
    """Solve a math captcha like 'What is 5 + 3?' or 'What is 12 × 4?'"""
    match = re.search(r"What is (\d+)\s*([+\-\u00d7\u2212])\s*(\d+)", text)
    if not match:
        raise ValueError(f"Cannot parse challenge: {text}")
    a, op, b = int(match.group(1)), match.group(2), int(match.group(3))
    if op == "+":
        return a + b
    elif op in ("-", "\u2212"):
        return a - b
    elif op in ("\u00d7", "*"):
        return a * b
    raise ValueError(f"Unknown operator: {op}")


def get_totp_code(secret: str = TOTP_SECRET) -> str:
    """Generate a current TOTP code."""
    return pyotp.TOTP(secret).now()


def login_to_service(page, idp_base: str, path: str, creds: dict) -> None:
    """Complete the login flow (password + captcha + MFA) for a service path.

    After this call, the session cookie is set on the IdP domain.
    The page may end up on AWS Console (cross-origin) or the IdP.
    """
    page.goto(f"{idp_base}/{path}", wait_until="networkidle")
    page.fill("#username", creds["username"])
    page.fill("#password", creds["password"])
    challenge = page.inner_text(".challenge-question")
    page.fill("#challenge_answer", str(solve_challenge(challenge)))
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle", timeout=10000)

    # Handle MFA step if it appears
    content = page.content()
    if "totp_code" in content and "Two-Factor" in content:
        page.fill("#totp_code", get_totp_code(creds["totp_secret"]))
        page.click("button[type=submit]")
        # Wait for navigation — might go to AWS (cross-origin) or stay on IdP
        import time
        time.sleep(3)
        # Wait until the session cookie appears in the context
        for _ in range(10):
            cookies = page.context.cookies()
            if any(c["name"] == "idp_session" for c in cookies):
                break
            time.sleep(0.5)


def login_to_admin(page, idp_base: str, creds: dict) -> None:
    """Complete the admin login flow (password + captcha + MFA in one page)."""
    page.goto(f"{idp_base}/admin", wait_until="networkidle")

    # If session cookie is valid, we might already be on the panel
    if "Users" in page.content() and "Service Providers" in page.content():
        return

    page.fill("#username", creds["username"])
    page.fill("#password", creds["password"])
    challenge = page.inner_text(".challenge-question")
    page.fill("#challenge_answer", str(solve_challenge(challenge)))
    # Fill TOTP if user has MFA
    if page.locator("#totp_code").count() > 0:
        page.fill("#totp_code", get_totp_code(creds["totp_secret"]))
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle", timeout=10000)
