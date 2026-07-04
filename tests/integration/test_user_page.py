"""Integration tests for the /user page: MFA enrollment, password change."""

from __future__ import annotations

import re

import pyotp
import pytest
from playwright.sync_api import Page

from .conftest import get_totp_code, login_to_service, solve_challenge


pytestmark = pytest.mark.integration


def test_user_page_shows_login(page: Page, idp_base: str):
    """/user shows a login form with captcha."""
    page.goto(f"{idp_base}/user", wait_until="networkidle")
    content = page.content()
    assert "Account Settings" in content
    assert "Human verification" in content
    assert page.locator("#username").count() == 1


def test_user_page_requires_mfa(page: Page, idp_base: str, credentials: dict):
    """/user login requires TOTP when MFA is enrolled."""
    page.goto(f"{idp_base}/user", wait_until="networkidle")
    page.fill("#username", credentials["username"])
    page.fill("#password", credentials["password"])
    challenge = page.inner_text(".challenge-question")
    page.fill("#challenge_answer", str(solve_challenge(challenge)))
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle", timeout=10000)

    content = page.content()
    assert "Two-Factor Authentication" in content or "totp_code" in content


def test_user_page_accessible_with_session(page: Page, idp_base: str, credentials: dict):
    """Even with session cookie, /user requires login (security-sensitive page)."""
    # Get session cookie via /aws login
    login_to_service(page, idp_base, "aws", credentials)
    # Visit /user — still shows login (password changes require re-auth)
    page.goto(f"{idp_base}/user", wait_until="networkidle")
    content = page.content()
    # /user always requires authentication — session cookie doesn't skip it
    assert "Account Settings" in content
    assert "username" in content


def test_password_change_validation(page: Page, idp_base: str, credentials: dict):
    """Password change rejects mismatched passwords."""
    # Login to /user directly
    page.goto(f"{idp_base}/user", wait_until="networkidle")
    page.fill("#username", credentials["username"])
    page.fill("#password", credentials["password"])
    challenge = page.inner_text(".challenge-question")
    page.fill("#challenge_answer", str(solve_challenge(challenge)))
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle", timeout=10000)
    # Handle TOTP
    content = page.content()
    if "totp_code" in content:
        page.fill("#totp_code", get_totp_code(credentials["totp_secret"]))
        page.click("button[type=submit]")
        page.wait_for_load_state("networkidle", timeout=10000)

    # Submit mismatched passwords
    page.fill("#new_password", "newpass123")
    page.fill("#confirm_password", "different456")
    page.locator("button:has-text('Change Password')").click()
    page.wait_for_load_state("networkidle", timeout=10000)
    assert "do not match" in page.content()


def test_password_change_too_short(page: Page, idp_base: str, credentials: dict):
    """Password change rejects passwords shorter than 8 characters."""
    page.goto(f"{idp_base}/user", wait_until="networkidle")
    page.fill("#username", credentials["username"])
    page.fill("#password", credentials["password"])
    challenge = page.inner_text(".challenge-question")
    page.fill("#challenge_answer", str(solve_challenge(challenge)))
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle", timeout=10000)
    content = page.content()
    if "totp_code" in content:
        page.fill("#totp_code", get_totp_code(credentials["totp_secret"]))
        page.click("button[type=submit]")
        page.wait_for_load_state("networkidle", timeout=10000)

    # Remove browser-side minlength validation to test server-side check
    page.evaluate("document.getElementById('new_password').removeAttribute('minlength')")
    page.evaluate("document.getElementById('confirm_password').removeAttribute('minlength')")
    page.fill("#new_password", "short")
    page.fill("#confirm_password", "short")
    page.locator("button:has-text('Change Password')").click()
    page.wait_for_load_state("networkidle", timeout=10000)
    assert "at least 8" in page.content()


def test_password_change_success(page: Page, idp_base: str, credentials: dict):
    """Password change succeeds and user can still log in."""
    page.goto(f"{idp_base}/user", wait_until="networkidle")
    page.fill("#username", credentials["username"])
    page.fill("#password", credentials["password"])
    challenge = page.inner_text(".challenge-question")
    page.fill("#challenge_answer", str(solve_challenge(challenge)))
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle", timeout=10000)
    content = page.content()
    if "totp_code" in content:
        page.fill("#totp_code", get_totp_code(credentials["totp_secret"]))
        page.click("button[type=submit]")
        page.wait_for_load_state("networkidle", timeout=10000)

    # Change password to the same password (non-destructive test)
    page.fill("#new_password", credentials["password"])
    page.fill("#confirm_password", credentials["password"])
    page.locator("button:has-text('Change Password')").click()
    page.wait_for_load_state("networkidle", timeout=10000)
    assert "Password changed successfully" in page.content()
