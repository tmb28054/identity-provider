"""Integration tests for the login flow: password + captcha + MFA → AWS Console."""

from __future__ import annotations

import pytest
from playwright.sync_api import Page

from .conftest import login_to_service, solve_challenge, get_totp_code


pytestmark = pytest.mark.integration


def test_aws_login_page_loads(page: Page, idp_base: str):
    """GET /aws returns a login form with username, password, and captcha."""
    page.goto(f"{idp_base}/aws", wait_until="networkidle")
    assert page.locator("#username").count() == 1
    assert page.locator("#password").count() == 1
    assert "Human verification" in page.content()


def test_wrong_captcha_rejected(page: Page, idp_base: str, credentials: dict):
    """Submitting a wrong captcha answer returns 401."""
    page.goto(f"{idp_base}/aws", wait_until="networkidle")
    page.fill("#username", credentials["username"])
    page.fill("#password", credentials["password"])
    page.fill("#challenge_answer", "99999")  # wrong
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle", timeout=10000)
    assert "Incorrect answer" in page.content()


def test_wrong_password_rejected(page: Page, idp_base: str, credentials: dict):
    """Submitting wrong password returns 401 with error message."""
    page.goto(f"{idp_base}/aws", wait_until="networkidle")
    page.fill("#username", credentials["username"])
    page.fill("#password", "wrongpassword")
    challenge = page.inner_text(".challenge-question")
    page.fill("#challenge_answer", str(solve_challenge(challenge)))
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle", timeout=10000)
    assert "Invalid credentials" in page.content()


def test_mfa_prompt_after_password(page: Page, idp_base: str, credentials: dict):
    """After correct password + captcha, user with MFA sees TOTP prompt."""
    page.goto(f"{idp_base}/aws", wait_until="networkidle")
    page.fill("#username", credentials["username"])
    page.fill("#password", credentials["password"])
    challenge = page.inner_text(".challenge-question")
    page.fill("#challenge_answer", str(solve_challenge(challenge)))
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle", timeout=10000)
    content = page.content()
    assert "Two-Factor Authentication" in content
    assert page.locator("#totp_code").count() == 1


def test_wrong_totp_rejected(page: Page, idp_base: str, credentials: dict):
    """Submitting wrong TOTP code returns 401."""
    page.goto(f"{idp_base}/aws", wait_until="networkidle")
    page.fill("#username", credentials["username"])
    page.fill("#password", credentials["password"])
    challenge = page.inner_text(".challenge-question")
    page.fill("#challenge_answer", str(solve_challenge(challenge)))
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle", timeout=10000)

    # Submit wrong TOTP
    page.fill("#totp_code", "000000")
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle", timeout=10000)
    assert "Invalid code" in page.content()


def test_full_mfa_login_reaches_aws(page: Page, idp_base: str, credentials: dict):
    """Full login flow (password + captcha + TOTP) redirects to AWS Console."""
    login_to_service(page, idp_base, "aws", credentials)
    # Should end up at AWS Console, AWS signin, or have SAML in the page
    url = page.url
    content = page.content()
    assert (
        "console.aws.amazon.com" in url
        or "signin.aws.amazon.com" in url
        or "SAMLResponse" in content
    )


def test_health_endpoint(page: Page, idp_base: str):
    """GET /health returns healthy status."""
    page.goto(f"{idp_base}/health", wait_until="networkidle")
    assert '"healthy"' in page.content()


def test_metadata_endpoint(page: Page, idp_base: str):
    """GET /metadata returns SAML XML with EntityDescriptor."""
    page.goto(f"{idp_base}/metadata", wait_until="networkidle")
    content = page.content()
    assert "EntityDescriptor" in content
    assert "X509Certificate" in content
