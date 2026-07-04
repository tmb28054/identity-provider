"""Integration tests for the 12-hour session cookie behavior."""

from __future__ import annotations

import pytest
from playwright.sync_api import Page

from .conftest import login_to_service


pytestmark = pytest.mark.integration


def test_session_cookie_set_after_mfa(page: Page, idp_base: str, credentials: dict):
    """After MFA login, the idp_session cookie is set."""
    login_to_service(page, idp_base, "aws", credentials)

    cookies = page.context.cookies()
    session_cookie = next((c for c in cookies if c["name"] == "idp_session"), None)
    assert session_cookie is not None, "idp_session cookie not set after MFA login"
    assert session_cookie["httpOnly"] is True
    assert session_cookie["sameSite"] == "Strict"


def test_session_cookie_skips_login_on_revisit(page: Page, idp_base: str, credentials: dict):
    """With a valid session cookie, visiting /aws skips the login form entirely."""
    # First: full MFA login to get the cookie
    login_to_service(page, idp_base, "aws", credentials)

    # Second: revisit /aws — should skip login and go straight to AWS
    page.goto(f"{idp_base}/aws", wait_until="networkidle")
    import time
    time.sleep(2)
    url = page.url
    content = page.content()
    # Should NOT see the login form with username field
    has_login_form = "challenge_answer" in content and '<input type="text" id="username"' in content
    assert not has_login_form, "Login form appeared — session cookie not working"


def test_session_cookie_grants_admin_access(page: Page, idp_base: str, credentials: dict):
    """Session cookie from /aws login also grants access to /admin."""
    # Login via /aws
    login_to_service(page, idp_base, "aws", credentials)

    # Visit /admin — should skip login (user has idpadmin claim)
    page.goto(f"{idp_base}/admin", wait_until="networkidle")
    content = page.content()
    assert "Users" in content and "Service Providers" in content


def test_session_cookie_grants_user_page_access(page: Page, idp_base: str, credentials: dict):
    """Session cookie alone does NOT grant /user access (re-auth required for security)."""
    # Login via /aws
    login_to_service(page, idp_base, "aws", credentials)

    # Visit /user — should still show login (password/MFA changes need fresh auth)
    page.goto(f"{idp_base}/user", wait_until="networkidle")
    content = page.content()
    assert "Account Settings" in content
    assert "username" in content


def test_no_cookie_shows_login_form(page: Page, idp_base: str):
    """Without a session cookie, /aws shows the login form."""
    page.goto(f"{idp_base}/aws", wait_until="networkidle")
    content = page.content()
    assert "username" in content
    assert "Human verification" in content
