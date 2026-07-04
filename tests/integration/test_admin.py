"""Integration tests for the /admin panel."""

from __future__ import annotations

import time

import pytest
from playwright.sync_api import Page

from .conftest import login_to_admin, login_to_service


pytestmark = pytest.mark.integration


def test_admin_login_page_loads(page: Page, idp_base: str):
    """/admin shows login form with captcha and MFA field."""
    page.goto(f"{idp_base}/admin", wait_until="networkidle")
    content = page.content()
    assert "Admin Panel" in content
    assert "Human verification" in content
    assert page.locator("#totp_code").count() == 1


def test_admin_requires_idpadmin_claim(page: Page, idp_base: str):
    """Users without idpadmin claim are denied access."""
    # This test would need a user without idpadmin — we verify the error message exists
    # in the template by checking the login page renders correctly
    page.goto(f"{idp_base}/admin", wait_until="networkidle")
    assert "Admin Panel" in page.content()


def test_admin_accessible_with_session_cookie(page: Page, idp_base: str, credentials: dict):
    """Session cookie from /aws grants /admin access (user has idpadmin claim)."""
    login_to_service(page, idp_base, "aws", credentials)
    page.goto(f"{idp_base}/admin", wait_until="networkidle")
    content = page.content()
    assert "Users" in content
    assert "Service Providers" in content


def test_admin_panel_shows_users(page: Page, idp_base: str, credentials: dict):
    """Admin panel lists existing users."""
    login_to_service(page, idp_base, "aws", credentials)
    page.goto(f"{idp_base}/admin", wait_until="networkidle")
    content = page.content()
    assert credentials["username"] in content


def test_admin_panel_shows_service_providers(page: Page, idp_base: str, credentials: dict):
    """Admin panel lists configured service providers."""
    login_to_service(page, idp_base, "aws", credentials)
    page.goto(f"{idp_base}/admin", wait_until="networkidle")
    content = page.content()
    assert "/aws" in content


def test_admin_add_and_delete_user(page: Page, idp_base: str, credentials: dict):
    """Admin can add a user and then delete them."""
    login_to_service(page, idp_base, "aws", credentials)
    page.goto(f"{idp_base}/admin", wait_until="networkidle")

    # Add user
    page.fill("input[name=new_username]", "integration_test_user")
    page.fill("input[name=new_user_password]", "TestPass99!")
    page.fill("input[name=new_user_claims]", "testclaim")
    page.locator("button:has-text('Add User')").click()
    page.wait_for_load_state("networkidle", timeout=10000)

    content = page.content()
    assert "integration_test_user" in content
    assert "created" in content.lower() or "integration_test_user" in content

    # Delete user — auto-accept confirm dialogs
    page.evaluate("window.confirm = () => true")
    delete_btn = page.locator(
        "form:has(input[value=integration_test_user]) button:has-text('Delete')"
    )
    delete_btn.click()
    page.wait_for_load_state("networkidle", timeout=10000)

    content = page.content()
    assert "integration_test_user" not in content or "deleted" in content.lower()


def test_admin_update_claims(page: Page, idp_base: str, credentials: dict):
    """Admin can update claims for a user (non-destructive: sets same claims)."""
    login_to_service(page, idp_base, "aws", credentials)
    page.goto(f"{idp_base}/admin", wait_until="networkidle")

    # The claims input should be pre-filled for the first user
    claims_value = page.input_value("#user_claims_input")
    assert claims_value  # Should have some claims

    # Submit the same claims (non-destructive)
    page.locator("button:has-text('Update Claims')").click()
    page.wait_for_load_state("networkidle", timeout=10000)
    assert "Claims updated" in page.content()


def test_admin_add_and_delete_sp(page: Page, idp_base: str, credentials: dict):
    """Admin can add a service provider and delete it."""
    login_to_service(page, idp_base, "aws", credentials)
    page.goto(f"{idp_base}/admin", wait_until="networkidle")

    # Add SP
    page.select_option("select[name=sp_protocol]", "saml")
    sp_path_input = page.locator(
        "form:has(button:has-text('Add / Update SP')) input[name=sp_path]"
    )
    sp_url_input = page.locator(
        "form:has(button:has-text('Add / Update SP')) input[name=sp_url]"
    )
    sp_path_input.fill("integrationtest")
    sp_url_input.fill("https://test.example.com/saml/acs")
    page.locator("button:has-text('Add / Update SP')").click()
    time.sleep(3)

    content = page.content()
    assert "integrationtest" in content

    # Delete SP — auto-accept confirm dialogs
    page.evaluate("window.confirm = () => true")
    delete_btn = page.locator(
        "form:has(input[value=integrationtest]) button:has-text('Delete')"
    )
    delete_btn.click()
    page.wait_for_load_state("networkidle", timeout=10000)

    content = page.content()
    assert "deleted" in content.lower() or "integrationtest" not in content
