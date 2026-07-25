"""Integration tests for claims management: registry + user detail page."""

from __future__ import annotations

import pytest
from playwright.sync_api import Page

from .conftest import login_to_service


pytestmark = pytest.mark.integration


def test_claims_registry_visible(page: Page, idp_base: str, credentials: dict):
    """Admin panel shows the Claims Registry section with existing claims."""
    login_to_service(page, idp_base, "aws", credentials)
    page.goto(f"{idp_base}/admin", wait_until="networkidle")
    content = page.content()
    assert "Claims Registry" in content
    assert "idpadmin" in content


def test_add_claim_to_registry(page: Page, idp_base: str, credentials: dict):
    """Admin can add a new claim to the registry."""
    login_to_service(page, idp_base, "aws", credentials)
    page.goto(f"{idp_base}/admin", wait_until="networkidle")

    page.locator("form:has(button:has-text('Add Claim')) input[name=claim_name]").fill("test-integration-claim")
    page.locator("button:has-text('Add Claim')").click()
    page.wait_for_load_state("networkidle", timeout=10000)

    content = page.content()
    assert "test-integration-claim" in content
    assert "added" in content.lower() or "already exists" in content.lower()


def test_user_detail_page_accessible(page: Page, idp_base: str, credentials: dict):
    """User detail page is accessible and shows claims."""
    login_to_service(page, idp_base, "aws", credentials)
    page.goto(f"{idp_base}/admin/user/{credentials['username']}", wait_until="networkidle")

    content = page.content()
    assert credentials["username"] in content
    assert "User Claims" in content
    assert "Add claim" in content


def test_user_detail_shows_current_claims(page: Page, idp_base: str, credentials: dict):
    """User detail page shows the user's current claims."""
    login_to_service(page, idp_base, "aws", credentials)
    page.goto(f"{idp_base}/admin/user/{credentials['username']}", wait_until="networkidle")

    content = page.content()
    assert "idpadmin" in content
    assert "awsadmin" in content


def test_user_detail_has_add_claim_dropdown(page: Page, idp_base: str, credentials: dict):
    """User detail page has a dropdown to add claims."""
    login_to_service(page, idp_base, "aws", credentials)
    page.goto(f"{idp_base}/admin/user/{credentials['username']}", wait_until="networkidle")

    select = page.locator("select[name=claim_name]")
    assert select.count() == 1
    # Should have at least one option (available claims not yet assigned)
    options = select.locator("option").all_text_contents()
    assert len(options) >= 1


def test_user_detail_back_link(page: Page, idp_base: str, credentials: dict):
    """User detail page has a back link to the admin panel."""
    login_to_service(page, idp_base, "aws", credentials)
    page.goto(f"{idp_base}/admin/user/{credentials['username']}", wait_until="networkidle")

    back_link = page.locator("a.back-link")
    assert back_link.count() == 1
    back_link.click()
    page.wait_for_load_state("networkidle", timeout=10000)
    assert "Admin Panel" in page.content()


def test_user_detail_shows_info(page: Page, idp_base: str, credentials: dict):
    """User detail page shows user info (email, MFA status)."""
    login_to_service(page, idp_base, "aws", credentials)
    page.goto(f"{idp_base}/admin/user/{credentials['username']}", wait_until="networkidle")

    content = page.content()
    assert "Details" in content
    assert "Email:" in content
    assert "MFA:" in content
    assert "Enabled" in content


def test_username_links_in_admin_panel(page: Page, idp_base: str, credentials: dict):
    """Usernames in the admin panel are clickable links to user detail pages."""
    login_to_service(page, idp_base, "aws", credentials)
    page.goto(f"{idp_base}/admin", wait_until="networkidle")

    user_link = page.locator(f"a[href='/admin/user/{credentials['username']}']")
    assert user_link.count() >= 1
