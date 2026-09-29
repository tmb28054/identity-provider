"""End-to-end passkey (WebAuthn) integration test.

Self-contained: launches a local IdP subprocess with passkeys enabled and drives
a real browser through the register -> authenticate ceremonies using Chrome
DevTools Protocol's virtual authenticator (``WebAuthn.addVirtualAuthenticator``).

Served over ``http://localhost`` — a WebAuthn "secure context" exception, so no
TLS is needed and ``rp_id=localhost`` validates. Network-gated like the other
integration tests (skips cleanly if the browser or a free port is unavailable).
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import bcrypt
import pytest

pytestmark = pytest.mark.integration

DATA_SRC = Path(__file__).parent.parent.parent / "data"
TEST_USER = "e2euser"
TEST_PASSWORD = "E2e-Passw0rd-Test!"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_server(url: str, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)  # noqa: S310 - localhost only
            return
        except urllib.error.HTTPError:
            return  # up, non-200 is fine
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"Server at {url} did not start within {timeout}s")


@pytest.fixture(scope="module")
def passkey_server(tmp_path_factory):
    """Launch a local IdP with passkeys enabled on http://localhost:<port>."""
    data_dir = tmp_path_factory.mktemp("idp_data")
    for name in ("idp.crt", "idp.key"):
        shutil.copy(DATA_SRC / name, data_dir / name)
    # A single local user with a known password and no MFA.
    pw_hash = bcrypt.hashpw(TEST_PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode()
    (data_dir / "users.json").write_text(json.dumps([
        {
            "username": TEST_USER,
            "password": pw_hash,
            "roles": [{"account_id": "111111111111", "role": "e2erole"}],
            "claims": [],
        }
    ]))

    port = _free_port()
    base = f"http://localhost:{port}"
    # Launch via an inline runner so we can pass secure_cookies=False — the
    # browser will not send Secure cookies over plain http://localhost, which
    # would break the CSRF double-submit. localhost is still a WebAuthn secure
    # context, so passkeys work without TLS.
    runner = (
        "from identity_provider_server.app import create_app; "
        f"create_app({str(data_dir)!r}, host='127.0.0.1', port={port}, "
        "secret_key='e2e-passkey-secret', secure_cookies=False, "
        "trust_proxy=False, webauthn_enabled=True, webauthn_rp_id='localhost', "
        f"webauthn_expected_origin={base!r})"
        f".run(host='127.0.0.1', port={port})"
    )
    proc = subprocess.Popen(  # noqa: S603 - fixed args, local test
        [sys.executable, "-c", runner],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for_server(f"http://127.0.0.1:{port}/health")
        yield {"base": base, "data_dir": data_dir}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover - cleanup best effort
            proc.kill()


def _enable_virtual_authenticator(page):
    """Attach a CDP virtual authenticator so navigator.credentials works."""
    client = page.context.new_cdp_session(page)
    client.send("WebAuthn.enable")
    result = client.send("WebAuthn.addVirtualAuthenticator", {
        "options": {
            "protocol": "ctap2",
            "transport": "internal",
            "hasResidentKey": True,
            "hasUserVerification": True,
            "isUserVerified": True,
            "automaticPresenceSimulation": True,
        }
    })
    return client, result["authenticatorId"]


def test_passkey_register_then_authenticate(passkey_server):
    """Register a passkey on /user, then log in with it on /aws."""
    playwright_api = pytest.importorskip("playwright.sync_api")
    base = passkey_server["base"]

    with playwright_api.sync_playwright() as pw:
        try:
            browser = pw.chromium.launch()
        except Exception as exc:  # pragma: no cover - env without browser
            pytest.skip(f"Chromium not available: {exc}")
        context = browser.new_context()
        page = context.new_page()
        _enable_virtual_authenticator(page)

        # --- sign in to /user (no MFA) ---
        page.goto(f"{base}/user", wait_until="networkidle")
        page.fill("#username", TEST_USER)
        page.fill("#password", TEST_PASSWORD)
        # Solve the captcha (no MFA on this account).
        import re
        q = re.search(r"What is (\d+)\s*([+\-\u00d7])\s*(\d+)",
                      page.inner_text(".challenge-question"))
        a, op, b = int(q.group(1)), q.group(2), int(q.group(3))
        ans = a + b if op == "+" else (a - b if op == "-" else a * b)
        page.fill("#challenge_answer", str(ans))
        page.click("button[type=submit]")
        page.wait_for_load_state("networkidle")
        assert page.locator("#passkey-register").count() == 1

        # --- register a passkey (CDP authenticator answers the prompt) ---
        page.click("#passkey-register")
        # On success the list gains a Remove button and the status shows success
        # (no page reload — the enroll page is POST-reached).
        page.wait_for_selector("#passkey-list li", timeout=10000)
        page.wait_for_selector("text=Passkey registered.", timeout=10000)

        # Confirm the credential was persisted server-side.
        users = json.loads((passkey_server["data_dir"] / "users.json").read_text())
        user = next(u for u in users if u["username"] == TEST_USER)
        assert len(user.get("webauthn_credentials", [])) == 1

        # --- authenticate with the passkey on /aws ---
        page.goto(f"{base}/aws", wait_until="networkidle")
        page.fill("#username", TEST_USER)
        page.click("#passkey-login")
        # On success the client auto-POSTs the SAML form to AWS (cross-origin).
        for _ in range(20):
            if any(c["name"] == "idp_session" for c in context.cookies()):
                break
            time.sleep(0.5)
        assert any(c["name"] == "idp_session" for c in context.cookies())

        context.close()
        browser.close()
