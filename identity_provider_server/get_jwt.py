"""CLI to authenticate against the identity provider and print the JWT.

Usage:
    get-jwt https://idp.botthouse.net/lint

Prompts for username, password, captcha answer, and (if enabled) an MFA
code, performs the OAuth login flow, and pretty-prints the decoded JWT
payload the way `jq` would format JSON. Pass --raw to print the raw
compact JWT string instead.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import re
import sys
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlparse

import requests

# Fields the IdP embeds as hidden inputs / prompts in the login pages.
_CHALLENGE_QUESTION_RE = re.compile(
    r'challenge-question"[^>]*>(?P<question>[^<]+)<', re.IGNORECASE
)


class _FormParser(HTMLParser):
    """Extract hidden input values and the challenge question from a page."""

    def __init__(self) -> None:
        super().__init__()
        self.hidden: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "input":
            return
        attr = {k: (v or "") for k, v in attrs}
        if attr.get("type") == "hidden" and attr.get("name"):
            self.hidden[attr["name"]] = attr.get("value", "")


def _parse_page(html: str) -> tuple[dict[str, str], str | None]:
    """Return (hidden_fields, challenge_question) parsed from a login page."""
    parser = _FormParser()
    parser.feed(html)
    question = None
    match = _CHALLENGE_QUESTION_RE.search(html)
    if match:
        question = match.group("question").strip()
    return parser.hidden, question


def _decode_jwt_payload(token: str) -> dict:
    """Decode the payload segment of a JWT without verifying the signature."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Not a valid JWT (expected three segments)")
    payload_b64 = parts[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


def _extract_token_from_response(resp: requests.Response) -> str | None:
    """Find a JWT in a redirect Location header, final URL, or history.

    The IdP issues the token via a 302 redirect to the service provider's
    callback URL as ``?token=<jwt>``. We inspect the redirect Location
    header first (so we never have to contact the service provider), then
    fall back to the final URL and any redirect hops.
    """
    candidates: list[str] = []
    location = resp.headers.get("Location", "")
    if location:
        candidates.append(location)
    candidates.append(resp.url)
    for hop in resp.history:
        hop_location = hop.headers.get("Location", "")
        if hop_location:
            candidates.append(hop_location)
    for url in candidates:
        query = parse_qs(urlparse(url).query)
        if "token" in query and query["token"]:
            return query["token"][0]
    return None


def _prompt(label: str, *, secret: bool = False) -> str:
    """Prompt the user for a single line of input."""
    if secret:
        return getpass.getpass(f"{label}: ")
    return input(f"{label}: ")


def fetch_jwt(service_url: str, *, session: requests.Session | None = None) -> str:
    """Run the interactive login flow and return the raw JWT string.

    Args:
        service_url: Full URL of the IdP service login page
            (e.g. https://idp.botthouse.net/lint).
        session: Optional requests session (used for testing).

    Returns:
        The raw compact JWT string.

    Raises:
        RuntimeError: If login fails or no token is returned.
    """
    session = session or requests.Session()

    # Step 1: GET the login page to obtain CSRF token + challenge.
    resp = session.get(service_url, timeout=30)
    resp.raise_for_status()
    hidden, question = _parse_page(resp.text)

    username = _prompt("username")
    password = _prompt("password", secret=True)
    if question:
        print(question, file=sys.stderr)
    captcha = _prompt("capta")

    form = {
        "csrf_token": hidden.get("csrf_token", ""),
        "challenge_hash": hidden.get("challenge_hash", ""),
        "username": username,
        "password": password,
        "challenge_answer": captcha,
    }

    # Step 2: POST credentials. Do NOT follow redirects — the token is in
    # the redirect Location header, and following it would contact the
    # service provider unnecessarily (and could leak the token there).
    resp = session.post(service_url, data=form, timeout=30, allow_redirects=False)

    token = _extract_token_from_response(resp)
    if token:
        return token

    # Step 3: MFA may be required — the response is the TOTP form.
    hidden, _ = _parse_page(resp.text)
    if hidden.get("totp_step") == "1":
        mfa_code = _prompt("mfa")
        form = {
            "csrf_token": hidden.get("csrf_token", ""),
            "totp_step": "1",
            "username": hidden.get("username", username),
            "service_path": hidden.get("service_path", ""),
            "totp_code": mfa_code,
        }
        resp = session.post(service_url, data=form, timeout=30, allow_redirects=False)
        token = _extract_token_from_response(resp)
        if token:
            return token

    raise RuntimeError(
        "Login did not return a token. Check your credentials, captcha, "
        "and MFA code, and confirm the service is an OAuth service provider."
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="get-jwt",
        description="Authenticate with the identity provider and print the JWT.",
    )
    parser.add_argument(
        "url",
        help="IdP service login URL (e.g. https://idp.botthouse.net/lint)",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Print the raw compact JWT string instead of the decoded payload.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the get-jwt console script."""
    args = _build_parser().parse_args(argv)

    try:
        token = fetch_jwt(args.url)
    except (requests.RequestException, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.raw:
        print(token)
        return 0

    try:
        payload = _decode_jwt_payload(token)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
