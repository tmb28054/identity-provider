from __future__ import annotations

import base64
import uuid
from datetime import datetime, timedelta, timezone

from lxml import etree
from signxml import XMLSigner

NSMAP = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}

SP_ENTITY_ID = "urn:amazon:webservices"
ACS_URL = "https://signin.aws.amazon.com/saml"


def _sub(
    parent: etree._Element,
    tag: str,
    ns: str,
    attribs: dict[str, str] | None = None,
    text: str | None = None,
) -> etree._Element:
    e = etree.SubElement(parent, f"{{{NSMAP[ns]}}}{tag}", attribs or {})
    if text is not None:
        e.text = text
    return e


def build_saml_response(
    username: str,
    roles: list[dict[str, str]],
    cert_pem: str,
    key_pem: str,
    idp_entity_id: str,
    *,
    provider_name: str = "local-idp",
    session_duration_hours: int = 1,
) -> str:
    """Build a signed SAML 2.0 Response for AWS federation.

    Args:
        username: Authenticated user's name (becomes NameID and RoleSessionName).
        roles: List of dicts with 'account_id' and 'role' keys.
        cert_pem: PEM-encoded signing certificate.
        key_pem: PEM-encoded private key.
        idp_entity_id: IdP entity ID (e.g. http://host:port/metadata).
        provider_name: SAML provider name registered in AWS IAM.
        session_duration_hours: Assertion validity in hours (1–12).

    Returns:
        Base64-encoded SAML Response XML.
    """
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(hours=session_duration_hours)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    assertion_id = "_" + uuid.uuid4().hex

    assertion = etree.Element(f"{{{NSMAP['saml']}}}Assertion", nsmap=NSMAP)
    assertion.attrib.update({
        "ID": assertion_id,
        "Version": "2.0",
        "IssueInstant": now.strftime(fmt),
    })
    _sub(assertion, "Issuer", "saml", text=idp_entity_id)

    subject = _sub(assertion, "Subject", "saml")
    _sub(
        subject,
        "NameID",
        "saml",
        {"Format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"},
        username,
    )
    sc = _sub(
        subject,
        "SubjectConfirmation",
        "saml",
        {"Method": "urn:oasis:names:tc:SAML:2.0:cm:bearer"},
    )
    _sub(
        sc,
        "SubjectConfirmationData",
        "saml",
        {"NotOnOrAfter": not_after.strftime(fmt), "Recipient": ACS_URL},
    )

    conditions = _sub(
        assertion,
        "Conditions",
        "saml",
        {"NotBefore": now.strftime(fmt), "NotOnOrAfter": not_after.strftime(fmt)},
    )
    _sub(
        _sub(conditions, "AudienceRestriction", "saml"),
        "Audience",
        "saml",
        text=SP_ENTITY_ID,
    )

    authn = _sub(
        assertion, "AuthnStatement", "saml", {"AuthnInstant": now.strftime(fmt)}
    )
    _sub(
        _sub(authn, "AuthnContext", "saml"),
        "AuthnContextClassRef",
        "saml",
        text="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    )

    attr_stmt = _sub(assertion, "AttributeStatement", "saml")

    def _attr(name: str, values: list[str]) -> None:
        a = _sub(
            attr_stmt,
            "Attribute",
            "saml",
            {
                "Name": name,
                "NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            },
        )
        for v in values:
            _sub(a, "AttributeValue", "saml", text=v)

    _attr(
        "https://aws.amazon.com/SAML/Attributes/Role",
        [
            f"arn:aws:iam::{r['account_id']}:role/{r['role']},"
            f"arn:aws:iam::{r['account_id']}:saml-provider/{provider_name}"
            for r in roles
        ],
    )
    _attr("https://aws.amazon.com/SAML/Attributes/RoleSessionName", [username])

    signed_assertion = XMLSigner(
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    ).sign(assertion, key=key_pem, cert=cert_pem, reference_uri=assertion_id)

    response = etree.Element(f"{{{NSMAP['samlp']}}}Response", nsmap=NSMAP)
    response.attrib.update({
        "ID": "_" + uuid.uuid4().hex,
        "Version": "2.0",
        "IssueInstant": now.strftime(fmt),
        "Destination": ACS_URL,
    })
    _sub(response, "Issuer", "saml", text=idp_entity_id)
    _sub(
        _sub(response, "Status", "samlp"),
        "StatusCode",
        "samlp",
        {"Value": "urn:oasis:names:tc:SAML:2.0:status:Success"},
    )
    response.append(signed_assertion)

    return base64.b64encode(
        etree.tostring(response, xml_declaration=True, encoding="UTF-8")
    ).decode()
