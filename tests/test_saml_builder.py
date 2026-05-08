import base64
from pathlib import Path

import pytest
from lxml import etree

from identity_provider_server.saml_builder import ACS_URL, SP_ENTITY_ID, build_saml_response

DATA = Path(__file__).parent.parent / "data"
CERT = (DATA / "idp.crt").read_text()
KEY = (DATA / "idp.key").read_text()
IDP = "http://localhost:5000/metadata"

ROLES = [
    {"account_id": "111122223333", "role": "RoleA"},
    {"account_id": "444455556666", "role": "RoleB"},
]

SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
NS = {"saml": SAML_NS, "samlp": SAMLP_NS, "ds": DS_NS}


@pytest.fixture(scope="module")
def response_xml():
    b64 = build_saml_response("alice", ROLES, CERT, KEY, IDP)
    return etree.fromstring(base64.b64decode(b64))


def _attrs(root):
    return {
        a.attrib["Name"]: [v.text for v in a.findall(f"{{{SAML_NS}}}AttributeValue")]
        for a in root.findall(f".//{{{SAML_NS}}}Attribute")
    }


# --- Response wrapper ---

def test_response_tag(response_xml):
    assert response_xml.tag == f"{{{SAMLP_NS}}}Response"


def test_response_version(response_xml):
    assert response_xml.attrib["Version"] == "2.0"


def test_response_destination(response_xml):
    assert response_xml.attrib["Destination"] == ACS_URL


def test_response_status_success(response_xml):
    code = response_xml.find(f".//{{{SAMLP_NS}}}StatusCode")
    assert code.attrib["Value"] == "urn:oasis:names:tc:SAML:2.0:status:Success"


def test_response_issuer(response_xml):
    assert response_xml.find(f"{{{SAML_NS}}}Issuer").text == IDP


# --- Assertion ---

def test_assertion_present(response_xml):
    assert response_xml.find(f".//{{{SAML_NS}}}Assertion") is not None


def test_nameid_value(response_xml):
    assert response_xml.find(f".//{{{SAML_NS}}}NameID").text == "alice"


def test_nameid_format(response_xml):
    assert "persistent" in response_xml.find(f".//{{{SAML_NS}}}NameID").attrib["Format"]


def test_subject_confirmation_recipient(response_xml):
    data = response_xml.find(f".//{{{SAML_NS}}}SubjectConfirmationData")
    assert data.attrib["Recipient"] == ACS_URL


def test_audience(response_xml):
    assert response_xml.find(f".//{{{SAML_NS}}}Audience").text == SP_ENTITY_ID


def test_authn_context(response_xml):
    ref = response_xml.find(f".//{{{SAML_NS}}}AuthnContextClassRef")
    assert "PasswordProtectedTransport" in ref.text


# --- Attributes ---

def test_role_session_name(response_xml):
    attrs = _attrs(response_xml)
    assert attrs["https://aws.amazon.com/SAML/Attributes/RoleSessionName"] == ["alice"]


def test_role_count(response_xml):
    assert len(_attrs(response_xml)["https://aws.amazon.com/SAML/Attributes/Role"]) == 2


def test_role_arn_format(response_xml):
    for value in _attrs(response_xml)["https://aws.amazon.com/SAML/Attributes/Role"]:
        role_arn, provider_arn = value.split(",")
        assert ":role/" in role_arn
        assert ":saml-provider/local-idp" in provider_arn


def test_role_arns_contain_correct_accounts(response_xml):
    roles = _attrs(response_xml)["https://aws.amazon.com/SAML/Attributes/Role"]
    accounts = {v.split(":")[4] for v in roles}
    assert accounts == {"111122223333", "444455556666"}


# --- Custom provider name ---

def test_custom_provider_name():
    b64 = build_saml_response("alice", ROLES, CERT, KEY, IDP, provider_name="my-custom-idp")
    xml = etree.fromstring(base64.b64decode(b64))
    roles = _attrs(xml)["https://aws.amazon.com/SAML/Attributes/Role"]
    for value in roles:
        assert ":saml-provider/my-custom-idp" in value


# --- Custom session duration ---

def test_custom_session_duration():
    b64 = build_saml_response("alice", ROLES, CERT, KEY, IDP, session_duration_hours=4)
    xml = etree.fromstring(base64.b64decode(b64))
    # Just verify it builds successfully — the time math is internal
    assert xml.find(f".//{{{SAML_NS}}}Assertion") is not None


# --- Signature ---

def test_signature_present(response_xml):
    assert response_xml.find(f".//{{{DS_NS}}}Signature") is not None


def test_signature_value_non_empty(response_xml):
    sig_value = response_xml.find(f".//{{{DS_NS}}}SignatureValue")
    assert sig_value is not None and sig_value.text


def test_certificate_embedded(response_xml):
    cert = response_xml.find(f".//{{{DS_NS}}}X509Certificate")
    assert cert is not None and len(cert.text) > 100


# --- Output encoding ---

def test_output_is_valid_base64():
    b64 = build_saml_response("alice", ROLES, CERT, KEY, IDP)
    assert base64.b64decode(b64).startswith(b"<?xml")


# --- No InResponseTo (removed dummy value) ---

def test_no_in_response_to(response_xml):
    assert "InResponseTo" not in response_xml.attrib
