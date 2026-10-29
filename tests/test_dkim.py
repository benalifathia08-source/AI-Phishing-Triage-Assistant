"""DKIM re-check, fully offline: sign with a throwaway key and serve its public half from a fake DNS."""
import base64

import dkim
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from phishtriage.dkim_check import check_dkim
from tests.helpers import make_eml


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )
    public_der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return private_pem, b"v=DKIM1; k=rsa; p=" + base64.b64encode(public_der)


def _signed(private_pem: bytes) -> bytes:
    message = make_eml(subject="Quarterly report")
    signature = dkim.sign(message, b"sel1", b"example.com", private_pem, include_headers=[b"from", b"to", b"subject"])
    return signature + message


def _dns(record):
    return lambda name, timeout=5: record if name == b"sel1._domainkey.example.com." else None


def test_valid_signature_passes(keypair):
    private_pem, record = keypair
    [check] = check_dkim(_signed(private_pem), dnsfunc=_dns(record))
    assert (check.domain, check.selector, check.status) == ("example.com", "sel1", "pass")


def test_changed_body_fails(keypair):
    private_pem, record = keypair
    tampered = _signed(private_pem).replace(b"This is a test message.", b"Please pay invoice 42.")
    [check] = check_dkim(tampered, dnsfunc=_dns(record))
    assert check.status == "fail"
    assert "body" in check.reason


def test_changed_signed_header_fails(keypair):
    private_pem, record = keypair
    tampered = _signed(private_pem).replace(b"Subject: Quarterly report", b"Subject: Urgent wire transfer")
    [check] = check_dkim(tampered, dnsfunc=_dns(record))
    assert check.status == "fail"
    assert "headers" in check.reason


def test_removed_key_is_unverifiable_not_forged(keypair):
    private_pem, _ = keypair
    [check] = check_dkim(_signed(private_pem), dnsfunc=_dns(None))
    assert check.status == "unverifiable"
    assert "no longer published" in check.reason


def test_unsigned_email_has_no_checks():
    assert check_dkim(make_eml()) == []
