"""Unit tests for verify-attestation.py's signature and claim checks.

Run with:  uv run --with 'PyJWT[crypto]' --with pytest --with requests pytest scripts/
"""

import datetime
import hashlib
import importlib.util
import pathlib

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

spec = importlib.util.spec_from_file_location(
    "verify_attestation", pathlib.Path(__file__).parent / "verify-attestation.py"
)
va = importlib.util.module_from_spec(spec)
spec.loader.exec_module(va)

AUD = "https://tee-example/attestation"
NONCE = "0123456789abcdef"
DIGEST = "sha256:" + "a" * 64


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    public_jwk["kid"] = "test-key"
    return key, {"keys": [public_jwk]}


def make_token(key, **overrides):
    claims = {
        "iss": va.EXPECTED_ISSUER,
        "aud": AUD,
        "eat_nonce": NONCE,
        "submods": {"container": {"image_digest": DIGEST}},
        **overrides,
    }
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test-key"})


def results_by_name(claims):
    return {name: ok for name, ok, _ in va.check_claims(claims, AUD, NONCE, DIGEST)}


def test_valid_token_passes_all_checks(keypair):
    key, jwks = keypair
    claims = va.verify_signature(make_token(key), jwks)
    assert claims is not None
    assert all(results_by_name(claims).values())


def test_tampered_token_fails_signature(keypair):
    key, jwks = keypair
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert va.verify_signature(make_token(other_key), jwks) is None


def test_wrong_image_digest_fails_only_digest_check(keypair):
    key, jwks = keypair
    claims = va.verify_signature(
        make_token(key, submods={"container": {"image_digest": "sha256:" + "b" * 64}}), jwks
    )
    results = results_by_name(claims)
    assert not results["image_digest"]
    assert results["issuer"] and results["audience"] and results["eat_nonce"]


def test_wrong_nonce_fails_nonce_check(keypair):
    key, jwks = keypair
    claims = va.verify_signature(make_token(key, eat_nonce="unexpected-nonce"), jwks)
    assert not results_by_name(claims)["eat_nonce"]


def test_nonce_list_form_is_accepted(keypair):
    key, jwks = keypair
    claims = va.verify_signature(make_token(key, eat_nonce=[NONCE]), jwks)
    assert results_by_name(claims)["eat_nonce"]


def test_nonce_with_key_binding_entries_is_accepted(keypair):
    key, jwks = keypair
    claims = va.verify_signature(
        make_token(key, eat_nonce=[NONCE, "hpke:" + "c" * 64, "tls:" + "d" * 64]), jwks
    )
    assert results_by_name(claims)["eat_nonce"]


def test_key_binding_entries_without_our_nonce_fail(keypair):
    key, jwks = keypair
    claims = va.verify_signature(
        make_token(key, eat_nonce=["hpke:" + "c" * 64, "tls:" + "d" * 64]), jwks
    )
    assert not results_by_name(claims)["eat_nonce"]


def test_wrong_issuer_and_audience_fail(keypair):
    key, jwks = keypair
    claims = va.verify_signature(make_token(key, iss="https://evil", aud="https://other"), jwks)
    results = results_by_name(claims)
    assert not results["issuer"]
    assert not results["audience"]


@pytest.fixture(scope="module")
def served_cert():
    """Self-signed cert shaped like the launcher's ACME cert (EC P-256).

    Returns (certificate DER, sha256 hex of the key's SPKI DER) — the latter
    is exactly what the launcher binds as the tls: eat_nonce (keys.rs).
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc))
        .sign(key, hashes.SHA256())
    )
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return cert.public_bytes(serialization.Encoding.DER), hashlib.sha256(spki).hexdigest()


def test_spki_sha256_hashes_the_subject_public_key_info(served_cert):
    cert_der, expected = served_cert
    assert va.spki_sha256(cert_der) == expected


def test_tls_binding_passes_when_served_key_is_attested(served_cert):
    cert_der, spki_hash = served_cert
    claims = {"eat_nonce": [NONCE, "hpke:" + "c" * 64, f"tls:{spki_hash}"]}
    name, ok, _ = va.check_tls_binding(claims, cert_der)
    assert name == "tls_binding"
    assert ok


def test_tls_binding_fails_on_wrong_entry(served_cert):
    cert_der, _ = served_cert
    _, ok, detail = va.check_tls_binding({"eat_nonce": [NONCE, "tls:" + "d" * 64]}, cert_der)
    assert not ok
    assert "tls:dddd" in detail  # the mismatching bound hash is reported


def test_tls_binding_fails_when_token_binds_no_tls_key(served_cert):
    cert_der, _ = served_cert
    _, ok, _ = va.check_tls_binding({"eat_nonce": NONCE}, cert_der)
    assert not ok


def test_eat_nonces_normalizes_string_list_and_absent():
    assert va.eat_nonces({"eat_nonce": NONCE}) == [NONCE]
    assert va.eat_nonces({"eat_nonce": [NONCE, "tls:" + "d" * 64]}) == [NONCE, "tls:" + "d" * 64]
    assert va.eat_nonces({}) == []
