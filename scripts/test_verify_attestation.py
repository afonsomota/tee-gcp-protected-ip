"""Unit tests for verify-attestation.py's signature and claim checks.

Run with:  uv run --with 'PyJWT[crypto]' --with pytest --with requests pytest scripts/
"""

import importlib.util
import pathlib

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

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
