"""Unit tests for verify-chain.py's pure logic (claims, digest, release match).

Run with:  uv run --with 'PyJWT[crypto]' --with pytest --with requests pytest scripts/
"""

import importlib.util
import pathlib

spec = importlib.util.spec_from_file_location(
    "verify_chain", pathlib.Path(__file__).parent / "verify-chain.py"
)
vc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vc)

AUD = "https://tee-example/attestation"
NONCE = "0123456789abcdef"
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


def make_claims(**overrides):
    return {
        "iss": vc.va.EXPECTED_ISSUER,
        "aud": AUD,
        "eat_nonce": [NONCE, "hpke:" + "c" * 64, "tls:" + "d" * 64],
        "submods": {"container": {"image_digest": DIGEST}},
        **overrides,
    }


def results_by_name(claims):
    return {name: ok for name, ok, _ in vc.check_claims(claims, AUD, NONCE)}


# ---- claim checks ------------------------------------------------------------

def test_google_issued_claims_pass():
    assert all(results_by_name(make_claims()).values())

def test_dev_issuer_passes_issuer_check():
    # --insecure-dev gates *acceptance*; the issuer check itself recognizes
    # the dev issuer so the failure surfaces at the signature step, not here.
    assert results_by_name(make_claims(iss=vc.DEV_ISSUER))["issuer"]

def test_unknown_issuer_fails():
    assert not results_by_name(make_claims(iss="https://evil"))["issuer"]

def test_wrong_audience_fails():
    assert not results_by_name(make_claims(aud="https://other"))["audience"]

def test_missing_nonce_fails():
    results = results_by_name(make_claims(eat_nonce=["hpke:" + "c" * 64]))
    assert not results["eat_nonce"]

def test_string_form_nonce_accepted():
    assert results_by_name(make_claims(eat_nonce=NONCE))["eat_nonce"]


# ---- digest extraction ---------------------------------------------------------

def test_extract_digest():
    assert vc.extract_digest(make_claims()) == DIGEST

def test_extract_digest_absent():
    assert vc.extract_digest({}) is None

def test_extract_digest_malformed():
    claims = make_claims(submods={"container": {"image_digest": "sha256:nothex"}})
    assert vc.extract_digest(claims) is None


# ---- release matching ----------------------------------------------------------

def release(tag, assets=(), body=""):
    return {"tag_name": tag, "assets": list(assets), "body": body}

def asset(url="https://example/image-digest.txt", name="image-digest.txt"):
    return {"name": name, "browser_download_url": url}


def test_match_by_digest_asset():
    releases = [release("v0.2.0", [asset("https://x/2")]),
                release("v0.1.0", [asset("https://x/1")])]
    texts = {"https://x/2": OTHER_DIGEST + "\n", "https://x/1": DIGEST + "\n"}
    assert vc.match_release(releases, DIGEST, texts.__getitem__) == "v0.1.0"


def test_asset_is_authoritative_over_body():
    # A digest in the notes of a release whose asset disagrees must not match.
    releases = [release("v0.1.0", [asset()], body=DIGEST)]
    assert vc.match_release(releases, DIGEST, lambda url: OTHER_DIGEST) is None


def test_match_by_body_when_no_asset():
    releases = [release("v0.1.0", body=f"digest D: `{DIGEST}`")]
    assert vc.match_release(releases, DIGEST, lambda url: "") == "v0.1.0"


def test_no_match_returns_none():
    releases = [release("v0.1.0", [asset()], body=OTHER_DIGEST)]
    assert vc.match_release(releases, DIGEST, lambda url: OTHER_DIGEST) is None


def test_no_releases_returns_none():
    assert vc.match_release([], DIGEST, lambda url: "") is None
