#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "PyJWT[crypto]>=2.8",
#   "cryptography>=42",
#   "requests>=2.31",
# ]
# ///
"""Verify a Confidential Space attestation token served by the launcher.

Fetches a token from the launcher's /attestation endpoint with a fresh random
nonce, validates Google's signature against the Confidential Space JWKS, and
checks issuer, audience, nonce, and the workload container image digest.
For https:// URLs it also checks the TLS key binding (issue 004): the served
certificate's public-key hash must equal the token's `tls:` eat_nonce entry,
proving the key terminating TLS lives inside the attested enclave.

Usage:
  ./verify-attestation.py --url http://EXTERNAL_IP:8080 \
      --image-digest sha256:abc... [--audience https://tee-example/attestation]
  ./verify-attestation.py --url https://api.YOUR_DOMAIN --image-digest sha256:abc...
"""

import argparse
import hashlib
import json
import secrets
import socket
import ssl
import sys
import time
from urllib.parse import urlparse

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

WELL_KNOWN_URL = (
    "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration"
)
EXPECTED_ISSUER = "https://confidentialcomputing.googleapis.com"
DEFAULT_AUDIENCE = "https://tee-example/attestation"

# On renewal the launcher rebinds `tls:` one scheduler tick before the new
# cert starts serving (launcher/src/acme_cache.rs); a token minted inside
# that window hashes the outgoing key. One retry with a fresh token is
# enough to ride it out.
TLS_REBIND_RETRIES = 1


def fetch_token(base_url: str, nonce: str) -> str:
    resp = requests.get(f"{base_url.rstrip('/')}/attestation", params={"nonce": nonce}, timeout=30)
    body = resp.json()
    if resp.status_code != 200:
        raise SystemExit(f"launcher returned {resp.status_code}: {body.get('error', body)}")
    return body["token"]


def verify_signature(token: str, jwks: dict) -> dict | None:
    """Return the decoded claims if the signature is valid, else None.

    Signature only — claim checks are done explicitly in check_claims so each
    one gets its own PASS/FAIL line.
    """
    try:
        header = jwt.get_unverified_header(token)
        key = next(k for k in jwks["keys"] if k.get("kid") == header.get("kid"))
        signing_key = jwt.PyJWK.from_dict(key).key
        return jwt.decode(
            token,
            key=signing_key,
            algorithms=["RS256"],  # pinned: never trust the token's own header
            options={"verify_aud": False},  # audience checked in check_claims
        )
    except (StopIteration, jwt.PyJWTError, KeyError):
        return None


def eat_nonces(claims: dict) -> list:
    """eat_nonce as a list (a single nonce may be flattened to a string)."""
    nonces = claims.get("eat_nonce")
    if nonces is None:
        return []
    return [nonces] if isinstance(nonces, str) else nonces


def check_claims(
    claims: dict, expected_audience: str, expected_nonce: str, expected_digest: str
) -> list[tuple[str, bool, str]]:
    """Pure claim checks; returns (check name, passed, detail) tuples."""
    image_digest = (
        claims.get("submods", {}).get("container", {}).get("image_digest")
    )
    # The launcher also binds enclave keys into eat_nonce as "hpke:..." /
    # "tls:..." entries (issue 003); freshness only needs our nonce present.
    nonces = eat_nonces(claims)
    return [
        ("issuer", claims.get("iss") == EXPECTED_ISSUER,
         f"iss={claims.get('iss')!r}"),
        ("audience", claims.get("aud") == expected_audience,
         f"aud={claims.get('aud')!r}"),
        ("eat_nonce", expected_nonce in nonces,
         f"eat_nonce={claims.get('eat_nonce')!r}"),
        ("image_digest", image_digest == expected_digest,
         f"submods.container.image_digest={image_digest!r}"),
    ]


def fetch_served_cert(url: str) -> bytes:
    """DER certificate presented on a fresh TLS handshake with the launcher.

    WebPKI validity is deliberately not checked (staging certs chain to
    untrusted test roots): trust comes from the attested `tls:` binding,
    which check_tls_binding compares against this certificate's key.
    """
    parsed = urlparse(url)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=30) as raw:
        with context.wrap_socket(raw, server_hostname=parsed.hostname) as tls:
            return tls.getpeercert(binary_form=True)


def spki_sha256(cert_der: bytes) -> str:
    """SHA-256 hex of the certificate's SubjectPublicKeyInfo DER — the
    `tls:` nonce preimage the launcher binds (launcher/src/keys.rs)."""
    public_key = x509.load_der_x509_certificate(cert_der).public_key()
    spki = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(spki).hexdigest()


def check_tls_binding(claims: dict, cert_der: bytes) -> tuple[str, bool, str]:
    """The key serving TLS must be the one the attestation token binds."""
    served = f"tls:{spki_sha256(cert_der)}"
    bound = [n for n in eat_nonces(claims) if isinstance(n, str) and n.startswith("tls:")]
    ok = served in bound
    return ("tls_binding", ok,
            f"served cert key hashes to {served}" if ok
            else f"served cert key hashes to {served}, token binds {bound!r}")


def verify_once(url: str, audience: str, expected_digest: str, jwks: dict):
    """One full verification pass against a fresh nonce (and, for https
    URLs, a fresh TLS handshake). Returns (claims, results)."""
    nonce = secrets.token_hex(16)  # 32 chars, within the 10-74 byte limit
    print(f"nonce: {nonce}")
    token = fetch_token(url, nonce)
    claims = verify_signature(token, jwks)
    results = [("signature", claims is not None, "Google JWKS signature")]
    if claims is None:
        return None, results
    results += check_claims(claims, audience, nonce, expected_digest)
    if url.startswith("https://"):
        results.append(check_tls_binding(claims, fetch_served_cert(url)))
    else:
        results.append(("tls_binding", None,
                        "plain-HTTP URL — no served certificate to compare"))
    return claims, results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True,
                        help="launcher base URL, e.g. http://1.2.3.4:8080 or https://api.example.com")
    parser.add_argument("--image-digest", required=True,
                        help="expected container image digest (sha256:...)")
    parser.add_argument("--audience", default=DEFAULT_AUDIENCE)
    args = parser.parse_args()

    well_known = requests.get(WELL_KNOWN_URL, timeout=30).json()
    jwks = requests.get(well_known["jwks_uri"], timeout=30).json()

    for _ in range(1 + TLS_REBIND_RETRIES):
        claims, results = verify_once(args.url, args.audience, args.image_digest, jwks)
        failed = [name for name, ok, _ in results if ok is False]
        if failed != ["tls_binding"]:
            break
        print("  tls_binding mismatched — retrying with a fresh token (cert rebind window)")
        time.sleep(1)

    all_ok = all(ok is not False for _, ok, _ in results)
    for name, ok, detail in results:
        status = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
        print(f"  [{status}] {name}: {detail}")
    print("RESULT: PASS" if all_ok else "RESULT: FAIL")
    if all_ok:
        print(json.dumps({k: claims.get(k) for k in ("iss", "aud", "exp", "hwmodel", "swname")},
                         indent=2))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
