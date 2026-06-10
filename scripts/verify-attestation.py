#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "PyJWT[crypto]>=2.8",
#   "requests>=2.31",
# ]
# ///
"""Verify a Confidential Space attestation token served by the launcher.

Fetches a token from the launcher's /attestation endpoint with a fresh random
nonce, validates Google's signature against the Confidential Space JWKS, and
checks issuer, audience, nonce, and the workload container image digest.

Usage:
  ./verify-attestation.py --url http://EXTERNAL_IP:8080 \
      --image-digest sha256:abc... [--audience https://tee-example/attestation]
"""

import argparse
import json
import secrets
import sys

import jwt
import requests

WELL_KNOWN_URL = (
    "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration"
)
EXPECTED_ISSUER = "https://confidentialcomputing.googleapis.com"
DEFAULT_AUDIENCE = "https://tee-example/attestation"


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


def check_claims(
    claims: dict, expected_audience: str, expected_nonce: str, expected_digest: str
) -> list[tuple[str, bool, str]]:
    """Pure claim checks; returns (check name, passed, detail) tuples."""
    image_digest = (
        claims.get("submods", {}).get("container", {}).get("image_digest")
    )
    nonces = claims.get("eat_nonce")
    if isinstance(nonces, str):  # single nonce may be flattened to a string
        nonces = [nonces]
    # The launcher also binds enclave keys into eat_nonce as "hpke:..." /
    # "tls:..." entries (issue 003); freshness only needs our nonce present.
    return [
        ("issuer", claims.get("iss") == EXPECTED_ISSUER,
         f"iss={claims.get('iss')!r}"),
        ("audience", claims.get("aud") == expected_audience,
         f"aud={claims.get('aud')!r}"),
        ("eat_nonce", nonces is not None and expected_nonce in nonces,
         f"eat_nonce={nonces!r}"),
        ("image_digest", image_digest == expected_digest,
         f"submods.container.image_digest={image_digest!r}"),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="launcher base URL, e.g. http://1.2.3.4:8080")
    parser.add_argument("--image-digest", required=True,
                        help="expected container image digest (sha256:...)")
    parser.add_argument("--audience", default=DEFAULT_AUDIENCE)
    args = parser.parse_args()

    nonce = secrets.token_hex(16)  # 32 chars, within the 10-74 byte limit
    print(f"nonce: {nonce}")
    token = fetch_token(args.url, nonce)

    well_known = requests.get(WELL_KNOWN_URL, timeout=30).json()
    jwks = requests.get(well_known["jwks_uri"], timeout=30).json()

    claims = verify_signature(token, jwks)
    results = [("signature", claims is not None, "Google JWKS signature")]
    if claims is not None:
        results += check_claims(claims, args.audience, nonce, args.image_digest)

    all_ok = all(ok for _, ok, _ in results)
    for name, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")
    print("RESULT: PASS" if all_ok else "RESULT: FAIL")
    if all_ok:
        print(json.dumps({k: claims.get(k) for k in ("iss", "aud", "exp", "hwmodel", "swname")},
                         indent=2))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
