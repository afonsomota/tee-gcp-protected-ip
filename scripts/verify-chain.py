#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "PyJWT[crypto]>=2.8",
#   "cryptography>=42",
#   "requests>=2.31",
# ]
# ///
"""Walk the full trust chain of a live tee-example deployment.

One command, the skeptic's path (each step maps to a section of
docs/verifying.md):

  1. fetch a fresh attestation token from the enclave (random nonce)
  2. verify Google's Confidential Space signature (JWKS)
  3. check the claims: issuer, audience, our nonce echoed in eat_nonce —
     and, for https URLs, that the served TLS certificate's key matches
     the token's tls: binding
  4. read the attested container image digest
  5. match that digest to a published GitHub release -> tag + git commit
  6. optionally re-derive the digest from the tagged source with the
     deterministic recipe (--rebuild), or compare against a digest you
     already re-derived yourself (--rebuilt-digest)

Steps 1-5 prove what Google attests is running and which public commit
published that exact image. Step 6 removes the last trust assumption: a
digest you re-derived from source on your own machine needs no trusted
build service, registry, or operator.

Usage:
  ./verify-chain.py --url https://HOST                  # steps 1-5
  ./verify-chain.py --url https://HOST --rebuild        # + rebuild (docker)
  ./verify-chain.py --url http://IP:8080 --release-digest sha256:...  # offline
"""

import argparse
import importlib.util
import pathlib
import re
import secrets
import subprocess
import sys
import tempfile

import jwt
import requests

# Shared token logic (fetch, JWKS signature check) lives in the sibling
# verify-attestation.py; import it by path so there is one implementation.
_spec = importlib.util.spec_from_file_location(
    "verify_attestation", pathlib.Path(__file__).resolve().parent / "verify-attestation.py"
)
va = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(va)

DEFAULT_REPO = "afonsomota/tee-gcp-protected-ip"
GITHUB_API = "https://api.github.com"
# The local launcher's --dev mode serves an unsigned token with this issuer;
# accepted only behind --insecure-dev and never counts as verified.
DEV_ISSUER = "urn:tee-example:dev-unverified"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


def check_claims(claims: dict, expected_audience: str, expected_nonce: str) -> list:
    """Issuer/audience/nonce checks as (name, ok, detail) tuples.

    Same checks as verify-attestation.py minus the digest equality: here the
    digest is *extracted* and matched to a published release instead.
    """
    nonces = claims.get("eat_nonce")
    if isinstance(nonces, str):
        nonces = [nonces]
    expected_issuer = DEV_ISSUER if claims.get("iss") == DEV_ISSUER else va.EXPECTED_ISSUER
    return [
        ("issuer", claims.get("iss") == expected_issuer, f"iss={claims.get('iss')!r}"),
        ("audience", claims.get("aud") == expected_audience, f"aud={claims.get('aud')!r}"),
        ("eat_nonce", nonces is not None and expected_nonce in nonces,
         "our fresh nonce is echoed" if nonces and expected_nonce in nonces
         else f"eat_nonce={nonces!r} does not echo our nonce"),
    ]


def extract_digest(claims: dict) -> str | None:
    digest = claims.get("submods", {}).get("container", {}).get("image_digest")
    return digest if isinstance(digest, str) and DIGEST_RE.fullmatch(digest) else None


def match_release(releases: list, digest: str, fetch_text) -> str | None:
    """Return the tag of the release that published `digest`, else None.

    A release matches when its image-digest.txt asset contains the digest
    (authoritative), falling back to the digest appearing in the release
    notes. `fetch_text(url) -> str` is injected for testability.
    """
    for release in releases:
        for asset in release.get("assets", []):
            if asset.get("name") == "image-digest.txt":
                if digest in fetch_text(asset["browser_download_url"]):
                    return release["tag_name"]
                break
        else:
            if digest in (release.get("body") or ""):
                return release["tag_name"]
    return None


def find_release_commit(repo: str, digest: str) -> tuple[str, str] | None:
    """(tag, commit sha) of the release publishing `digest`, else None."""
    releases = requests.get(f"{GITHUB_API}/repos/{repo}/releases", timeout=30).json()
    if not isinstance(releases, list):
        raise SystemExit(f"GitHub API error listing releases for {repo}: {releases}")
    tag = match_release(releases, digest, lambda url: requests.get(url, timeout=30).text)
    if tag is None:
        return None
    # /commits/{tag} dereferences annotated tags to the underlying commit.
    commit = requests.get(f"{GITHUB_API}/repos/{repo}/commits/{tag}", timeout=30).json()
    return tag, commit["sha"]


def rebuild_from_source(repo: str, tag: str) -> str:
    """Clone the public source at `tag` and run the deterministic recipe.

    Returns the re-derived image digest. Requires docker, python3, curl —
    exactly what scripts/build-image.sh needs. This is the trustless path:
    nothing about the clone or build is trusted, the digest is the proof.
    """
    with tempfile.TemporaryDirectory(prefix="verify-chain-") as workdir:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", tag,
             f"https://github.com/{repo}.git", workdir],
            check=True,
        )
        subprocess.run(["make", "image"], cwd=workdir, check=True)
        return (pathlib.Path(workdir) / "dist" / "image-digest.txt").read_text().strip()


def report(results: list) -> bool:
    """Print one [PASS]/[FAIL]/[SKIP] line per step; True if nothing failed."""
    for name, ok, detail in results:
        status = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
        print(f"  [{status}] {name}: {detail}")
    return all(ok is not False for _, ok, _ in results)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--url", required=True, help="enclave base URL, e.g. https://host")
    parser.add_argument("--repo", default=DEFAULT_REPO,
                        help=f"GitHub repo publishing releases (default {DEFAULT_REPO})")
    parser.add_argument("--audience", default=va.DEFAULT_AUDIENCE)
    parser.add_argument("--release-digest", metavar="sha256:...",
                        help="published digest to compare against, instead of "
                             "querying GitHub releases (offline / pre-release)")
    parser.add_argument("--rebuild", action="store_true",
                        help="re-derive the digest from the tagged source via the "
                             "deterministic recipe and compare (needs docker; slow)")
    parser.add_argument("--rebuilt-digest", metavar="sha256:...",
                        help="digest you already re-derived with 'make image'; "
                             "compared against the attested digest")
    parser.add_argument("--insecure-dev", action="store_true",
                        help="accept the local launcher's unsigned --dev token "
                             "(proves NOTHING; for local development only)")
    args = parser.parse_args()

    # -- 1. fresh token (verifying.md step 1) ---------------------------------
    nonce = secrets.token_hex(16)
    print(f"==> 1. fetch attestation token (nonce {nonce})")
    token = va.fetch_token(args.url, nonce)
    print(f"  [PASS] fetch-token: {len(token)} bytes from {args.url}/attestation")

    # -- 2. signature (verifying.md step 2) -----------------------------------
    print("==> 2. verify Google signature")
    dev_token = False
    claims = None
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        unverified = {}
    if args.insecure_dev and unverified.get("iss") == DEV_ISSUER:
        dev_token, claims = True, unverified
        ok = report([("signature", None,
                      "UNSIGNED dev token accepted via --insecure-dev — proves nothing")])
    else:
        well_known = requests.get(va.WELL_KNOWN_URL, timeout=30).json()
        jwks = requests.get(well_known["jwks_uri"], timeout=30).json()
        claims = va.verify_signature(token, jwks)
        ok = report([("signature", claims is not None,
                      "Google Confidential Space JWKS, RS256")])
        if claims is None:
            print("RESULT: FAIL")
            return 1

    # -- 3. claims (verifying.md step 3) --------------------------------------
    print("==> 3. check claims")
    claim_results = check_claims(claims, args.audience, nonce)
    if args.url.startswith("https://"):
        claim_results.append(va.check_tls_binding(claims, va.fetch_served_cert(args.url)))
    else:
        claim_results.append(("tls_binding", None,
                              "plain-HTTP URL — no served certificate to compare"))
    ok &= report(claim_results)

    # -- 4. attested digest (verifying.md step 4) -----------------------------
    print("==> 4. read attested image digest")
    digest = extract_digest(claims)
    ok &= report([("image-digest", digest is not None,
                   digest or "submods.container.image_digest absent or malformed")])
    if digest is None:
        print("RESULT: FAIL")
        return 1

    # -- 5. published release -> tag + commit (verifying.md step 5) -----------
    print("==> 5. match digest to a published release")
    tag = None
    if args.release_digest:
        ok &= report([("release-digest", digest == args.release_digest,
                       f"attested {digest} vs provided {args.release_digest}")])
    else:
        found = find_release_commit(args.repo, digest)
        if found:
            tag, commit = found
            ok &= report([("release", True,
                           f"release {tag} published this digest"),
                          ("commit", True,
                           f"the running code was built from {commit} (tag {tag})")])
        else:
            ok &= report([("release", False,
                           f"no release of {args.repo} publishes {digest} — "
                           "either nothing is released yet or this is NOT a released image")])

    # -- 6. re-derive from source (verifying.md step 6) ------------------------
    if args.rebuild or args.rebuilt_digest:
        print("==> 6. re-derive digest from source (deterministic recipe)")
        if args.rebuilt_digest:
            rebuilt = args.rebuilt_digest
            detail = f"attested {digest} vs locally re-derived {rebuilt}"
        elif tag is None:
            rebuilt, detail = None, "no matching release tag to rebuild from"
        else:
            rebuilt = rebuild_from_source(args.repo, tag)
            detail = f"attested {digest} vs rebuilt-from-{tag} {rebuilt}"
        ok &= report([("rebuild", rebuilt == digest if rebuilt else False, detail)])
    else:
        print("==> 6. rebuild from source: skipped (pass --rebuild or --rebuilt-digest;"
              " see docs/verifying.md step 6 — this is the zero-trust step)")

    if dev_token:
        print("RESULT: " + ("PASS (DEV MODE — token UNSIGNED, nothing was proven)"
                            if ok else "FAIL"))
    else:
        print("RESULT: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
