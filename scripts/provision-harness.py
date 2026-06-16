#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "cryptography>=42",
#   "requests>=2.31",
# ]
# ///
"""Provision the encrypted, signed wasm harness for the attested enclave (issue #8).

The harness (harness/, a stand-in for a private repo) is compiled to
harness.wasm, signed offline with the company key, then delivered to the
enclave over the *same* KMS-gated envelope pipeline as the model weights
(issue #7). This script:

  1. signs harness.wasm with the Ed25519 company key (demo key by default),
  2. encrypts it with a fresh DEK in the shared envelope format,
  3. wraps the DEK with the artifact-sealing KMS key (operator holds
     encrypt-only; decrypt is granted solely to the attested workload),
  4. uploads ciphertext + manifest (the manifest carries the base64
     signature), and
  5. prints the `harness_object` Terraform variable for infra/terraform.tfvars.

The envelope format and GCP REST helpers are reused verbatim from
provision-weights.py so the two artifacts can never drift. The launcher
(launcher/src/artifacts.rs `deliver_harness`) decrypts, verifies the SHA-256,
and then launcher/src/harness.rs verifies the signature against the pinned
public key before instantiating the module.

Usage:
  ./provision-harness.py --project YOUR_PROJECT_ID
  ./provision-harness.py --project YOUR_PROJECT_ID --wasm path/to/harness.wasm
"""

import argparse
import base64
import hashlib
import importlib.util
import io
import json
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Reuse the weights provisioner's envelope + GCP helpers (its filename has a
# hyphen, so load it by path). Importing runs only its top-level defs — the
# CLI is guarded by __main__ — so this has no side effects.
_pw_path = Path(__file__).resolve().parent / "provision-weights.py"
_spec = importlib.util.spec_from_file_location("provision_weights", _pw_path)
pw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pw)

DEFAULT_WASM = (
    Path(__file__).resolve().parent.parent
    / "launcher" / "tests" / "fixtures" / "harness" / "harness.wasm"
)
DEFAULT_SEED = (
    Path(__file__).resolve().parent.parent / "harness" / "keys" / "demo-signing-key.seed"
)


def sign(wasm: bytes, seed_path: Path) -> bytes:
    """Detached Ed25519 signature over the exact harness bytes (64 bytes)."""
    seed = seed_path.read_bytes()
    if len(seed) != 32:
        raise SystemExit(f"{seed_path}: expected a 32-byte seed, got {len(seed)}")
    return Ed25519PrivateKey.from_private_bytes(seed).sign(wasm)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--project", required=True, help="GCP project ID")
    parser.add_argument("--region", default="europe-west4")
    parser.add_argument("--bucket", help="artifacts bucket (default: PROJECT-tee-example-artifacts)")
    parser.add_argument("--kms-key", help="full KMS key name (default: bootstrap's artifact-sealing key)")
    parser.add_argument("--wasm", type=Path, default=DEFAULT_WASM, help="harness.wasm to deliver")
    parser.add_argument("--seed", type=Path, default=DEFAULT_SEED, help="Ed25519 signing seed")
    parser.add_argument("--object-prefix", default="harness/")
    args = parser.parse_args()

    bucket = args.bucket or f"{args.project}-tee-example-artifacts"
    kms_key = args.kms_key or (
        f"projects/{args.project}/locations/{args.region}"
        f"/keyRings/tee-example/cryptoKeys/artifact-sealing"
    )

    print("[1/4] read + sign harness")
    wasm = args.wasm.read_bytes()
    signature = sign(wasm, args.seed)
    sha256 = hashlib.sha256(wasm).hexdigest()
    print(f"  {args.wasm.name}: {len(wasm)} bytes, sha256 {sha256[:16]}…")

    manifest_object = f"{args.object_prefix}{args.wasm.name}.manifest.json"
    ciphertext_object = f"{args.object_prefix}{args.wasm.name}.enc"
    token = pw.access_token()

    print("[2/4] idempotency check")
    # A manifest is current only if every field the launcher acts on matches —
    # including the signature (re-signing a rebuilt harness must re-provision).
    existing = pw.gcs_get_json(token, bucket, manifest_object)
    if (
        existing
        and existing.get("format") == pw.ENVELOPE_FORMAT
        and existing.get("cipher") == pw.CIPHER
        and existing.get("chunk_size") == pw.CHUNK_SIZE
        and existing.get("kms_key") == kms_key
        and existing.get("plaintext_sha256") == sha256
        and existing.get("signature") == base64.b64encode(signature).decode()
        and pw.gcs_object_exists(token, bucket, existing.get("ciphertext_object", ""))
    ):
        print("  bucket already holds this signed harness — nothing to do")
        print(f'\nSet in infra/terraform.tfvars:\n  harness_object = "{manifest_object}"')
        return

    print("[3/4] encrypt + wrap DEK")
    dek = secrets.token_bytes(32)
    nonce_prefix = secrets.token_bytes(pw.NONCE_PREFIX_SIZE)
    out = io.BytesIO()
    size, sha = pw.encrypt_stream(io.BytesIO(wasm), out, dek, nonce_prefix)
    assert sha == sha256 and size == len(wasm)  # envelope must not mutate bytes
    wrapped_dek = pw.kms_wrap(token, kms_key, dek)
    del dek

    manifest = {
        "format": pw.ENVELOPE_FORMAT,
        "cipher": pw.CIPHER,
        "chunk_size": pw.CHUNK_SIZE,
        "nonce_prefix": base64.b64encode(nonce_prefix).decode(),
        "wrapped_dek": wrapped_dek,
        "kms_key": kms_key,
        "plaintext_size": size,
        "plaintext_sha256": sha,
        "ciphertext_object": ciphertext_object,
        # The piece weights manifests don't have: the offline company signature
        # the launcher checks against its pinned public key before running.
        "signature": base64.b64encode(signature).decode(),
    }

    print("[4/4] upload")
    # ciphertext first, then manifest (a manifest never points at a missing
    # object), mirroring provision-weights.py's ordering.
    pw.gcs_upload_small(token, bucket, ciphertext_object, out.getvalue(),
                        content_type="application/octet-stream")
    pw.gcs_upload_small(token, bucket, manifest_object,
                        json.dumps(manifest, indent=2).encode())

    print(f'\nSet in infra/terraform.tfvars:\n  harness_object = "{manifest_object}"')


if __name__ == "__main__":
    main()
