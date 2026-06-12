#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "cryptography>=42",
#   "requests>=2.31",
# ]
# ///
"""Provision envelope-encrypted model weights for the attested enclave (issue #7).

Downloads the GGUF model from Hugging Face (cached locally), encrypts it with
a fresh data-encryption key, wraps that DEK with the artifact-sealing KMS key
(the operator holds encrypt-only — decrypt is granted exclusively to the
attested workload identity principalSet by infra/), uploads ciphertext and
manifest to the artifacts bucket, and prints the `weights_object` Terraform
variable to put in infra/terraform.tfvars.

Idempotent: if the bucket already holds a manifest whose plaintext_sha256
matches the local model and whose ciphertext object exists, nothing is
re-encrypted or re-uploaded.

Envelope format (decrypted by launcher/src/artifacts.rs, pinned by the
interop fixture launcher/tests/fixtures/artifact-envelope.json):

  ChaCha20-Poly1305 in the RustCrypto STREAM (BE32) construction.
  The plaintext is split into chunk_size segments; segment i is sealed with
  nonce = nonce_prefix (7 bytes) || i as u32 BE (4 bytes) || last-flag (1
  byte, 0x01 on the final segment), AAD = the format string. Each ciphertext
  segment is plaintext segment + 16-byte tag, concatenated in order. The
  final segment may be shorter; if the plaintext is an exact multiple of
  chunk_size the final segment is full-sized (empty plaintext = one empty
  final segment). The manifest JSON carries the KMS-wrapped DEK plus
  integrity metadata.

Usage:
  ./provision-weights.py --project YOUR_PROJECT_ID
"""

import argparse
import base64
import hashlib
import io
import json
import secrets
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import quote

import requests
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

ENVELOPE_FORMAT = "tee-example/artifact-envelope/v1"
ENVELOPE_AAD = ENVELOPE_FORMAT.encode()
CIPHER = "chacha20poly1305-stream-be32"
CHUNK_SIZE = 4 * 1024 * 1024
TAG_SIZE = 16
NONCE_PREFIX_SIZE = 7

DEFAULT_MODEL_URL = (
    "https://huggingface.co/google/gemma-4-E2B-it-qat-q4_0-gguf"
    "/resolve/main/gemma-4-E2B_q4_0-it.gguf"
)
HF_TOKEN_PATH = Path.home() / ".cache" / "huggingface" / "token"


def encrypt_stream(reader, writer, dek: bytes, nonce_prefix: bytes,
                   chunk_size: int = CHUNK_SIZE) -> tuple[int, str]:
    """Seal reader→writer in STREAM BE32 segments; return (size, sha256hex).

    Mirrored by `EnvelopeDecryptor` in launcher/src/artifacts.rs — any change
    here must regenerate the interop fixture and pass `cargo test` too.
    """
    if len(dek) != 32 or len(nonce_prefix) != NONCE_PREFIX_SIZE:
        raise ValueError("need a 32-byte DEK and a 7-byte nonce prefix")
    aead = ChaCha20Poly1305(dek)
    digest = hashlib.sha256()
    size = 0
    counter = 0
    chunk = reader.read(chunk_size)
    while True:
        next_chunk = reader.read(chunk_size)
        last = not next_chunk
        digest.update(chunk)
        size += len(chunk)
        nonce = nonce_prefix + counter.to_bytes(4, "big") + (b"\x01" if last else b"\x00")
        writer.write(aead.encrypt(nonce, chunk, ENVELOPE_AAD))
        counter += 1
        if last:
            return size, digest.hexdigest()
        chunk = next_chunk


def fixture_json() -> str:
    """Interop test vectors for the Rust decryptor, with fixed keys so the
    output is deterministic. Written to
    launcher/tests/fixtures/artifact-envelope.json by --write-fixture;
    scripts/test_provision_weights.py asserts the checked-in file matches."""
    cases = []
    for name, plaintext, chunk_size in [
        ("multi-chunk, partial last", bytes(range(100)), 32),
        ("exact multiple of chunk_size: last segment full-sized", bytes(range(64)), 32),
        ("single short chunk", b"tee weights", 32),
        ("empty plaintext: one empty final segment", b"", 32),
    ]:
        dek = bytes.fromhex("11" * 16 + "22" * 16)
        nonce_prefix = bytes.fromhex("01020304050607")
        out = io.BytesIO()
        size, sha = encrypt_stream(io.BytesIO(plaintext), out, dek, nonce_prefix, chunk_size)
        cases.append({
            "name": name,
            "chunk_size": chunk_size,
            "dek": base64.b64encode(dek).decode(),
            "nonce_prefix": base64.b64encode(nonce_prefix).decode(),
            "plaintext": base64.b64encode(plaintext).decode(),
            "plaintext_size": size,
            "plaintext_sha256": sha,
            "ciphertext": base64.b64encode(out.getvalue()).decode(),
        })
    doc = {
        "generator": "python scripts/provision-weights.py --write-fixture",
        "format": ENVELOPE_FORMAT,
        "cipher": CIPHER,
        "aad": base64.b64encode(ENVELOPE_AAD).decode(),
        "cases": cases,
    }
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


# ---- GCP REST helpers (no SDKs; auth = the operator's gcloud login) ---------

def access_token() -> str:
    result = subprocess.run(
        ["gcloud", "auth", "print-access-token"],
        check=True, capture_output=True, text=True,
    )
    return result.stdout.strip()


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def gcs_object_url(bucket: str, name: str) -> str:
    # object names contain "/" — must be percent-encoded in the URL path
    return f"https://storage.googleapis.com/storage/v1/b/{bucket}/o/{quote(name, safe='')}"


def gcs_get_json(token: str, bucket: str, name: str) -> dict | None:
    resp = requests.get(
        gcs_object_url(bucket, name), params={"alt": "media"},
        headers=auth_headers(token), timeout=60,
    )
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def gcs_object_exists(token: str, bucket: str, name: str) -> bool:
    resp = requests.get(gcs_object_url(bucket, name), headers=auth_headers(token), timeout=60)
    if resp.status_code == 404:
        return False
    resp.raise_for_status()
    return True


def gcs_upload_small(token: str, bucket: str, name: str, data: bytes,
                     content_type: str = "application/json") -> None:
    resp = requests.post(
        f"https://storage.googleapis.com/upload/storage/v1/b/{bucket}/o",
        params={"uploadType": "media", "name": name},
        headers={**auth_headers(token), "Content-Type": content_type},
        data=data, timeout=60,
    )
    resp.raise_for_status()


def gcs_upload_resumable(token: str, bucket: str, name: str, path: Path) -> None:
    """Resumable upload for the multi-GB ciphertext: one session, streamed PUT."""
    size = path.stat().st_size
    init = requests.post(
        f"https://storage.googleapis.com/upload/storage/v1/b/{bucket}/o",
        params={"uploadType": "resumable", "name": name},
        headers={
            **auth_headers(token),
            "Content-Type": "application/json",
            "X-Upload-Content-Type": "application/octet-stream",
            "X-Upload-Content-Length": str(size),
        },
        json={"name": name}, timeout=60,
    )
    init.raise_for_status()
    session = init.headers["Location"]
    print(f"  uploading {size / 2**30:.2f} GiB to gs://{bucket}/{name} ...")
    with path.open("rb") as f:
        put = requests.put(
            session,
            headers={"Content-Length": str(size), "Content-Type": "application/octet-stream"},
            data=f, timeout=3600,
        )
    put.raise_for_status()


def kms_wrap(token: str, key: str, dek: bytes) -> str:
    """Wrap the DEK with the artifact-sealing key; returns base64 ciphertext."""
    resp = requests.post(
        f"https://cloudkms.googleapis.com/v1/{key}:encrypt",
        headers=auth_headers(token),
        json={"plaintext": base64.b64encode(dek).decode()}, timeout=60,
    )
    if resp.status_code == 403:
        raise SystemExit(
            "KMS encrypt denied. Grant yourself encrypt with:\n"
            "  terraform -chdir=infra/bootstrap apply \\\n"
            "    -var 'artifact_encrypter_members=[\"user:YOU@example.com\"]' ..."
        )
    resp.raise_for_status()
    return resp.json()["ciphertext"]


# ---- provisioning steps -----------------------------------------------------

def download_model(url: str, cache_dir: Path) -> Path:
    filename = url.rsplit("/", 1)[-1]
    target = cache_dir / filename
    if target.exists():
        print(f"  model cached at {target}")
        return target
    cache_dir.mkdir(parents=True, exist_ok=True)
    headers = {}
    if HF_TOKEN_PATH.exists():
        headers["Authorization"] = f"Bearer {HF_TOKEN_PATH.read_text().strip()}"
    print(f"  downloading {url} ...")
    part = target.with_suffix(target.suffix + ".part")
    with requests.get(url, headers=headers, stream=True, timeout=60) as resp:
        resp.raise_for_status()
        with part.open("wb") as f:
            for block in resp.iter_content(chunk_size=2**20):
                f.write(block)
    part.rename(target)
    return target


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(2**20):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--project", help="GCP project ID (required unless --write-fixture)")
    parser.add_argument("--region", default="europe-west4")
    parser.add_argument("--bucket", help="artifacts bucket (default: PROJECT-tee-example-artifacts)")
    parser.add_argument("--kms-key", help="full KMS key name (default: bootstrap's artifact-sealing key)")
    parser.add_argument("--model-url", default=DEFAULT_MODEL_URL)
    parser.add_argument("--object-prefix", default="weights/")
    parser.add_argument("--cache-dir", type=Path,
                        default=Path.home() / ".cache" / "tee-example" / "weights")
    parser.add_argument("--write-fixture", metavar="PATH",
                        help="write the Rust interop fixture JSON and exit")
    args = parser.parse_args()

    if args.write_fixture:
        Path(args.write_fixture).write_text(fixture_json())
        print(f"wrote {args.write_fixture}")
        return
    if not args.project:
        parser.error("--project is required")

    bucket = args.bucket or f"{args.project}-tee-example-artifacts"
    kms_key = args.kms_key or (
        f"projects/{args.project}/locations/{args.region}"
        f"/keyRings/tee-example/cryptoKeys/artifact-sealing"
    )

    print("[1/4] model")
    model = download_model(args.model_url, args.cache_dir)
    local_sha = sha256_file(model)

    manifest_object = f"{args.object_prefix}{model.name}.manifest.json"
    ciphertext_object = f"{args.object_prefix}{model.name}.enc"
    token = access_token()

    print("[2/4] idempotency check")
    existing = gcs_get_json(token, bucket, manifest_object)
    if (
        existing
        and existing.get("plaintext_sha256") == local_sha
        and gcs_object_exists(token, bucket, existing.get("ciphertext_object", ""))
    ):
        print("  bucket already holds this model — nothing to do")
        print(f'\nSet in infra/terraform.tfvars:\n  weights_object = "{manifest_object}"')
        return

    print("[3/4] encrypt + wrap DEK")
    dek = secrets.token_bytes(32)
    nonce_prefix = secrets.token_bytes(NONCE_PREFIX_SIZE)
    with tempfile.NamedTemporaryFile(dir=args.cache_dir, suffix=".enc", delete=False) as tmp:
        enc_path = Path(tmp.name)
        with model.open("rb") as plain:
            size, sha = encrypt_stream(plain, tmp, dek, nonce_prefix)
    assert sha == local_sha
    wrapped_dek = kms_wrap(token, kms_key, dek)
    del dek  # the only plaintext copy of the key material in this process

    manifest = {
        "format": ENVELOPE_FORMAT,
        "cipher": CIPHER,
        "chunk_size": CHUNK_SIZE,
        "nonce_prefix": base64.b64encode(nonce_prefix).decode(),
        "wrapped_dek": wrapped_dek,
        "kms_key": kms_key,
        "plaintext_size": size,
        "plaintext_sha256": sha,
        "ciphertext_object": ciphertext_object,
    }

    print("[4/4] upload")
    try:
        # ciphertext first: a manifest is only ever uploaded once its
        # ciphertext is fully in place, so a crashed run can't leave a
        # manifest pointing at a missing/partial object.
        gcs_upload_resumable(token, bucket, ciphertext_object, enc_path)
        gcs_upload_small(token, bucket, manifest_object,
                         json.dumps(manifest, indent=2).encode())
    finally:
        enc_path.unlink()

    print(f'\nSet in infra/terraform.tfvars:\n  weights_object = "{manifest_object}"')


if __name__ == "__main__":
    main()
