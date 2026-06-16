"""Unit tests for provision-harness.py (issue #8 signed delivery).

Run with:  uv run --with 'PyJWT[crypto]' --with pytest --with requests pytest scripts/

The decrypting/verifying peer is the launcher: launcher/src/artifacts.rs opens
the envelope, launcher/src/harness.rs checks the Ed25519 signature against the
pinned COMPANY_PUBLIC_KEY. These tests pin the *signing* side and assert the
pinned public key in the Rust source still matches the committed demo seed.
"""

import base64
import importlib.util
import io
import pathlib
import re

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ROOT = pathlib.Path(__file__).parent.parent

spec = importlib.util.spec_from_file_location(
    "provision_harness", pathlib.Path(__file__).parent / "provision-harness.py"
)
ph = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ph)

SEED = ROOT / "harness" / "keys" / "demo-signing-key.seed"
HARNESS_RS = ROOT / "launcher" / "src" / "harness.rs"


def pinned_public_key() -> bytes:
    """The COMPANY_PUBLIC_KEY byte array pinned in launcher/src/harness.rs."""
    text = HARNESS_RS.read_text()
    block = re.search(r"COMPANY_PUBLIC_KEY:\s*\[u8;\s*32\]\s*=\s*\[(.*?)\]", text, re.S)
    assert block, "could not find COMPANY_PUBLIC_KEY in harness.rs"
    return bytes(int(b, 16) for b in re.findall(r"0x([0-9a-fA-F]{2})", block.group(1)))


def test_signature_is_64_bytes_and_verifies():
    wasm = b"\x00asm\x01\x00\x00\x00 demo module bytes"
    sig = ph.sign(wasm, SEED)
    assert len(sig) == 64
    pub = Ed25519PrivateKey.from_private_bytes(SEED.read_bytes()).public_key()
    pub.verify(sig, wasm)  # raises InvalidSignature on mismatch


def test_signature_rejects_tampered_bytes():
    wasm = b"\x00asm\x01\x00\x00\x00 original"
    sig = ph.sign(wasm, SEED)
    pub = Ed25519PrivateKey.from_private_bytes(SEED.read_bytes()).public_key()
    with pytest.raises(InvalidSignature):
        pub.verify(sig, wasm + b"!")


def test_launcher_pins_the_committed_demo_public_key():
    """The pinned key in harness.rs must be the public half of the seed the
    provisioner signs with — otherwise the launcher would reject every
    legitimately signed harness."""
    derived = (
        Ed25519PrivateKey.from_private_bytes(SEED.read_bytes())
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    assert derived == pinned_public_key()


def test_pinned_key_validates_a_real_signature():
    """End to end on the demo key: sign with the seed, verify with the bytes
    the launcher has hard-coded."""
    wasm = b"\x00asm\x01\x00\x00\x00 harness"
    sig = ph.sign(wasm, SEED)
    Ed25519PublicKey.from_public_bytes(pinned_public_key()).verify(sig, wasm)


def test_envelope_does_not_mutate_the_wasm():
    """provision-harness reuses provision-weights' encrypt_stream; the manifest
    sha256 must be the plaintext's, so the launcher's post-decrypt check
    passes."""
    import hashlib

    wasm = bytes(i % 251 for i in range(5000))
    dek = bytes(range(32))
    nonce_prefix = b"\xbb" * ph.pw.NONCE_PREFIX_SIZE
    out = io.BytesIO()
    size, sha = ph.pw.encrypt_stream(io.BytesIO(wasm), out, dek, nonce_prefix)
    assert size == len(wasm)
    assert sha == hashlib.sha256(wasm).hexdigest()
    assert out.getvalue() != wasm  # it really is encrypted


def test_sign_rejects_a_bad_seed(tmp_path):
    bad = tmp_path / "short.seed"
    bad.write_bytes(b"too short")
    with pytest.raises(SystemExit):
        ph.sign(b"data", bad)


def test_base64_signature_round_trips_into_a_manifest_field():
    """The manifest carries the signature as base64; the launcher base64-decodes
    it back to the 64 raw bytes."""
    sig = ph.sign(b"abc", SEED)
    field = base64.b64encode(sig).decode()
    assert base64.b64decode(field) == sig
