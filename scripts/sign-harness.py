#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "cryptography>=42",
# ]
# ///
"""Sign the wasm harness with the demo company key (issue #8).

Produces a detached 64-byte Ed25519 signature over the exact bytes of
`harness.wasm`. The launcher (`launcher/src/harness.rs`) verifies it against
the public key pinned as `COMPANY_PUBLIC_KEY` before it will instantiate the
module; a bad or missing signature is refused.

The signing key here is a committed DEMO seed (harness/keys/demo-signing-key.seed,
the value d3b0…d3b0) — see harness/keys/README.md. A real company would sign
offline with a key that never enters the repo and pin only the public half.

Usage:
  ./sign-harness.py WASM [--out WASM.sig] [--seed PATH] [--print-pubkey]
"""

import argparse
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEFAULT_SEED = Path(__file__).resolve().parent.parent / "harness" / "keys" / "demo-signing-key.seed"


def load_key(seed_path: Path) -> Ed25519PrivateKey:
    seed = seed_path.read_bytes()
    if len(seed) != 32:
        raise SystemExit(f"{seed_path}: expected a 32-byte seed, got {len(seed)}")
    return Ed25519PrivateKey.from_private_bytes(seed)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("wasm", type=Path, nargs="?", help="path to harness.wasm")
    parser.add_argument("--out", type=Path, help="signature path (default: <wasm>.sig)")
    parser.add_argument("--seed", type=Path, default=DEFAULT_SEED, help="Ed25519 private seed")
    parser.add_argument("--print-pubkey", action="store_true",
                        help="print the public key (as a Rust byte array) and exit")
    args = parser.parse_args()

    key = load_key(args.seed)

    if args.print_pubkey:
        pub = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        print("pub_hex:", pub.hex())
        print("COMPANY_PUBLIC_KEY:", ", ".join(f"0x{b:02x}" for b in pub))
        return

    if not args.wasm:
        parser.error("WASM is required unless --print-pubkey")

    data = args.wasm.read_bytes()
    signature = key.sign(data)  # Ed25519 signatures are always 64 bytes
    out = args.out or args.wasm.with_suffix(args.wasm.suffix + ".sig")
    out.write_bytes(signature)
    print(f"signed {args.wasm} ({len(data)} bytes) -> {out} ({len(signature)} bytes)")


if __name__ == "__main__":
    main()
