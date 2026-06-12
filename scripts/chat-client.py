#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "pyhpke>=0.6",
#   "requests>=2.31",
# ]
# ///
"""HPKE-encrypted chat against the launcher's /chat endpoint.

Mirrors what the frontend does on the wire (suite X25519-HKDF-SHA256 /
HKDF-SHA256 / ChaCha20-Poly1305, envelope {"enc","ct"} in standard base64):
fetch the enclave HPKE public key, seal {"messages", "reply_pub"} to it with
the chat request info string, POST the envelope, open the reply with a fresh
ephemeral key. Conversation state lives only here on the client; every
request carries the full history. Useful for exercising a deployed enclave
(or a local launcher) without the browser.

NOTE: unlike the frontend, this script does NOT verify the attestation
token before trusting the key — pair it with verify-attestation.py when
talking to a real enclave.

Usage:
  ./chat-client.py --url http://EXTERNAL_IP:8080 "how was my week?"   # one shot
  ./chat-client.py --url http://EXTERNAL_IP:8080                      # interactive
"""

import argparse
import base64
import json
import sys

import requests
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

REQUEST_INFO = b"tee-example/hpke/chat/request/v1"
RESPONSE_INFO = b"tee-example/hpke/chat/response/v1"

SUITE = CipherSuite.new(
    KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305
)


def chat(base: str, enclave_pub: KEMKey, messages: list[dict[str, str]]) -> str:
    """Seal the full history to the enclave, return the decrypted reply."""
    reply_key = X25519PrivateKey.generate()
    request = json.dumps(
        {
            "messages": messages,
            "reply_pub": base64.b64encode(
                reply_key.public_key().public_bytes_raw()
            ).decode(),
        }
    ).encode()
    enc, sender = SUITE.create_sender_context(enclave_pub, info=REQUEST_INFO)
    envelope = {
        "enc": base64.b64encode(enc).decode(),
        "ct": base64.b64encode(sender.seal(request)).decode(),
    }

    resp = requests.post(f"{base}/chat", json=envelope, timeout=180)
    body = resp.json()
    if resp.status_code != 200:
        raise SystemExit(f"launcher returned {resp.status_code}: {body.get('error', body)}")

    recipient = SUITE.create_recipient_context(
        base64.b64decode(body["enc"]),
        KEMKey.from_pyca_cryptography_key(reply_key),
        info=RESPONSE_INFO,
    )
    reply = json.loads(recipient.open(base64.b64decode(body["ct"])))
    return reply["reply"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="launcher base URL")
    parser.add_argument(
        "message",
        nargs="?",
        help="chat message to send; omit for an interactive multi-turn session",
    )
    args = parser.parse_args()
    base = args.url.rstrip("/")

    key_info = requests.get(f"{base}/hpke-key", timeout=30).json()
    enclave_pub = KEMKey.from_pyca_cryptography_key(
        X25519PublicKey.from_public_bytes(base64.b64decode(key_info["public_key"]))
    )

    if args.message is not None:
        print(chat(base, enclave_pub, [{"role": "user", "content": args.message}]))
        return

    # Interactive: history lives in this list and is resent in full each turn.
    history: list[dict[str, str]] = []
    while True:
        try:
            msg = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not msg:
            continue
        history.append({"role": "user", "content": msg})
        reply = chat(base, enclave_pub, history)
        history.append({"role": "assistant", "content": reply})
        print(f"enclave> {reply}")


if __name__ == "__main__":
    main()
