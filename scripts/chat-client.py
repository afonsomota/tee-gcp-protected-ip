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

The enclave may answer with client-side tool calls (issue #10) instead of a
reply — e.g. `search_entries` over the user's local journal. This CLI has no
local journal, so it runs those tools as no-ops (empty results) and feeds the
results back until the harness produces a reply; it prints each tool the
enclave asked for so the loop is visible. Use the browser frontend for the
real, journal-backed tool flow.

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


MAX_TOOL_ROUNDS = 4


def run_tool(call: dict) -> object:
    """Execute one client-side tool call. This CLI has no local journal, so
    `search_entries` matches nothing and `attach_metadata` is a no-op; the
    enclave's harness handles empty results gracefully."""
    name = call.get("name")
    if name == "search_entries":
        return {"matches": [], "count": 0}
    if name == "attach_metadata":
        return {"ok": False, "error": "chat-client.py has no local journal"}
    raise SystemExit(f"enclave requested an unknown tool: {name!r}")


def _send_turn(
    base: str,
    enclave_pub: KEMKey,
    messages: list[dict[str, str]],
    tool_results: list[dict] | None,
) -> dict:
    """One /chat round-trip: seal the history (+ any tool results), return the
    decrypted harness turn ({"reply": ...} or {"tool_calls": [...]})."""
    reply_key = X25519PrivateKey.generate()
    payload: dict[str, object] = {
        "messages": messages,
        "reply_pub": base64.b64encode(
            reply_key.public_key().public_bytes_raw()
        ).decode(),
    }
    if tool_results:
        payload["tool_results"] = tool_results
    request = json.dumps(payload).encode()
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
    return json.loads(recipient.open(base64.b64decode(body["ct"])))


def chat(base: str, enclave_pub: KEMKey, messages: list[dict[str, str]]) -> str:
    """Run a full turn: send the history and, while the enclave asks for tools,
    run them locally and feed the results back, until it returns a reply."""
    tool_results: list[dict] | None = None
    for _ in range(MAX_TOOL_ROUNDS + 1):
        turn = _send_turn(base, enclave_pub, messages, tool_results)
        if "reply" in turn:
            return turn["reply"]
        calls = turn.get("tool_calls") or []
        if not calls:
            raise SystemExit("enclave returned neither a reply nor tool calls")
        tool_results = []
        for call in calls:
            args = call.get("arguments", {})
            print(f"  [enclave tool: {call.get('name')} {json.dumps(args)}]", file=sys.stderr)
            tool_results.append(
                {"id": call.get("id"), "name": call.get("name"), "result": run_tool(call)}
            )
    raise SystemExit(f"enclave tool loop exceeded {MAX_TOOL_ROUNDS} rounds")


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
