#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "pyhpke>=0.6",
#   "requests>=2.31",
# ]
# ///
"""HPKE client for the launcher's /chat and /enrich endpoints.

Mirrors what the frontend does on the wire (suite X25519-HKDF-SHA256 /
HKDF-SHA256 / ChaCha20-Poly1305, envelope {"enc","ct"} in standard base64):
fetch the enclave HPKE public key, seal the request to it with the per-endpoint
request info string, POST the envelope, open the reply with a fresh ephemeral
key. The enclave is stateless, so every request carries the full state (the
chat history, or the entry to enrich). Useful for exercising a deployed enclave
(or a local launcher) without the browser.

Either endpoint may answer with client-side tool calls (issues #10, #11)
instead of a reply: `search_entries` over the user's local journal (chat) and
`attach_metadata` to store enrichment (enrich). Model-bound tools (`summarize`,
`extract_metadata`, `embed`) run inside the enclave and never reach us. This
CLI has no local journal, so it runs `search_entries` as a no-op (empty
results) and `attach_metadata` as a no-op ack, printing the enrichment the
enclave produced; it prints each tool the enclave asked for so the loop is
visible. Use the browser frontend for the real, journal-backed tool flow.

NOTE: unlike the frontend, this script does NOT verify the attestation
token before trusting the key — pair it with verify-attestation.py when
talking to a real enclave.

Usage:
  ./chat-client.py --url http://EXTERNAL_IP:8080 "how was my week?"   # one shot
  ./chat-client.py --url http://EXTERNAL_IP:8080                      # interactive
  ./chat-client.py --url http://EXTERNAL_IP:8080 --enrich \
      --title "Monday" "Long day, but the demo finally worked."       # enrich an entry
"""

import argparse
import base64
import json
import sys
import uuid

import requests
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

CHAT_REQUEST_INFO = b"tee-example/hpke/chat/request/v1"
CHAT_RESPONSE_INFO = b"tee-example/hpke/chat/response/v1"
ENRICH_REQUEST_INFO = b"tee-example/hpke/enrich/request/v1"
ENRICH_RESPONSE_INFO = b"tee-example/hpke/enrich/response/v1"

SUITE = CipherSuite.new(
    KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305
)


MAX_TOOL_ROUNDS = 4


def run_tool(call: dict) -> object:
    """Execute one client-side tool call. This CLI has no local journal, so
    `search_entries` matches nothing and `attach_metadata` is a no-op ack; the
    enclave's harness only checks that the write happened. For enrichment we
    print the metadata the enclave produced before acking it."""
    name = call.get("name")
    if name == "search_entries":
        return {"matches": [], "count": 0}
    if name == "attach_metadata":
        args = call.get("arguments", {})
        print_enrichment(args.get("enrichment", {}))
        return {"ok": True, "entry_id": args.get("entry_id")}
    raise SystemExit(f"enclave requested an unknown tool: {name!r}")


def print_enrichment(enrichment: dict) -> None:
    """Print the enrichment the enclave attached: summary, metadata, and the
    embedding's dimensionality (never the raw vector)."""
    print("enrichment:")
    if enrichment.get("summary"):
        print(f"  summary: {enrichment['summary']}")
    for field in ("emotions", "situations", "lifePhases"):
        if enrichment.get(field):
            print(f"  {field}: {', '.join(enrichment[field])}")
    embedding = enrichment.get("embedding")
    if isinstance(embedding, list):
        print(f"  embedding: {len(embedding)} dimensions")


def _send_turn(
    base: str,
    enclave_pub: KEMKey,
    path: str,
    req_info: bytes,
    resp_info: bytes,
    fields: dict[str, object],
    tool_results: list[dict] | None,
) -> dict:
    """One request/response round-trip: seal the state (+ any tool results),
    return the decrypted harness turn ({"reply": ...} or {"tool_calls": [...]})."""
    reply_key = X25519PrivateKey.generate()
    payload: dict[str, object] = dict(fields)
    payload["reply_pub"] = base64.b64encode(
        reply_key.public_key().public_bytes_raw()
    ).decode()
    if tool_results:
        payload["tool_results"] = tool_results
    request = json.dumps(payload).encode()
    enc, sender = SUITE.create_sender_context(enclave_pub, info=req_info)
    envelope = {
        "enc": base64.b64encode(enc).decode(),
        "ct": base64.b64encode(sender.seal(request)).decode(),
    }

    resp = requests.post(f"{base}{path}", json=envelope, timeout=180)
    body = resp.json()
    if resp.status_code != 200:
        raise SystemExit(f"launcher returned {resp.status_code}: {body.get('error', body)}")

    recipient = SUITE.create_recipient_context(
        base64.b64decode(body["enc"]),
        KEMKey.from_pyca_cryptography_key(reply_key),
        info=resp_info,
    )
    return json.loads(recipient.open(base64.b64decode(body["ct"])))


def drive(
    base: str,
    enclave_pub: KEMKey,
    path: str,
    req_info: bytes,
    resp_info: bytes,
    fields: dict[str, object],
) -> str:
    """Run a full exchange against `path`: send the state and, while the enclave
    asks for client tools, run them locally and feed the results back, until it
    returns a reply."""
    tool_results: list[dict] | None = None
    for _ in range(MAX_TOOL_ROUNDS + 1):
        turn = _send_turn(base, enclave_pub, path, req_info, resp_info, fields, tool_results)
        if "reply" in turn:
            return turn["reply"]
        calls = turn.get("tool_calls") or []
        if not calls:
            raise SystemExit("enclave returned neither a reply nor tool calls")
        tool_results = []
        for call in calls:
            # attach_metadata's args carry the (large) embedding, printed by
            # run_tool instead; keep the loop line compact.
            name = call.get("name")
            detail = "" if name == "attach_metadata" else f" {json.dumps(call.get('arguments', {}))}"
            print(f"  [enclave tool: {name}{detail}]", file=sys.stderr)
            tool_results.append({"id": call.get("id"), "name": name, "result": run_tool(call)})
    raise SystemExit(f"enclave tool loop exceeded {MAX_TOOL_ROUNDS} rounds")


def chat(base: str, enclave_pub: KEMKey, messages: list[dict[str, str]]) -> str:
    return drive(base, enclave_pub, "/chat", CHAT_REQUEST_INFO, CHAT_RESPONSE_INFO,
                 {"messages": messages})


def enrich(base: str, enclave_pub: KEMKey, entry: dict[str, str]) -> str:
    return drive(base, enclave_pub, "/enrich", ENRICH_REQUEST_INFO, ENRICH_RESPONSE_INFO,
                 {"entry": entry})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="launcher base URL")
    parser.add_argument("--enrich", action="store_true",
                        help="enrich an entry instead of chatting")
    parser.add_argument("--title", default="", help="entry title (--enrich mode)")
    parser.add_argument("--id", help="entry id (--enrich mode; default: random)")
    parser.add_argument(
        "message",
        nargs="?",
        help="chat message, or the entry body in --enrich mode; "
             "omit (chat only) for an interactive multi-turn session",
    )
    args = parser.parse_args()
    base = args.url.rstrip("/")

    key_info = requests.get(f"{base}/hpke-key", timeout=30).json()
    enclave_pub = KEMKey.from_pyca_cryptography_key(
        X25519PublicKey.from_public_bytes(base64.b64decode(key_info["public_key"]))
    )

    if args.enrich:
        if args.message is None:
            parser.error("--enrich needs an entry body")
        entry = {"id": args.id or uuid.uuid4().hex, "title": args.title, "body": args.message}
        print(enrich(base, enclave_pub, entry))
        return

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
