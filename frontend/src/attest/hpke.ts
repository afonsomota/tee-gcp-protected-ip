/**
 * HPKE client for the enclave channel. Suite (must match the launcher's
 * `hpke` crate config): KEM X25519-HKDF-SHA256, KDF HKDF-SHA256,
 * AEAD ChaCha20-Poly1305, mode Base, empty AAD.
 *
 * Wire envelope, both directions: JSON `{"enc": "<base64>", "ct": "<base64>"}`
 * (standard base64; `enc` is the 32-byte encapsulated key). See
 * launcher/src/hpke_channel.rs for the canonical format description.
 */
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";

export const REQUEST_INFO = "tee-example/hpke/echo/request/v1";
export const RESPONSE_INFO = "tee-example/hpke/echo/response/v1";

/** The wire envelope: base64 of the encapsulated key and the ciphertext. */
export interface Envelope {
  enc: string;
  ct: string;
}

export function makeSuite(): CipherSuite {
  return new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });
}

export function b64encode(bytes: Uint8Array | ArrayBuffer): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const byte of u8) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function b64decode(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

const utf8 = new TextEncoder();

/** Single-shot seal to a raw 32-byte X25519 recipient public key. */
export async function seal(
  recipientPublicKeyRaw: Uint8Array,
  info: Uint8Array,
  plaintext: Uint8Array,
): Promise<Envelope> {
  const suite = makeSuite();
  const recipientPublicKey = await suite.kem.deserializePublicKey(recipientPublicKeyRaw);
  const sender = await suite.createSenderContext({ recipientPublicKey, info });
  const ct = await sender.seal(plaintext);
  return { enc: b64encode(sender.enc), ct: b64encode(ct) };
}

/** Single-shot open with the recipient private key. */
export async function open(
  recipientPrivateKey: CryptoKey,
  envelope: Envelope,
  info: Uint8Array,
): Promise<Uint8Array> {
  const suite = makeSuite();
  const recipient = await suite.createRecipientContext({
    recipientKey: recipientPrivateKey,
    enc: b64decode(envelope.enc),
    info,
  });
  return new Uint8Array(await recipient.open(b64decode(envelope.ct)));
}

/**
 * Round-trip an encrypted echo: seal `{msg, reply_pub}` to the pinned enclave
 * key, POST it, open the reply with a fresh ephemeral keypair. Only
 * ciphertext crosses the wire in either direction.
 */
export async function hpkeEcho(
  baseUrl: string,
  enclavePublicKey: Uint8Array,
  msg: string,
): Promise<string> {
  const suite = makeSuite();
  const replyKeyPair = await suite.kem.generateKeyPair();
  const replyPub = new Uint8Array(await suite.kem.serializePublicKey(replyKeyPair.publicKey));
  const request = JSON.stringify({ msg, reply_pub: b64encode(replyPub) });
  const envelope = await seal(enclavePublicKey, utf8.encode(REQUEST_INFO), utf8.encode(request));

  const response = await fetch(new URL("/hpke/echo", baseUrl), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(envelope),
  });
  if (!response.ok) {
    throw new Error(`hpke echo failed: HTTP ${response.status} ${await response.text()}`);
  }
  const reply = (await response.json()) as Envelope;
  const plaintext = await open(replyKeyPair.privateKey, reply, utf8.encode(RESPONSE_INFO));
  const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as { echo: string };
  return parsed.echo;
}
