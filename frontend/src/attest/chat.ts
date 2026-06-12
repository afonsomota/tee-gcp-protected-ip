/**
 * HPKE chat channel to the enclave.
 *
 * The /chat endpoint receives an HPKE-sealed JSON payload containing the
 * full chat history (client-side state — no server persistence) and a fresh
 * ephemeral reply key. The enclave unseals it, runs inference, and returns
 * an HPKE-sealed reply encrypted to the ephemeral key.
 *
 * Info strings must match launcher/src/hpke_channel.rs.
 */
import { type Envelope, b64encode, makeSuite, open, seal } from "./hpke";

export const CHAT_REQUEST_INFO = "tee-example/hpke/chat/request/v1";
export const CHAT_RESPONSE_INFO = "tee-example/hpke/chat/response/v1";

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

const utf8 = new TextEncoder();

/**
 * Send the full chat history to /chat and return the model's plaintext reply.
 * Only ciphertext crosses the wire in either direction.
 */
export async function hpkeChat(
  apiEndpoint: string,
  enclavePublicKey: Uint8Array,
  history: ChatMessage[],
): Promise<string> {
  const suite = makeSuite();
  const replyKeyPair = await suite.kem.generateKeyPair();
  const replyPub = new Uint8Array(await suite.kem.serializePublicKey(replyKeyPair.publicKey));

  const requestPayload = JSON.stringify({ history, reply_pub: b64encode(replyPub) });
  const envelope = await seal(
    enclavePublicKey,
    utf8.encode(CHAT_REQUEST_INFO),
    utf8.encode(requestPayload),
  );

  const response = await fetch(`${apiEndpoint}/chat`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(envelope),
  });

  if (!response.ok) {
    throw new Error(`chat failed: HTTP ${response.status} ${await response.text()}`);
  }

  const reply = (await response.json()) as Envelope;
  const plaintext = await open(replyKeyPair.privateKey, reply, utf8.encode(CHAT_RESPONSE_INFO));
  const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as { reply: string };
  return parsed.reply;
}
