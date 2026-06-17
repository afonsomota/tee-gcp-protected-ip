/**
 * HPKE chat channel to the enclave, with the client-side tool loop (issue #10).
 *
 * The /chat endpoint receives an HPKE-sealed JSON payload containing the
 * full chat history (client-side state — no server persistence), any pending
 * tool results, and a fresh ephemeral reply key. The enclave unseals it, runs
 * the harness, and returns an HPKE-sealed reply that is either a final answer
 * or a request to run client-side tools.
 *
 * The tool loop itself lives in `toolLoop.ts` (shared with `/enrich`); this
 * module is just the chat-specific transport: build the request, seal it, post
 * it, and unseal the per-turn reply. Only the tool *results* (e.g. the
 * search-matched entries) cross the channel; the rest of the journal never
 * leaves the device.
 *
 * Info strings and the request/response plaintext shapes must match
 * launcher/src/chat.rs.
 */
import { type Envelope, b64encode, makeSuite, open, seal } from "./hpke";
import {
  type HarnessTurn,
  type ToolLoopOptions,
  type ToolResult,
  runToolLoop,
} from "./toolLoop";

export type { ToolActivity, ToolResult } from "./toolLoop";

export const CHAT_REQUEST_INFO = "tee-example/hpke/chat/request/v1";
export const CHAT_RESPONSE_INFO = "tee-example/hpke/chat/response/v1";

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export type ChatOptions = ToolLoopOptions;

const utf8 = new TextEncoder();

/**
 * Build the /chat request plaintext. Field names pin the launcher's wire
 * format (`ChatRequest` in launcher/src/chat.rs): `messages` is the full
 * conversation oldest-first, `reply_pub` the base64 raw 32-byte X25519 key the
 * response is sealed to, and `tool_results` (only when present) the output of
 * the tool calls the harness asked for last round.
 */
export function buildChatPayload(
  history: ChatMessage[],
  replyPub: Uint8Array,
  toolResults?: ToolResult[],
): string {
  const payload: Record<string, unknown> = {
    messages: history,
    reply_pub: b64encode(replyPub),
  };
  if (toolResults !== undefined && toolResults.length > 0) {
    payload.tool_results = toolResults;
  }
  return JSON.stringify(payload);
}

/**
 * Send the chat history (and any pending tool results) to /chat and return the
 * enclave's per-turn reply. Only ciphertext crosses the wire in either
 * direction.
 */
async function sendTurn(
  apiEndpoint: string,
  enclavePublicKey: Uint8Array,
  history: ChatMessage[],
  toolResults?: ToolResult[],
): Promise<HarnessTurn> {
  const suite = makeSuite();
  const replyKeyPair = await suite.kem.generateKeyPair();
  const replyPub = new Uint8Array(await suite.kem.serializePublicKey(replyKeyPair.publicKey));

  const requestPayload = buildChatPayload(history, replyPub, toolResults);
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
  return JSON.parse(new TextDecoder().decode(plaintext)) as HarnessTurn;
}

/**
 * Run a full chat turn: send the history, and while the enclave asks for tools,
 * execute them locally and feed the results back, until it returns a reply.
 */
export async function hpkeChat(
  apiEndpoint: string,
  enclavePublicKey: Uint8Array,
  history: ChatMessage[],
  options: ChatOptions = {},
): Promise<string> {
  return runToolLoop(
    (toolResults) => sendTurn(apiEndpoint, enclavePublicKey, history, toolResults),
    options,
  );
}
