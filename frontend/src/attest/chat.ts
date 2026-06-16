/**
 * HPKE chat channel to the enclave, with the client-side tool loop (issue #10).
 *
 * The /chat endpoint receives an HPKE-sealed JSON payload containing the
 * full chat history (client-side state — no server persistence), any pending
 * tool results, and a fresh ephemeral reply key. The enclave unseals it, runs
 * the harness, and returns an HPKE-sealed reply that is either a final answer
 * or a request to run client-side tools.
 *
 * When the enclave asks for tools, we execute them locally (over IndexedDB),
 * seal the results, and send them back for the next harness turn — looping
 * until the harness produces a reply. Only the tool *results* (e.g. the
 * search-matched entries) cross the channel; the rest of the journal never
 * leaves the device.
 *
 * Info strings and the request/response plaintext shapes must match
 * launcher/src/chat.rs.
 */
import { type Envelope, b64encode, makeSuite, open, seal } from "./hpke";
import type { ToolCall, ToolExecutor } from "./tools";

export const CHAT_REQUEST_INFO = "tee-example/hpke/chat/request/v1";
export const CHAT_RESPONSE_INFO = "tee-example/hpke/chat/response/v1";

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

/** A tool result fed back to the enclave for the next harness turn. */
export interface ToolResult {
  id: string;
  name: string;
  result: unknown;
}

/** UI-facing record of one tool the enclave asked us to run. */
export interface ToolActivity {
  id: string;
  name: string;
  status: "running" | "done" | "error";
  summary: string;
}

export interface ChatOptions {
  /** Runs a client-locus tool the enclave requested. Required if the harness
   *  emits tool calls (it does on every user turn). */
  executeTool?: ToolExecutor;
  /** Notified as each tool starts and finishes, for the chat UI. */
  onActivity?: (activity: ToolActivity) => void;
  /** Safety bound on harness↔client tool rounds before giving up. */
  maxToolRounds?: number;
}

/** The enclave's per-turn reply: a final answer xor a batch of tool calls. */
interface HarnessTurn {
  reply?: string;
  tool_calls?: ToolCall[];
}

const utf8 = new TextEncoder();
const DEFAULT_MAX_TOOL_ROUNDS = 4;

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
  const maxRounds = options.maxToolRounds ?? DEFAULT_MAX_TOOL_ROUNDS;
  let toolResults: ToolResult[] | undefined;

  for (let round = 0; round <= maxRounds; round++) {
    const turn = await sendTurn(apiEndpoint, enclavePublicKey, history, toolResults);

    if (typeof turn.reply === "string") {
      return turn.reply;
    }

    const calls = turn.tool_calls;
    if (calls === undefined || calls.length === 0) {
      throw new Error("enclave returned neither a reply nor tool calls");
    }
    if (options.executeTool === undefined) {
      throw new Error("the enclave requested a tool, but no tool executor is configured");
    }

    toolResults = [];
    for (const call of calls) {
      options.onActivity?.({
        id: call.id,
        name: call.name,
        status: "running",
        summary: describePending(call),
      });
      try {
        const outcome = await options.executeTool(call);
        toolResults.push({ id: call.id, name: call.name, result: outcome.result });
        options.onActivity?.({
          id: call.id,
          name: call.name,
          status: "done",
          summary: outcome.summary,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        options.onActivity?.({
          id: call.id,
          name: call.name,
          status: "error",
          summary: `Tool ${call.name} failed: ${message}`,
        });
        throw err;
      }
    }
  }

  throw new Error(`enclave tool loop exceeded ${maxRounds} rounds`);
}

function describePending(call: ToolCall): string {
  if (call.name === "search_entries") {
    const query = typeof call.arguments.query === "string" ? call.arguments.query : "";
    return query ? `Searching your entries for “${query}”…` : "Searching your entries…";
  }
  if (call.name === "attach_metadata") {
    return "Saving metadata to your local journal…";
  }
  return `Running ${call.name}…`;
}
