/**
 * HPKE entry-enrichment channel to the enclave (issue #11).
 *
 * When the user saves an entry, the browser sends it (HPKE-sealed) to /enrich.
 * The enclave's harness runs the model-bound enclave tools — `summarize`,
 * `extract_metadata`, and (when available) `embed` — in-enclave, folds the
 * results into one enrichment object, and asks the browser to `attach_metadata`
 * (the only thing returned). The client stores it encrypted, beside the entry,
 * via the same tool executor as chat.
 *
 * Only the entry being enriched crosses the channel — nothing else from the
 * journal — and it is never persisted server-side. The loop and tool execution
 * are shared with chat (`toolLoop.ts`); this module is just the enrich-specific
 * transport.
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

export const ENRICH_REQUEST_INFO = "tee-example/hpke/enrich/request/v1";
export const ENRICH_RESPONSE_INFO = "tee-example/hpke/enrich/response/v1";

/** The entry handed to the enclave for enrichment. */
export interface EnrichEntry {
  id: string;
  title: string;
  body: string;
}

/** The tool executor is required: enrichment always ends in `attach_metadata`. */
export interface EnrichOptions extends ToolLoopOptions {
  executeTool: ToolLoopOptions["executeTool"];
}

const utf8 = new TextEncoder();

/**
 * Build the /enrich request plaintext. Field names pin the launcher's wire
 * format (`EnrichRequest` in launcher/src/chat.rs): `entry` is the entry to
 * enrich, `reply_pub` the base64 raw 32-byte X25519 key the response is sealed
 * to, and `tool_results` (only when present) the output of the tool calls the
 * harness asked for last round.
 */
export function buildEnrichPayload(
  entry: EnrichEntry,
  replyPub: Uint8Array,
  toolResults?: ToolResult[],
): string {
  const payload: Record<string, unknown> = {
    entry,
    reply_pub: b64encode(replyPub),
  };
  if (toolResults !== undefined && toolResults.length > 0) {
    payload.tool_results = toolResults;
  }
  return JSON.stringify(payload);
}

/**
 * Seal the entry (and any pending tool results) to /enrich and return the
 * enclave's per-turn reply. Only ciphertext crosses the wire in either
 * direction.
 */
async function sendTurn(
  apiEndpoint: string,
  enclavePublicKey: Uint8Array,
  entry: EnrichEntry,
  toolResults?: ToolResult[],
): Promise<HarnessTurn> {
  const suite = makeSuite();
  const replyKeyPair = await suite.kem.generateKeyPair();
  const replyPub = new Uint8Array(await suite.kem.serializePublicKey(replyKeyPair.publicKey));

  const requestPayload = buildEnrichPayload(entry, replyPub, toolResults);
  const envelope = await seal(
    enclavePublicKey,
    utf8.encode(ENRICH_REQUEST_INFO),
    utf8.encode(requestPayload),
  );

  const response = await fetch(`${apiEndpoint}/enrich`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(envelope),
  });

  if (!response.ok) {
    throw new Error(`enrich failed: HTTP ${response.status} ${await response.text()}`);
  }

  const reply = (await response.json()) as Envelope;
  const plaintext = await open(replyKeyPair.privateKey, reply, utf8.encode(ENRICH_RESPONSE_INFO));
  return JSON.parse(new TextDecoder().decode(plaintext)) as HarnessTurn;
}

/**
 * Enrich one saved entry: send it to the enclave and, while the enclave asks
 * for client tools (it ends with `attach_metadata`), execute them locally and
 * feed the results back, until it returns a final acknowledgement.
 */
export async function enrichEntry(
  apiEndpoint: string,
  enclavePublicKey: Uint8Array,
  entry: EnrichEntry,
  options: EnrichOptions,
): Promise<string> {
  return runToolLoop(
    (toolResults) => sendTurn(apiEndpoint, enclavePublicKey, entry, toolResults),
    options,
  );
}
