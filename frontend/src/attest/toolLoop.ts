/**
 * The client-side tool loop, shared by `/chat` and `/enrich` (issue #11).
 *
 * The enclave's harness can ask the browser to run a tool instead of replying.
 * This drives that exchange: send a turn, and while the enclave asks for tools,
 * execute them locally and feed the results back, until it returns a reply.
 *
 * Both flows differ only in *what* they send each turn (a chat history vs. an
 * entry to enrich) — captured by the `sendTurn` callback — so the loop itself,
 * including which data crosses the channel and how tool activity is surfaced,
 * lives here once. Only the tool *results* (e.g. the search-matched entries)
 * ever leave the device; the rest of the journal never does.
 */
import type { ToolCall, ToolExecutor } from "./tools";

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

/** The enclave's per-turn reply: a final answer xor a batch of tool calls. */
export interface HarnessTurn {
  reply?: string;
  tool_calls?: ToolCall[];
}

export interface ToolLoopOptions {
  /** Runs a client-locus tool the enclave requested. Required if the harness
   *  emits tool calls (it does on every user/enrich turn). */
  executeTool?: ToolExecutor;
  /** Notified as each tool starts and finishes, for the UI. */
  onActivity?: (activity: ToolActivity) => void;
  /** Safety bound on harness↔client tool rounds before giving up. */
  maxToolRounds?: number;
}

export const DEFAULT_MAX_TOOL_ROUNDS = 4;

/**
 * Run a full turn: call `sendTurn` (which seals + posts the request and returns
 * the enclave's per-turn reply), and while the enclave asks for client tools,
 * execute them locally and feed the results back, until it returns a reply.
 */
export async function runToolLoop(
  sendTurn: (toolResults?: ToolResult[]) => Promise<HarnessTurn>,
  options: ToolLoopOptions = {},
): Promise<string> {
  const maxRounds = options.maxToolRounds ?? DEFAULT_MAX_TOOL_ROUNDS;
  let toolResults: ToolResult[] | undefined;

  for (let round = 0; round < maxRounds; round++) {
    const turn = await sendTurn(toolResults);

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

/** A human line for the chat UI describing a tool the moment it starts. */
export function describePending(call: ToolCall): string {
  if (call.name === "search_entries") {
    const query = typeof call.arguments.query === "string" ? call.arguments.query : "";
    return query ? `Searching your entries for “${query}”…` : "Searching your entries…";
  }
  if (call.name === "attach_metadata") {
    return "Saving notes to your local journal…";
  }
  return `Running ${call.name}…`;
}
