/**
 * Client-side tool executor (issue #10).
 *
 * The enclave's harness can ask the browser to run a tool instead of replying.
 * Two tools live here, both bound to the user's *local* data (never the
 * enclave's):
 *
 *   - `search_entries`  — keyword/metadata search over IndexedDB. Returns only
 *                         the matched entries (top-k). This is the only path by
 *                         which entries leave the device for the enclave, so
 *                         the returned set IS the data-minimization boundary:
 *                         nothing else crosses.
 *   - `attach_metadata` — merge harness-provided enrichment into one stored
 *                         entry and re-encrypt it locally.
 *
 * Tool names, argument shapes, and loci mirror the launcher manifest
 * (`launcher/src/tools.rs`); the launcher re-validates every call before it
 * reaches us.
 *
 * Vector similarity for `search_entries` arrives in issue #11; for now it is
 * keyword + metadata matching.
 */
import type { JournalDb } from "../lib/store";
import type { EntryEnrichment, JournalEntry } from "../lib/types";

/** A tool call the harness emitted (already manifest-validated by the launcher). */
export interface ToolCall {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
}

/**
 * The outcome of running one tool: `result` is the JSON fed back to the enclave
 * for the next harness turn; `summary` is a human line for the chat UI so the
 * user can see exactly what left (or stayed on) their device.
 */
export interface ToolOutcome {
  result: unknown;
  summary: string;
}

export type ToolExecutor = (call: ToolCall) => Promise<ToolOutcome>;

const DEFAULT_SEARCH_LIMIT = 5;

/** What a matched entry looks like when it crosses to the enclave. */
interface MatchedEntry {
  id: string;
  title: string;
  body: string;
  createdAt: string;
  enrichment?: EntryEnrichment;
}

/**
 * Build an executor bound to the unlocked journal. The returned function reads
 * and writes only through `db` with the in-memory `key`, so plaintext entries
 * never leave the browser except as a tool's explicit result.
 */
export function makeToolExecutor(db: JournalDb, key: CryptoKey): ToolExecutor {
  return async (call: ToolCall): Promise<ToolOutcome> => {
    switch (call.name) {
      case "search_entries":
        return searchEntries(db, key, call.arguments);
      case "attach_metadata":
        return attachMetadata(db, key, call.arguments);
      default:
        // The launcher gates names against its manifest, so this is a
        // belt-and-braces guard against drift between the two sides.
        throw new Error(`unknown tool: ${call.name}`);
    }
  };
}

// Common words carry no search signal; dropping them keeps "how was my week?"
// from matching every entry on "my"/"was".
const STOPWORDS = new Set([
  "a", "about", "an", "and", "are", "as", "at", "be", "but", "by", "did", "do",
  "for", "from", "had", "has", "have", "how", "i", "in", "is", "it", "its", "me",
  "my", "of", "on", "or", "so", "that", "the", "this", "to", "was", "were",
  "what", "when", "where", "which", "who", "why", "with", "you", "your",
]);

function tokenize(text: string): string[] {
  return (text.toLowerCase().match(/[a-z0-9]+/g) ?? []).filter((t) => t.length > 1);
}

/** Everything a keyword can match against, lowercased. */
function haystack(entry: JournalEntry): string {
  const e = entry.enrichment;
  return [
    entry.title,
    entry.body,
    ...(e?.emotions ?? []),
    ...(e?.situations ?? []),
    ...(e?.lifePhases ?? []),
    e?.summary ?? "",
  ]
    .join(" ")
    .toLowerCase();
}

async function searchEntries(
  db: JournalDb,
  key: CryptoKey,
  args: Record<string, unknown>,
): Promise<ToolOutcome> {
  const query = typeof args.query === "string" ? args.query : "";
  const limit =
    typeof args.limit === "number" && args.limit > 0
      ? Math.floor(args.limit)
      : DEFAULT_SEARCH_LIMIT;

  const all = await db.listEntries(key); // already newest-first
  const keywords = tokenize(query).filter((t) => !STOPWORDS.has(t));

  let ranked: JournalEntry[];
  if (keywords.length === 0) {
    // No usable keywords (e.g. an all-stopword question): fall back to the most
    // recent entries so the assistant still has grounding — still top-k, still
    // only these cross the channel.
    ranked = all;
  } else {
    ranked = all
      .map((entry) => ({ entry, score: score(entry, keywords) }))
      .filter((r) => r.score > 0)
      .sort((a, b) => b.score - a.score || b.entry.createdAt.localeCompare(a.entry.createdAt))
      .map((r) => r.entry);
  }

  const matches: MatchedEntry[] = ranked.slice(0, limit).map((entry) => ({
    id: entry.id,
    title: entry.title,
    body: entry.body,
    createdAt: entry.createdAt,
    ...(entry.enrichment !== undefined ? { enrichment: entry.enrichment } : {}),
  }));

  return {
    result: { matches, count: matches.length },
    summary: summarizeSearch(query, matches),
  };
}

function score(entry: JournalEntry, keywords: string[]): number {
  const hay = haystack(entry);
  // Count distinct keywords present — presence, not frequency, so a long entry
  // doesn't dominate on one repeated word.
  return keywords.reduce((n, kw) => (hay.includes(kw) ? n + 1 : n), 0);
}

function summarizeSearch(query: string, matches: MatchedEntry[]): string {
  const q = query.trim();
  if (matches.length === 0) {
    return `Searched your entries${q ? ` for “${q}”` : ""} — 0 matches; nothing left your device.`;
  }
  const titles = matches.map((m) => `“${m.title || "Untitled"}”`).join(", ");
  return `Searched your entries${q ? ` for “${q}”` : ""} — sent ${matches.length} to the enclave: ${titles}.`;
}

async function attachMetadata(
  db: JournalDb,
  key: CryptoKey,
  args: Record<string, unknown>,
): Promise<ToolOutcome> {
  const entryId = typeof args.entry_id === "string" ? args.entry_id : "";
  const enrichment = isObject(args.enrichment) ? (args.enrichment as EntryEnrichment) : null;
  if (entryId === "" || enrichment === null) {
    return {
      result: { ok: false, error: "attach_metadata needs entry_id and an enrichment object" },
      summary: "Couldn't attach metadata: malformed request.",
    };
  }

  const entries = await db.listEntries(key);
  const entry = entries.find((e) => e.id === entryId);
  if (entry === undefined) {
    return {
      result: { ok: false, entry_id: entryId, error: "entry not found" },
      summary: `Couldn't attach metadata: no entry ${entryId}.`,
    };
  }

  const merged: JournalEntry = {
    ...entry,
    enrichment: {
      ...entry.enrichment,
      ...enrichment,
      enrichedAt: new Date().toISOString(),
    },
    updatedAt: new Date().toISOString(),
  };
  await db.putEntry(key, merged);

  return {
    result: { ok: true, entry_id: entryId },
    summary: `Saved metadata to “${entry.title || "Untitled"}” (stays encrypted on your device).`,
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
