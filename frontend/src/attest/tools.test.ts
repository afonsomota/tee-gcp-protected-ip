/**
 * The client-side tool executor (issue #10). Runs against a real (fake)
 * IndexedDB journal so the search/attach paths exercise the same store the app
 * uses. The contract these tests pin: only search-matched entries leave the
 * device, and attach_metadata writes harness-provided enrichment locally.
 */
import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it } from "vitest";
import { openJournalDb, type JournalDb } from "../lib/store";
import { newEntry, type JournalEntry } from "../lib/types";
import { makeToolExecutor, type ToolExecutor } from "./tools";

const testParams = { memorySizeKib: 1024, iterations: 2, parallelism: 1 };

let n = 0;
const freshName = () => `tool-journal-${++n}`;

// Seed a journal with three entries on distinct topics, oldest first by the
// timestamps we set (store sorts newest-first on read).
async function seededJournal(): Promise<{ db: JournalDb; key: CryptoKey; ids: Record<string, string> }> {
  const db = await openJournalDb(freshName());
  const { key } = await db.unlock("pw", testParams);

  const make = (title: string, body: string, createdAt: string): JournalEntry => ({
    ...newEntry(title, body),
    createdAt,
    updatedAt: createdAt,
  });

  const cooking = make("Sunday roast", "spent the afternoon cooking a big roast dinner", "2026-01-01T00:00:00Z");
  const work = make("New job", "first week at the new job, nervous but excited", "2026-02-01T00:00:00Z");
  const garden = make("Tomatoes", "planted tomatoes in the garden", "2026-03-01T00:00:00Z");
  for (const e of [cooking, work, garden]) await db.putEntry(key, e);

  return { db, key, ids: { cooking: cooking.id, work: work.id, garden: garden.id } };
}

describe("search_entries", () => {
  let executor: ToolExecutor;
  let ids: Record<string, string>;

  beforeEach(async () => {
    const j = await seededJournal();
    executor = makeToolExecutor(j.db, j.key);
    ids = j.ids;
  });

  it("returns only the keyword-matched entries, not the whole journal", async () => {
    const { result, summary } = await executor({
      id: "1",
      name: "search_entries",
      arguments: { query: "new job nerves" },
    });
    const r = result as { matches: { id: string; title: string }[]; count: number };
    expect(r.count).toBe(1);
    expect(r.matches[0].id).toBe(ids.work);
    // The data-minimization guarantee is observable in the summary line.
    expect(summary).toContain("sent 1 to the enclave");
    expect(summary).toContain("New job");
  });

  it("matches against enrichment metadata, not just title/body", async () => {
    const j = await seededJournal();
    const exec = makeToolExecutor(j.db, j.key);
    const entries = await j.db.listEntries(j.key);
    const target = entries.find((e) => e.id === j.ids.garden)!;
    await j.db.putEntry(j.key, { ...target, enrichment: { situations: ["mindfulness"] } });

    const { result } = await exec({
      id: "1",
      name: "search_entries",
      arguments: { query: "mindfulness" },
    });
    const r = result as { matches: { id: string }[] };
    expect(r.matches.map((m) => m.id)).toEqual([j.ids.garden]);
  });

  it("honours the limit (top-k)", async () => {
    const { result } = await executor({
      id: "1",
      name: "search_entries",
      arguments: { query: "cooking job garden tomatoes roast", limit: 2 },
    });
    const r = result as { matches: unknown[]; count: number };
    expect(r.count).toBe(2);
  });

  it("falls back to most-recent entries when the query is all stopwords", async () => {
    const { result } = await executor({
      id: "1",
      name: "search_entries",
      arguments: { query: "how are you?", limit: 2 },
    });
    const r = result as { matches: { id: string }[] };
    // Newest two: tomatoes (Mar), new job (Feb).
    expect(r.matches.map((m) => m.id)).toEqual([ids.garden, ids.work]);
  });

  it("returns nothing — and says so — when no entry matches", async () => {
    const { result, summary } = await executor({
      id: "1",
      name: "search_entries",
      arguments: { query: "skydiving" },
    });
    expect((result as { count: number }).count).toBe(0);
    expect(summary).toContain("nothing left your device");
  });
});

describe("attach_metadata", () => {
  it("merges harness-provided enrichment into the stored, encrypted entry", async () => {
    const { db, key, ids } = await seededJournal();
    const executor = makeToolExecutor(db, key);

    const { result, summary } = await executor({
      id: "1",
      name: "attach_metadata",
      arguments: {
        entry_id: ids.work,
        enrichment: { emotions: ["excited", "nervous"], summary: "starting a new job" },
      },
    });
    expect(result).toMatchObject({ ok: true, entry_id: ids.work });
    expect(summary).toContain("Saved metadata");

    const entries = await db.listEntries(key);
    const enriched = entries.find((e) => e.id === ids.work)!;
    expect(enriched.enrichment?.emotions).toEqual(["excited", "nervous"]);
    expect(enriched.enrichment?.summary).toBe("starting a new job");
    expect(enriched.enrichment?.enrichedAt).toBeDefined();
  });

  it("reports ok:false for an unknown entry instead of throwing", async () => {
    const { db, key } = await seededJournal();
    const executor = makeToolExecutor(db, key);
    const { result } = await executor({
      id: "1",
      name: "attach_metadata",
      arguments: { entry_id: "does-not-exist", enrichment: { summary: "x" } },
    });
    expect(result).toMatchObject({ ok: false });
  });
});

describe("unknown tool", () => {
  it("rejects a tool the executor does not implement", async () => {
    const { db, key } = await seededJournal();
    const executor = makeToolExecutor(db, key);
    await expect(
      executor({ id: "1", name: "exfiltrate", arguments: {} }),
    ).rejects.toThrow(/unknown tool/);
  });
});
