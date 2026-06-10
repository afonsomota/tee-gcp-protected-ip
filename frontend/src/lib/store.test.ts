import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { WrongPassphraseError, openJournalDb } from "./store";
import { newEntry } from "./types";

// Small Argon2id parameters to keep the suite fast. They are persisted in the
// journal metadata at creation time, so later unlocks pick them up on their own.
const testParams = { memorySizeKib: 1024, iterations: 2, parallelism: 1 };

let n = 0;
const freshName = () => `test-journal-${++n}`;

describe("unlock (login is key derivation)", () => {
  it("creates a journal on first unlock and opens it on the next", async () => {
    const name = freshName();
    const db = await openJournalDb(name);
    const first = await db.unlock("open sesame", testParams);
    expect(first.created).toBe(true);
    db.close();

    const reopened = await openJournalDb(name);
    const second = await reopened.unlock("open sesame");
    expect(second.created).toBe(false);
    reopened.close();
  });

  it("rejects a wrong passphrase with WrongPassphraseError", async () => {
    const db = await openJournalDb(freshName());
    await db.unlock("right", testParams);
    await expect(db.unlock("wrong")).rejects.toBeInstanceOf(WrongPassphraseError);
    db.close();
  });
});

describe("entry CRUD", () => {
  it("creates, reads, updates and deletes entries", async () => {
    const db = await openJournalDb(freshName());
    const { key } = await db.unlock("pw", testParams);

    const a = newEntry("First", "body one");
    const b = newEntry("Second", "body two");
    await db.putEntry(key, a);
    await db.putEntry(key, b);

    let entries = await db.listEntries(key);
    expect(entries.map((e) => e.title).sort()).toEqual(["First", "Second"]);

    await db.putEntry(key, { ...a, body: "edited", updatedAt: new Date().toISOString() });
    entries = await db.listEntries(key);
    expect(entries.find((e) => e.id === a.id)?.body).toBe("edited");

    await db.deleteEntry(b.id);
    entries = await db.listEntries(key);
    expect(entries.map((e) => e.id)).toEqual([a.id]);
    db.close();
  });

  it("persists entries across close/reopen (page reload)", async () => {
    const name = freshName();
    const db = await openJournalDb(name);
    const { key } = await db.unlock("pw", testParams);
    const entry = newEntry("Survives reload", "still here");
    entry.enrichment = { emotions: ["calm"], summary: "a short day" };
    await db.putEntry(key, entry);
    db.close();

    const reopened = await openJournalDb(name);
    const { key: key2 } = await reopened.unlock("pw");
    const entries = await reopened.listEntries(key2);
    expect(entries).toEqual([entry]);
    reopened.close();
  });
});

describe("everything at rest is ciphertext", () => {
  it("stores no readable plaintext in IndexedDB records", async () => {
    const name = freshName();
    const db = await openJournalDb(name);
    const { key } = await db.unlock("pw", testParams);
    const entry = newEntry("SECRET-TITLE", "SECRET-BODY");
    await db.putEntry(key, entry);
    db.close();

    // Read the raw database, as devtools would.
    const raw = indexedDB.open(name);
    const rawDb = await new Promise<IDBDatabase>((resolve, reject) => {
      raw.onsuccess = () => resolve(raw.result);
      raw.onerror = () => reject(raw.error);
    });
    const dump: unknown[] = [];
    for (const storeName of Array.from(rawDb.objectStoreNames)) {
      const tx = rawDb.transaction(storeName, "readonly");
      const all = tx.objectStore(storeName).getAll();
      const keys = tx.objectStore(storeName).getAllKeys();
      await new Promise((resolve, reject) => {
        tx.oncomplete = resolve;
        tx.onerror = () => reject(tx.error);
      });
      dump.push(all.result, keys.result);
    }
    rawDb.close();

    const rendered = JSON.stringify(dump, (_, v) =>
      v instanceof Uint8Array || v instanceof ArrayBuffer
        ? new TextDecoder().decode(v instanceof ArrayBuffer ? new Uint8Array(v) : v)
        : v,
    );
    expect(rendered).not.toContain("SECRET-TITLE");
    expect(rendered).not.toContain("SECRET-BODY");
    expect(rendered).not.toContain(entry.createdAt);
    expect(rendered).not.toContain("pw");
  });
});

describe("export / import", () => {
  it("restores an exported journal in a fresh profile with the same passphrase", async () => {
    const source = await openJournalDb(freshName());
    const { key } = await source.unlock("travel pw", testParams);
    const entry = newEntry("Packed", "ready to move");
    await source.putEntry(key, entry);
    const file = await source.exportJournal();
    source.close();

    // "Fresh browser profile" = brand new, empty database.
    const target = await openJournalDb(freshName());
    await target.importJournal(file);
    const { key: key2, created } = await target.unlock("travel pw");
    expect(created).toBe(false);
    expect(await target.listEntries(key2)).toEqual([entry]);
    target.close();
  });

  it("export file contains no plaintext, and a wrong passphrase still fails after import", async () => {
    const source = await openJournalDb(freshName());
    const { key } = await source.unlock("travel pw", testParams);
    await source.putEntry(key, newEntry("EXPORT-SECRET", "EXPORT-BODY"));
    const file = await source.exportJournal();
    source.close();

    const text = new TextDecoder().decode(file);
    expect(text).not.toContain("EXPORT-SECRET");
    expect(text).not.toContain("EXPORT-BODY");

    const target = await openJournalDb(freshName());
    await target.importJournal(file);
    await expect(target.unlock("not the travel pw")).rejects.toBeInstanceOf(
      WrongPassphraseError,
    );
    target.close();
  });

  it("rejects garbage import files without touching the existing journal", async () => {
    const db = await openJournalDb(freshName());
    const { key } = await db.unlock("pw", testParams);
    await db.putEntry(key, newEntry("Keep me", "intact"));

    await expect(db.importJournal(new TextEncoder().encode("not an export"))).rejects.toThrow();

    const entries = await db.listEntries(key);
    expect(entries.map((e) => e.title)).toEqual(["Keep me"]);
    db.close();
  });
});
