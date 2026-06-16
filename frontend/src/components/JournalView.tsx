import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { enrichEntry } from "../attest/enrich";
import { makeToolExecutor } from "../attest/tools";
import { useEnclaveSession } from "../attest/useEnclaveSession";
import { config } from "../lib/config";
import type { JournalDb } from "../lib/store";
import { type JournalEntry, newEntry } from "../lib/types";
import { ChatPane } from "./ChatPane";

interface Props {
  db: JournalDb;
  journalKey: CryptoKey;
  onLock: () => void;
}

export function JournalView({ db, journalKey, onLock }: Props) {
  const [entries, setEntries] = useState<JournalEntry[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  // Ids currently being enriched in the enclave (async, non-blocking).
  const [enriching, setEnriching] = useState<Set<string>>(new Set());
  const fileInput = useRef<HTMLInputElement>(null);

  // One verified enclave session shared by the chat pane and entry enrichment.
  const session = useEnclaveSession();
  const executeTool = useMemo(() => makeToolExecutor(db, journalKey), [db, journalKey]);

  const refresh = useCallback(async () => {
    setEntries(await db.listEntries(journalKey));
  }, [db, journalKey]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const selected = entries.find((e) => e.id === selectedId) ?? null;

  function select(entry: JournalEntry | null) {
    setSelectedId(entry?.id ?? null);
    setTitle(entry?.title ?? "");
    setBody(entry?.body ?? "");
    setStatus(null);
  }

  /**
   * Kick off enrichment for a saved entry in the background. Deliberately not
   * awaited by `handleSave`: journal CRUD stays fully usable while the enclave
   * summarizes, extracts metadata, and embeds (issue #11). The enclave stores
   * the result via `attach_metadata`, so we just refresh once it lands.
   */
  async function startEnrichment(entry: JournalEntry) {
    if (session.status.kind !== "verified") return;
    if (entry.body.trim() === "" && entry.title.trim() === "") return;
    const hpkeKey = session.status.hpkePublicKey;
    setEnriching((prev) => new Set(prev).add(entry.id));
    try {
      await enrichEntry(
        config.apiEndpoint,
        hpkeKey,
        { id: entry.id, title: entry.title, body: entry.body },
        { executeTool },
      );
      await refresh();
    } catch (err) {
      // Enrichment is best-effort: a failure leaves the entry intact, just
      // without metadata. Surface it quietly without blocking the journal.
      console.error("enrichment failed", err);
    } finally {
      setEnriching((prev) => {
        const next = new Set(prev);
        next.delete(entry.id);
        return next;
      });
    }
  }

  async function handleSave() {
    const entry: JournalEntry =
      selected !== null
        ? { ...selected, title, body, updatedAt: new Date().toISOString() }
        : newEntry(title, body);
    await db.putEntry(journalKey, entry);
    await refresh();
    setSelectedId(entry.id);
    setStatus(session.status.kind === "verified" ? "Saved. Enriching privately…" : "Saved.");
    // Fire-and-forget: do not await, so saving stays instant.
    void startEnrichment(entry);
  }

  async function handleDelete() {
    if (selected === null) return;
    if (!window.confirm(`Delete "${selected.title || "Untitled"}"? This cannot be undone.`)) {
      return;
    }
    await db.deleteEntry(selected.id);
    await refresh();
    select(null);
  }

  async function handleExport() {
    const bytes = await db.exportJournal();
    const blob = new Blob([bytes as BlobPart], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `journal-${new Date().toISOString().slice(0, 10)}.tee-journal.json`;
    link.click();
    URL.revokeObjectURL(url);
    setStatus("Exported encrypted journal file.");
  }

  async function handleImport(file: File) {
    if (!window.confirm("Importing replaces the journal stored in this browser. Continue?")) {
      return;
    }
    try {
      await db.importJournal(new Uint8Array(await file.arrayBuffer()));
      // The imported journal has its own salt/passphrase; force a re-unlock.
      onLock();
    } catch (err) {
      setStatus("That file doesn't look like a journal export.");
      console.error(err);
    }
  }

  return (
    <div className="journal">
      <aside className="sidebar">
        <header>
          <h1>Journal</h1>
          <button onClick={() => select(null)}>New entry</button>
        </header>
        <ul className="entry-list">
          {entries.map((entry) => (
            <li key={entry.id}>
              <button
                className={entry.id === selectedId ? "entry-link selected" : "entry-link"}
                onClick={() => select(entry)}
              >
                <span className="entry-title">
                  {entry.title || "Untitled"}
                  {enriching.has(entry.id) ? (
                    <span className="entry-enriching" title="Enriching in the enclave…">
                      {" "}
                      ✨
                    </span>
                  ) : (
                    entry.enrichment?.enrichedAt !== undefined && (
                      <span className="entry-enriched" title="Enriched by the enclave">
                        {" "}
                        🏷️
                      </span>
                    )
                  )}
                </span>
                <span className="entry-date">
                  {new Date(entry.createdAt).toLocaleDateString()}
                </span>
              </button>
            </li>
          ))}
          {entries.length === 0 && <li className="muted empty">No entries yet.</li>}
        </ul>
        <footer>
          <button className="secondary" onClick={() => void handleExport()}>
            Export
          </button>
          <button className="secondary" onClick={() => fileInput.current?.click()}>
            Import
          </button>
          <button className="secondary" onClick={onLock}>
            Lock
          </button>
          <input
            ref={fileInput}
            type="file"
            hidden
            onChange={(e) => {
              const file = e.target.files?.[0];
              e.target.value = "";
              if (file !== undefined) void handleImport(file);
            }}
          />
        </footer>
      </aside>

      <section className="editor">
        <input
          className="title-input"
          placeholder="Title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />
        <textarea
          className="body-input"
          placeholder="Write your entry…"
          value={body}
          onChange={(e) => setBody(e.target.value)}
        />
        <div className="editor-actions">
          <button onClick={() => void handleSave()} disabled={title === "" && body === ""}>
            {selected !== null ? "Save changes" : "Save entry"}
          </button>
          {selected !== null && (
            <button className="danger" onClick={() => void handleDelete()}>
              Delete
            </button>
          )}
          {status !== null && <span className="muted">{status}</span>}
        </div>
      </section>

      <ChatPane db={db} journalKey={journalKey} session={session} />
    </div>
  );
}
