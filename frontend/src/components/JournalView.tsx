import { useCallback, useEffect, useRef, useState } from "react";
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
  const fileInput = useRef<HTMLInputElement>(null);

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

  async function handleSave() {
    const entry: JournalEntry =
      selected !== null
        ? { ...selected, title, body, updatedAt: new Date().toISOString() }
        : newEntry(title, body);
    await db.putEntry(journalKey, entry);
    await refresh();
    setSelectedId(entry.id);
    setStatus("Saved.");
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
                <span className="entry-title">{entry.title || "Untitled"}</span>
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

      <ChatPane />
    </div>
  );
}
