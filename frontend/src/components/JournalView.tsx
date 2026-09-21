import {
  type Ref,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { enrichEntry } from "../attest/enrich";
import { makeToolExecutor } from "../attest/tools";
import type { EnclaveSession } from "../attest/useEnclaveSession";
import { useEnclaveSession } from "../attest/useEnclaveSession";
import { config } from "../lib/config";
import type { JournalDb } from "../lib/store";
import { type JournalEntry, newEntry } from "../lib/types";
import { AttestationBadge, AttestationPill } from "./AttestationBadge";
import { ChatPane } from "./ChatPane";

type InspectorTab = "companion" | "details";

// Below this width the entries rail stops being a column and becomes an
// off-canvas drawer (must match the max-width: 900px block in styles.css).
const NARROW_QUERY = "(max-width: 900px)";

/** The breakpoint's MediaQueryList, or null where matchMedia is missing (jsdom). */
function narrowMedia(): MediaQueryList | null {
  return typeof window.matchMedia === "function" ? window.matchMedia(NARROW_QUERY) : null;
}

interface Props {
  db: JournalDb;
  journalKey: CryptoKey;
  onLock: () => void;
  /**
   * Entry to focus on first mount. Production omits this (the journal opens
   * with nothing selected); design-sync previews set it so the editor and the
   * inspector's metadata, which only render for a selected entry, are visible
   * to the design pass.
   */
  initialSelectedId?: string;
  /**
   * Open the inspector drawer on first mount. Production omits this (the journal
   * opens with a clean, writing-first focus view — the drawer closed); the
   * design-sync preview sets it so the design pass can style the drawer.
   */
  initialInspectorOpen?: boolean;
  /** Which inspector tab to show first. Preview-only, like the flags above. */
  initialInspectorTab?: InspectorTab;
}

export function JournalView({
  db,
  journalKey,
  onLock,
  initialSelectedId,
  initialInspectorOpen,
  initialInspectorTab,
}: Props) {
  const [entries, setEntries] = useState<JournalEntry[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(initialSelectedId ?? null);
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  // Ids currently being enriched in the enclave (async, non-blocking).
  const [enriching, setEnriching] = useState<Set<string>>(new Set());
  const fileInput = useRef<HTMLInputElement>(null);
  const trustCard = useRef<HTMLDivElement>(null);
  const titleInput = useRef<HTMLTextAreaElement>(null);
  const bodyInput = useRef<HTMLTextAreaElement>(null);

  // Writing-first view state: a collapsible entries rail and an on-demand
  // inspector drawer (chat + details) that floats over the editor (issue: the
  // old three-pane layout crushed the editor). Defaults to a clean focus view.
  // On narrow screens both panes are drawers over the editor: the entries
  // drawer starts closed, and only one drawer is open at a time.
  const [narrow, setNarrow] = useState(() => narrowMedia()?.matches ?? false);
  const [sidebarOpen, setSidebarOpen] = useState(!narrow);
  const [inspectorOpen, setInspectorOpen] = useState(initialInspectorOpen ?? false);
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>(
    initialInspectorTab ?? "companion",
  );
  const [query, setQuery] = useState("");

  // One verified enclave session shared by the chat pane and entry enrichment.
  const session = useEnclaveSession();
  const executeTool = useMemo(() => makeToolExecutor(db, journalKey), [db, journalKey]);

  const refresh = useCallback(async () => {
    setEntries(await db.listEntries(journalKey));
  }, [db, journalKey]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Populate the editor for an entry focused via `initialSelectedId` once the
  // list loads. No-op in production, where `initialSelectedId` is undefined.
  const seededEditor = useRef(false);
  useEffect(() => {
    if (seededEditor.current || initialSelectedId === undefined) return;
    const entry = entries.find((e) => e.id === initialSelectedId);
    if (entry === undefined) return;
    seededEditor.current = true;
    setTitle(entry.title);
    setBody(entry.body);
  }, [entries, initialSelectedId]);

  // Crossing the breakpoint resets the rail to that layout's default.
  useEffect(() => {
    const mq = narrowMedia();
    if (mq === null) return;
    const onChange = () => {
      setNarrow(mq.matches);
      setSidebarOpen(!mq.matches);
    };
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  // Escape dismisses whatever is floating over the editor. Only listens while
  // something is; ignores Escapes that belong to an IME or another handler.
  const floating = inspectorOpen || (narrow && sidebarOpen);
  useEffect(() => {
    if (!floating) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || e.isComposing || e.defaultPrevented) return;
      setInspectorOpen(false);
      if (narrow) setSidebarOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [floating, narrow]);

  // The title is a one-row textarea that grows to show a long title in full (an
  // <input> clips it). Its height follows its content: refit when the text
  // changes and when its width does (window resize, rail collapse).
  const fitTitle = useCallback(() => {
    const el = titleInput.current;
    if (el === null) return;
    el.style.height = "auto";
    el.style.height = `${el.scrollHeight}px`;
  }, []);
  useLayoutEffect(fitTitle, [fitTitle, title]);
  useEffect(() => {
    const el = titleInput.current;
    if (el === null || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(fitTitle);
    observer.observe(el);
    return () => observer.disconnect();
  }, [fitTitle]);

  const selected = entries.find((e) => e.id === selectedId) ?? null;

  // Live word count / reading time for the editor meta line (issue: surface the
  // writing stats the redesign calls for — derived, never stored).
  const words = countWords(body);
  const readMinutes = readingMinutes(words);

  // Entries the rail shows: a real title/body search filter, grouped by recency.
  const visible = useMemo(() => filterEntries(entries, query), [entries, query]);
  const groups = useMemo(() => groupByRecency(visible), [visible]);

  function select(entry: JournalEntry | null) {
    setSelectedId(entry?.id ?? null);
    setTitle(entry?.title ?? "");
    setBody(entry?.body ?? "");
    setStatus(null);
    if (narrow) setSidebarOpen(false);
  }

  function toggleSidebar() {
    if (narrow && !sidebarOpen) setInspectorOpen(false);
    setSidebarOpen((o) => !o);
  }

  function openInspector(tab: InspectorTab) {
    setInspectorTab(tab);
    setInspectorOpen(true);
    if (narrow) setSidebarOpen(false);
  }

  // The compact header badge leads to the full one, which sits at the bottom of
  // the Details tab — scroll it into view once that tab has rendered.
  function showTrustCard() {
    openInspector("details");
    requestAnimationFrame(() => trustCard.current?.scrollIntoView({ block: "nearest" }));
  }

  // Inspector tab logic (shared by the header control and the in-drawer tabs):
  // clicking the tab the drawer is already open on closes it; otherwise open the
  // drawer on that tab.
  function pickTab(tab: InspectorTab) {
    if (inspectorOpen && inspectorTab === tab) {
      setInspectorOpen(false);
    } else {
      openInspector(tab);
    }
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
      <header className="topbar">
        <div className="topbar-group">
          <button
            type="button"
            className="icon-button"
            aria-label={sidebarOpen ? "Collapse entries" : "Expand entries"}
            aria-expanded={sidebarOpen}
            onClick={toggleSidebar}
          >
            <span className="hamburger" aria-hidden="true" />
          </button>
          <span className="brand">
            <span className="brand-mark" aria-hidden="true" />
            <span className="brand-name">Journal</span>
          </span>
          <AttestationBadge status={session.status} onRetry={() => void session.verify()} />
          <AttestationPill status={session.status} onOpen={showTrustCard} />
        </div>
        <div className="topbar-group">
          <div className="seg" role="tablist" aria-label="Inspector">
            <button
              type="button"
              role="tab"
              aria-selected={inspectorOpen && inspectorTab === "companion"}
              className={
                inspectorOpen && inspectorTab === "companion" ? "seg-btn active" : "seg-btn"
              }
              onClick={() => pickTab("companion")}
            >
              Companion
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={inspectorOpen && inspectorTab === "details"}
              className={
                inspectorOpen && inspectorTab === "details" ? "seg-btn active" : "seg-btn"
              }
              onClick={() => pickTab("details")}
            >
              Details
            </button>
          </div>
          {/* Phones: the segmented control doesn't fit, so one button stands in. */}
          <button
            type="button"
            className="icon-button inspector-toggle"
            aria-label={inspectorOpen ? "Close inspector panel" : "Open inspector panel"}
            aria-expanded={inspectorOpen}
            onClick={() => pickTab(inspectorTab)}
          >
            <span className="panel-icon" aria-hidden="true" />
          </button>
        </div>
      </header>

      <div className="journal-body">
        <aside
          className={sidebarOpen ? "sidebar" : "sidebar sidebar--collapsed"}
          inert={narrow && !sidebarOpen}
        >
          {/* A closed drawer keeps its contents (no dot rail) so it slides out intact. */}
          {sidebarOpen || narrow ? (
            <>
              <div className="sidebar-head">
                <span className="rail-label">Entries</span>
                <button className="secondary" onClick={() => select(null)}>
                  + New
                </button>
              </div>
              <input
                className="rail-search"
                placeholder="Search entries…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              <div className="entry-list">
                {groups.length === 0 && (
                  <p className="muted empty">{query === "" ? "No entries yet." : "No matches."}</p>
                )}
                {groups.map(([label, groupEntries]) => (
                  <div className="entry-group" key={label}>
                    <span className="entry-group-label">{label}</span>
                    {groupEntries.map((entry) => (
                      <button
                        key={entry.id}
                        className={entry.id === selectedId ? "entry-link selected" : "entry-link"}
                        onClick={() => select(entry)}
                      >
                        <span className="entry-date">
                          {new Date(entry.createdAt).toLocaleDateString()}
                          {enriching.has(entry.id) ? (
                            <span className="entry-enriching" title="Enriching in the enclave…">
                              {" ✨"}
                            </span>
                          ) : (
                            entry.enrichment?.enrichedAt !== undefined && (
                              <span className="entry-enriched" title="Enriched by the enclave">
                                {" 🏷️"}
                              </span>
                            )
                          )}
                        </span>
                        <span className="entry-title">{entry.title || "Untitled"}</span>
                        {entry.body.trim() !== "" && (
                          <span className="entry-preview muted">{entry.body}</span>
                        )}
                      </button>
                    ))}
                  </div>
                ))}
              </div>
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
            </>
          ) : (
            <div className="rail-collapsed">
              <button
                type="button"
                className="icon-button"
                title="New entry"
                aria-label="New entry"
                onClick={() => select(null)}
              >
                +
              </button>
              <div className="rail-divider" />
              <div className="rail-dots">
                {visible.map((entry) => {
                  const enriched = entry.enrichment?.enrichedAt !== undefined;
                  return (
                    <button
                      key={entry.id}
                      type="button"
                      className={
                        "rail-dot" +
                        (entry.id === selectedId ? " selected" : "") +
                        (enriched ? " enriched" : "")
                      }
                      title={`${entry.title || "Untitled"}${enriched ? " · enriched" : ""}`}
                      aria-label={entry.title || "Untitled"}
                      onClick={() => select(entry)}
                    />
                  );
                })}
              </div>
            </div>
          )}
        </aside>

        {/* Behind the scrim the editor is out of reach for Tab too. */}
        <main className="editor" inert={narrow && (sidebarOpen || inspectorOpen)}>
          <div className="editor-meta">
            <span>{selected !== null ? formatDate(selected.createdAt) : "New entry"}</span>
            <span>
              {words} {words === 1 ? "word" : "words"} · {readMinutes} min
            </span>
          </div>
          <div className="editor-surface">
            <article className="editor-article">
              <textarea
                ref={titleInput}
                className="title-input"
                placeholder="Title"
                rows={1}
                value={title}
                // Still a single line of text: pasted newlines become spaces and
                // Enter moves on to the body. The DOM value is cleaned in place so
                // React sees no mismatch and the caret stays where the paste ended.
                onChange={(e) => {
                  const el = e.target;
                  const clean = el.value.replace(/\r?\n/g, " ");
                  if (clean !== el.value) {
                    const pos = el.selectionStart;
                    el.value = clean;
                    el.setSelectionRange(pos, pos);
                  }
                  setTitle(clean);
                }}
                onKeyDown={(e) => {
                  if (e.key !== "Enter" || e.nativeEvent.isComposing) return;
                  e.preventDefault();
                  bodyInput.current?.focus();
                }}
              />
              <textarea
                ref={bodyInput}
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
            </article>
          </div>
        </main>

        {narrow && (sidebarOpen || inspectorOpen) && (
          <div
            className="scrim"
            onClick={() => {
              setSidebarOpen(false);
              setInspectorOpen(false);
            }}
          />
        )}

        <aside
          className={inspectorOpen ? "inspector open" : "inspector"}
          aria-hidden={!inspectorOpen}
          inert={!inspectorOpen}
        >
          <div className="inspector-head">
            <div className="seg" role="tablist" aria-label="Inspector tabs">
              <button
                type="button"
                role="tab"
                aria-selected={inspectorTab === "companion"}
                className={inspectorTab === "companion" ? "seg-btn active" : "seg-btn"}
                onClick={() => pickTab("companion")}
              >
                Companion
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={inspectorTab === "details"}
                className={inspectorTab === "details" ? "seg-btn active" : "seg-btn"}
                onClick={() => pickTab("details")}
              >
                Details
              </button>
            </div>
            <button
              type="button"
              className="icon-button"
              aria-label="Close inspector"
              onClick={() => setInspectorOpen(false)}
            >
              ×
            </button>
          </div>
          <div className="inspector-body">
            {inspectorTab === "companion" ? (
              <div className="companion">
                {selected !== null && (
                  <div className="companion-context muted" title={selected.title || "Untitled"}>
                    Reading · {selected.title || "Untitled"}
                  </div>
                )}
                <ChatPane db={db} journalKey={journalKey} session={session} embedded />
              </div>
            ) : (
              <DetailsTab selected={selected} session={session} trustCardRef={trustCard} />
            )}
          </div>
        </aside>
      </div>
    </div>
  );
}

/** The inspector's "Details" tab: real entry metadata + enclave enrichment. */
function DetailsTab({
  selected,
  session,
  trustCardRef,
}: {
  selected: JournalEntry | null;
  session: EnclaveSession;
  trustCardRef: Ref<HTMLDivElement>;
}) {
  const trustCard = (
    <div className="trust-card" ref={trustCardRef}>
      <AttestationBadge status={session.status} onRetry={() => void session.verify()} />
      <p className="muted">
        Stored only in this browser, encrypted with your passphrase. Enrichment and chat run
        inside the verified enclave — nothing is kept server-side.
      </p>
    </div>
  );
  // The trust card shows even with no entry selected: it is where the top bar's
  // compact badge sends people for the full status, Retry and "Know more".
  if (selected === null) {
    return (
      <div className="details">
        <p className="muted">Select an entry to see its details.</p>
        {trustCard}
      </div>
    );
  }
  const words = countWords(selected.body);
  const enr = selected.enrichment;
  return (
    <div className="details">
      <div className="details-entry">
        <span className="rail-label">Entry</span>
        <h3 className="details-title">{selected.title || "Untitled"}</h3>
      </div>

      <div className="meta-grid">
        <MetaCell k="Created" v={formatDate(selected.createdAt)} />
        <MetaCell k="Last edited" v={formatDate(selected.updatedAt)} />
        <MetaCell k="Words" v={String(words)} />
        <MetaCell k="Reading time" v={`${readingMinutes(words)} min`} />
        <MetaCell k="Entry id" v={selected.id} mono wide />
      </div>

      {enr !== undefined ? (
        <div className="details-enrichment">
          <span className="rail-label">🏷️ Enclave notes</span>
          {enr.summary !== undefined && <p className="enrichment-summary">{enr.summary}</p>}
          <TagRow label="Emotions" tags={enr.emotions} />
          <TagRow label="Situations" tags={enr.situations} />
          <TagRow label="Life phases" tags={enr.lifePhases} />
          {(enr.embedding !== undefined || enr.enrichedAt !== undefined) && (
            <p className="enrichment-meta muted">
              {enr.embedding !== undefined &&
                `Semantic embedding · ${enr.embedding.length} dimensions`}
              {enr.enrichedAt !== undefined &&
                `${enr.embedding !== undefined ? " · " : ""}enriched ${new Date(
                  enr.enrichedAt,
                ).toLocaleString()}`}
            </p>
          )}
        </div>
      ) : (
        <p className="muted">Not yet enriched by the enclave.</p>
      )}

      {trustCard}
    </div>
  );
}

/** One cell of the Details metadata grid: a small mono key over its value. */
function MetaCell({ k, v, mono, wide }: { k: string; v: string; mono?: boolean; wide?: boolean }) {
  return (
    <div className={wide === true ? "meta-cell meta-cell--wide" : "meta-cell"}>
      <span className="meta-key">{k}</span>
      <span className={mono === true ? "meta-val mono" : "meta-val"}>{v}</span>
    </div>
  );
}

/** One labelled row of enrichment tags; renders nothing when the list is empty. */
function TagRow({ label, tags }: { label: string; tags?: string[] }) {
  if (tags === undefined || tags.length === 0) return null;
  return (
    <div className="enrichment-tags">
      <span className="enrichment-tags-label">{label}</span>
      <span className="enrichment-tags-list">
        {tags.map((tag) => (
          <span key={tag} className="tag">
            {tag}
          </span>
        ))}
      </span>
    </div>
  );
}

function countWords(text: string): number {
  const trimmed = text.trim();
  return trimmed === "" ? 0 : trimmed.split(/\s+/).length;
}

/** Reading time in minutes at ~200 wpm, floored to a minimum of 1. */
function readingMinutes(words: number): number {
  return Math.max(1, Math.round(words / 200));
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    month: "long",
    day: "numeric",
    year: "numeric",
  });
}

function filterEntries(entries: JournalEntry[], query: string): JournalEntry[] {
  const q = query.trim().toLowerCase();
  if (q === "") return entries;
  return entries.filter((e) => `${e.title} ${e.body}`.toLowerCase().includes(q));
}

/**
 * Group entries into recency buckets for the rail, newest first. Buckets with
 * no entries are dropped, so labels only appear when they hold something.
 */
function groupByRecency(entries: JournalEntry[]): [string, JournalEntry[]][] {
  const sorted = [...entries].sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
  );
  const now = Date.now();
  const day = 86_400_000;
  const buckets: [string, JournalEntry[]][] = [
    ["This week", []],
    ["Earlier this month", []],
    ["Older", []],
  ];
  for (const entry of sorted) {
    const age = now - new Date(entry.createdAt).getTime();
    const bucket = age < 7 * day ? buckets[0] : age < 30 * day ? buckets[1] : buckets[2];
    bucket[1].push(entry);
  }
  return buckets.filter(([, list]) => list.length > 0);
}
