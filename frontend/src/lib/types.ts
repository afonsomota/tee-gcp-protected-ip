/**
 * Journal entry model.
 *
 * The whole object is serialized to JSON and encrypted before it touches
 * IndexedDB — only the opaque record id is visible in cleartext. Timestamps,
 * title, body and enrichment all live inside the ciphertext.
 */

/**
 * Enrichment metadata produced later by the enclave tools
 * (`extract_metadata`, `summarize`, `embed` — see issue 011).
 * All optional: entries created offline simply have none.
 */
export interface EntryEnrichment {
  /** Emotions detected in the entry (e.g. "joy", "anxiety"). */
  emotions?: string[];
  /** Situations / topics the entry talks about (e.g. "work", "family"). */
  situations?: string[];
  /** Life phases the entry relates to (e.g. "new job", "parenthood"). */
  lifePhases?: string[];
  /** Short model-generated summary of the entry. */
  summary?: string;
  /** Embedding vector for local similarity search. */
  embedding?: number[];
  /** When the enrichment was attached (ISO 8601). */
  enrichedAt?: string;
}

export interface JournalEntry {
  /** Opaque id; the only entry field stored in cleartext (as the DB key). */
  id: string;
  title: string;
  body: string;
  /** ISO 8601 — stored inside the ciphertext, not as a DB index. */
  createdAt: string;
  /** ISO 8601 — stored inside the ciphertext, not as a DB index. */
  updatedAt: string;
  enrichment?: EntryEnrichment;
}

export function newEntry(title: string, body: string): JournalEntry {
  const now = new Date().toISOString();
  return {
    id: crypto.randomUUID(),
    title,
    body,
    createdAt: now,
    updatedAt: now,
  };
}
