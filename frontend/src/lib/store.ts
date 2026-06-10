/**
 * Encrypted journal storage over IndexedDB, independent of React.
 *
 * At rest the database holds only:
 *   - `meta/kdf`: the Argon2id salt + params and an encrypted check value
 *   - `entries/<id>`: AES-GCM ciphertext of the serialized JournalEntry
 *
 * Entry ids are opaque UUIDs; titles, bodies and timestamps live inside the
 * ciphertext. Nothing here is readable without the passphrase.
 *
 * Export/import moves the same ciphertext (plus the KDF material) as a single
 * file, so a journal can be restored in a fresh browser profile and unlocked
 * with the original passphrase.
 */
import { openDB, type IDBPDatabase } from "idb";
import {
  type Argon2Params,
  DEFAULT_ARGON2_PARAMS,
  createCheckValue,
  decryptJson,
  deriveKey,
  encryptJson,
  generateSalt,
  verifyCheckValue,
} from "./crypto";
import type { JournalEntry } from "./types";

const META_STORE = "meta";
const ENTRIES_STORE = "entries";
const KDF_META_KEY = "kdf";

export const DEFAULT_DB_NAME = "tee-journal";
const EXPORT_FORMAT = "tee-journal-export";
const EXPORT_VERSION = 1;

export class WrongPassphraseError extends Error {
  constructor() {
    super("Wrong passphrase for this journal");
    this.name = "WrongPassphraseError";
  }
}

export class ImportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ImportError";
  }
}

interface KdfMeta {
  salt: Uint8Array;
  check: Uint8Array;
  params: Argon2Params;
}

export interface UnlockResult {
  key: CryptoKey;
  /** True when this unlock created a brand-new journal. */
  created: boolean;
}

interface ExportFile {
  format: typeof EXPORT_FORMAT;
  version: typeof EXPORT_VERSION;
  kdf: { salt: string; check: string; params: Argon2Params };
  entries: { id: string; data: string }[];
}

export interface JournalDb {
  /** Derive the key; create the journal on first use, verify it afterwards. */
  unlock(passphrase: string, params?: Argon2Params): Promise<UnlockResult>;
  hasJournal(): Promise<boolean>;
  listEntries(key: CryptoKey): Promise<JournalEntry[]>;
  putEntry(key: CryptoKey, entry: JournalEntry): Promise<void>;
  deleteEntry(id: string): Promise<void>;
  exportJournal(): Promise<Uint8Array>;
  importJournal(file: Uint8Array): Promise<void>;
  close(): void;
}

export async function openJournalDb(name = DEFAULT_DB_NAME): Promise<JournalDb> {
  const db: IDBPDatabase = await openDB(name, 1, {
    upgrade(database) {
      database.createObjectStore(META_STORE);
      database.createObjectStore(ENTRIES_STORE);
    },
  });

  const getKdfMeta = (): Promise<KdfMeta | undefined> => db.get(META_STORE, KDF_META_KEY);

  return {
    async hasJournal() {
      return (await getKdfMeta()) !== undefined;
    },

    async unlock(passphrase, params = DEFAULT_ARGON2_PARAMS) {
      const existing = await getKdfMeta();
      if (existing === undefined) {
        const salt = generateSalt();
        const key = await deriveKey(passphrase, salt, params);
        const meta: KdfMeta = { salt, check: await createCheckValue(key), params };
        await db.put(META_STORE, meta, KDF_META_KEY);
        return { key, created: true };
      }
      const key = await deriveKey(passphrase, existing.salt, existing.params);
      if (!(await verifyCheckValue(key, existing.check))) throw new WrongPassphraseError();
      return { key, created: false };
    },

    async listEntries(key) {
      const blobs: Uint8Array[] = await db.getAll(ENTRIES_STORE);
      const entries = await Promise.all(
        blobs.map((blob) => decryptJson<JournalEntry>(key, blob)),
      );
      return entries.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    },

    async putEntry(key, entry) {
      await db.put(ENTRIES_STORE, await encryptJson(key, entry), entry.id);
    },

    async deleteEntry(id) {
      await db.delete(ENTRIES_STORE, id);
    },

    async exportJournal() {
      const kdf = await getKdfMeta();
      if (kdf === undefined) throw new Error("Nothing to export: no journal exists yet");
      const tx = db.transaction(ENTRIES_STORE, "readonly");
      const [blobs, ids] = await Promise.all([
        tx.store.getAll() as Promise<Uint8Array[]>,
        tx.store.getAllKeys() as Promise<string[]>,
      ]);
      const file: ExportFile = {
        format: EXPORT_FORMAT,
        version: EXPORT_VERSION,
        kdf: { salt: toBase64(kdf.salt), check: toBase64(kdf.check), params: kdf.params },
        entries: ids.map((id, i) => ({ id, data: toBase64(blobs[i]) })),
      };
      return new TextEncoder().encode(JSON.stringify(file, null, 2));
    },

    async importJournal(fileBytes) {
      const file = parseExportFile(fileBytes);
      // Validation happened above; only now replace the existing journal.
      const tx = db.transaction([META_STORE, ENTRIES_STORE], "readwrite");
      const meta = tx.objectStore(META_STORE);
      const entries = tx.objectStore(ENTRIES_STORE);
      await Promise.all([meta.clear(), entries.clear()]);
      const kdf: KdfMeta = {
        salt: fromBase64(file.kdf.salt),
        check: fromBase64(file.kdf.check),
        params: file.kdf.params,
      };
      await meta.put(kdf, KDF_META_KEY);
      await Promise.all(file.entries.map((e) => entries.put(fromBase64(e.data), e.id)));
      await tx.done;
    },

    close() {
      db.close();
    },
  };
}

function parseExportFile(fileBytes: Uint8Array): ExportFile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(fileBytes));
  } catch {
    throw new ImportError("Not a journal export file (invalid JSON)");
  }
  const file = parsed as Partial<ExportFile>;
  if (file?.format !== EXPORT_FORMAT) throw new ImportError("Not a journal export file");
  if (file.version !== EXPORT_VERSION) {
    throw new ImportError(`Unsupported export version: ${String(file.version)}`);
  }
  const { kdf, entries } = file;
  if (
    typeof kdf?.salt !== "string" ||
    typeof kdf.check !== "string" ||
    typeof kdf.params?.memorySizeKib !== "number" ||
    typeof kdf.params.iterations !== "number" ||
    typeof kdf.params.parallelism !== "number" ||
    !Array.isArray(entries) ||
    entries.some((e) => typeof e?.id !== "string" || typeof e.data !== "string")
  ) {
    throw new ImportError("Corrupted journal export file");
  }
  return file as ExportFile;
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

function fromBase64(text: string): Uint8Array {
  let binary: string;
  try {
    binary = atob(text);
  } catch {
    throw new ImportError("Corrupted journal export file (bad base64)");
  }
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}
