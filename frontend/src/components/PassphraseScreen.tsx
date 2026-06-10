import { type FormEvent, useEffect, useRef, useState } from "react";
import { type JournalDb, WrongPassphraseError } from "../lib/store";

interface Props {
  db: JournalDb;
  onUnlocked: (key: CryptoKey) => void;
}

/**
 * Login is key derivation: the passphrase is stretched with Argon2id into the
 * journal's AES key. No accounts, no server — just unlock (or create) the
 * local encrypted journal.
 */
export function PassphraseScreen({ db, onUnlocked }: Props) {
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [hasJournal, setHasJournal] = useState<boolean | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    void db.hasJournal().then(setHasJournal);
  }, [db]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (passphrase.length === 0 || busy) return;
    setBusy(true);
    setError(null);
    try {
      const { key } = await db.unlock(passphrase);
      onUnlocked(key);
    } catch (err) {
      if (err instanceof WrongPassphraseError) {
        setError("That passphrase doesn't unlock this journal. Please try again.");
      } else {
        setError("Something went wrong while unlocking. Please try again.");
        console.error(err);
      }
    } finally {
      setBusy(false);
    }
  }

  async function handleImport(file: File) {
    if (
      hasJournal === true &&
      !window.confirm("Importing replaces the journal stored in this browser. Continue?")
    ) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await db.importJournal(new Uint8Array(await file.arrayBuffer()));
      setHasJournal(true);
      setPassphrase("");
      setError(null);
    } catch (err) {
      setError("That file doesn't look like a journal export.");
      console.error(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="centered">
      <form className="passphrase-card" onSubmit={handleSubmit}>
        <h1>Private Journal</h1>
        <p className="muted">
          {hasJournal
            ? "Enter your passphrase to unlock your journal."
            : "Choose a passphrase to create a new encrypted journal. It never leaves this device — and it cannot be recovered if lost."}
        </p>
        <input
          type="password"
          autoFocus
          placeholder="Passphrase"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          disabled={busy}
        />
        {error !== null && <p className="error">{error}</p>}
        <button type="submit" disabled={busy || passphrase.length === 0}>
          {busy ? "Deriving key…" : hasJournal ? "Unlock" : "Create journal"}
        </button>
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={() => fileInput.current?.click()}
        >
          Import journal file…
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
      </form>
    </main>
  );
}
