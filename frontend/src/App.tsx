import { useEffect, useState } from "react";
import { JournalView } from "./components/JournalView";
import { PassphraseScreen } from "./components/PassphraseScreen";
import { type JournalDb, openJournalDb } from "./lib/store";

export function App() {
  const [db, setDb] = useState<JournalDb | null>(null);
  const [key, setKey] = useState<CryptoKey | null>(null);

  useEffect(() => {
    let cancelled = false;
    let opened: JournalDb | null = null;
    void openJournalDb().then((journalDb) => {
      if (cancelled) {
        journalDb.close();
      } else {
        opened = journalDb;
        setDb(journalDb);
      }
    });
    return () => {
      cancelled = true;
      opened?.close();
    };
  }, []);

  if (db === null) return <main className="centered">Opening journal…</main>;

  if (key === null) {
    return <PassphraseScreen db={db} onUnlocked={setKey} />;
  }

  return <JournalView db={db} journalKey={key} onLock={() => setKey(null)} />;
}
