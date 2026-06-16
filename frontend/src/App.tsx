import { useEffect, useState } from "react";
import { JournalView } from "./components/JournalView";
import { KnowMorePage } from "./components/KnowMorePage";
import { PassphraseScreen } from "./components/PassphraseScreen";
import { type JournalDb, openJournalDb } from "./lib/store";

function useHash() {
  const [hash, setHash] = useState(() => window.location.hash);
  useEffect(() => {
    const handler = () => setHash(window.location.hash);
    window.addEventListener("hashchange", handler);
    return () => window.removeEventListener("hashchange", handler);
  }, []);
  return hash;
}

export function App() {
  const [db, setDb] = useState<JournalDb | null>(null);
  const [key, setKey] = useState<CryptoKey | null>(null);
  const hash = useHash();

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

  if (hash === "#know-more") {
    return (
      <KnowMorePage
        onBack={() => {
          window.location.hash = "";
        }}
      />
    );
  }

  if (db === null) return <main className="centered">Opening journal…</main>;

  if (key === null) {
    return <PassphraseScreen db={db} onUnlocked={setKey} />;
  }

  return <JournalView db={db} journalKey={key} onLock={() => setKey(null)} />;
}
