// Authored preview — the local-first login/create screen. The screen calls
// db.hasJournal() to decide between "unlock an existing journal" and "create a
// new one"; the two cells stub that to show both copy variants. unlock/import
// are never invoked at render, so they're inert stubs.
import { PassphraseScreen } from "tee-journal-frontend";

const key = {} as CryptoKey;
const baseDb = {
  unlock: async () => ({ key }),
  importJournal: async () => {},
};
const noop = () => {};

/** A journal already exists in this browser → "Unlock". */
export const Unlock = () => (
  <PassphraseScreen db={{ ...baseDb, hasJournal: async () => true }} onUnlocked={noop} />
);

/** No journal yet → "Create journal" with the create-a-passphrase copy. */
export const CreateJournal = () => (
  <PassphraseScreen db={{ ...baseDb, hasJournal: async () => false }} onUnlocked={noop} />
);
