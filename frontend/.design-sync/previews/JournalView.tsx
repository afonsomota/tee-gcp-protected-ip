// Authored preview — the full journal screen: entry list, editor, the "Enclave
// notes" enrichment panel, and the chat pane. db.listEntries() is stubbed with a
// few realistic entries so the sidebar populates; `initialSelectedId` focuses the
// first (enriched) entry so its editor and enrichment panel render — the panel
// only shows for a selected entry, which production opens without. The view runs
// its own enclave session internally, which can't reach an enclave at preview
// time, so the chat pane shows its "not verified" state — the honest offline
// render of this screen.
import { JournalView } from "tee-journal-frontend";

const entries = [
  {
    id: "1",
    title: "First week at the new job",
    body: "Overwhelming but good. Everyone has been patient while I find my footing.",
    createdAt: "2026-05-02T09:12:00.000Z",
    updatedAt: "2026-05-02T09:12:00.000Z",
    enrichment: {
      enrichedAt: "2026-05-02T09:13:00.000Z",
      emotions: ["anxiety", "hope"],
      situations: ["work"],
      lifePhases: ["career change"],
      summary: "Starting a new job; nervous but optimistic.",
      embedding: new Array(768).fill(0),
    },
  },
  {
    id: "2",
    title: "Weekend hike",
    body: "Took the long trail up to the ridge. Phone stayed in my pocket the whole time.",
    createdAt: "2026-05-10T18:30:00.000Z",
    updatedAt: "2026-05-10T18:30:00.000Z",
  },
  {
    id: "3",
    title: "Call with Mom",
    body: "We talked for an hour. I should do that more often.",
    createdAt: "2026-05-15T20:05:00.000Z",
    updatedAt: "2026-05-15T20:05:00.000Z",
    enrichment: { enrichedAt: "2026-05-15T20:06:00.000Z", emotions: ["warmth"] },
  },
];

const db = {
  listEntries: async () => entries,
} as never;
const journalKey = {} as CryptoKey;

/** The full three-pane journal: entry list, editor, and the private chat pane. */
export const Default = () => (
  <JournalView db={db} journalKey={journalKey} onLock={() => {}} initialSelectedId="1" />
);
