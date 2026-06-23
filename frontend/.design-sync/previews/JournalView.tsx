// Authored preview — the full writing-first journal screen: the top bar, the
// collapsible entries rail, the hero editor, and the on-demand inspector drawer.
// db.listEntries() is stubbed with a few realistic entries so the rail populates;
// `initialSelectedId` focuses the first (enriched) entry so the editor and the
// inspector's metadata render (both only show for a selected entry, which
// production opens without). `initialInspectorOpen` + `initialInspectorTab`
// open the drawer on the Details tab so the design pass sees the new metadata UI
// (grid, enclave-notes, trust card); production opens with the drawer closed.
// The view runs its own enclave session internally, which can't reach an enclave
// at preview time, so the trust badge shows its "not verified" state — the honest
// offline render of this screen.
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

/** The writing-first journal: rail, hero editor, and the inspector drawer open
 *  on Details so the metadata grid, enclave notes, and trust card are styled. */
export const Default = () => (
  <JournalView
    db={db}
    journalKey={journalKey}
    onLock={() => {}}
    initialSelectedId="1"
    initialInspectorOpen
    initialInspectorTab="details"
  />
);
