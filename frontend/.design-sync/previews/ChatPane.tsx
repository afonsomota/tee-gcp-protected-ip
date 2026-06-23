// Authored preview — the enclave chat pane. Its transcript is internal state we
// can't seed via props, so the cells show the two empty-state shells the user
// first sees: chat enabled once the enclave is verified, and chat disabled while
// it isn't. db/journalKey are only closed over by the tool executor (never
// called at render), so inert stubs are fine; the session prop drives the badge
// and the enabled/disabled state.
import { ChatPane } from "tee-journal-frontend";

const db = {} as never;
const journalKey = {} as CryptoKey;

/** Enclave verified → chat enabled, end-to-end-encryption reassurance shown. */
export const Verified = () => (
  <ChatPane
    db={db}
    journalKey={journalKey}
    session={{
      status: { kind: "verified", signatureVerified: true, hpkePublicKey: {} },
      verify: async () => {},
    }}
  />
);

/** Enclave unreachable → chat disabled, the badge shows the failure. */
export const AwaitingVerification = () => (
  <ChatPane
    db={db}
    journalKey={journalKey}
    session={{
      status: {
        kind: "failed",
        code: "NETWORK_ERROR",
        detail: "connection refused — the enclave may be scaled to zero",
      },
      verify: async () => {},
    }}
  />
);
