// design-sync bundle entry (cfg.entry).
//
// This app has no library build — its components live in src/ and are mounted
// by main.tsx, which has side effects (ReactDOM.createRoot().render()). This
// barrel re-exports ONLY the components we sync, so the design-sync bundle
// pulls in their real, shipped code without ever evaluating main.tsx. Walking
// up from this file's location also lets the converter resolve the package
// root (frontend/), so src/, styles.css, and node_modules all resolve with
// portable relative paths. Keep it in lockstep with cfg.componentSrcMap.
export { AttestationBadge } from "../src/components/AttestationBadge";
export { ChatPane } from "../src/components/ChatPane";
export { JournalView } from "../src/components/JournalView";
export { KnowMorePage } from "../src/components/KnowMorePage";
export { PassphraseScreen } from "../src/components/PassphraseScreen";
