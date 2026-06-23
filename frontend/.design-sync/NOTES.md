# design-sync notes — tee-journal-frontend

Repo-specific gotchas for syncing this project to claude.ai/design. Read before
re-syncing.

## This is an app, not a component library

`tee-journal-frontend` is a Vite SPA, not a published component library. There is
**no library build** (`pnpm build` runs `tsc --noEmit && vite build` — an app
bundle, not component dist), no `exports`/`module`/`types` in package.json.
Consequences for the sync:

- **Synth/source build via a barrel entry.** `cfg.entry = .design-sync/ds-entry.tsx`
  re-exports only the 5 synced components. This (a) keeps `main.tsx`'s
  `createRoot().render()` side effect out of the bundle, and (b) anchors the
  converter's `PKG_DIR` to the frontend root via package.json walk-up, so
  `src/`, `cssEntry`, and `node_modules` resolve with portable relative paths.
  **Keep `ds-entry.tsx` in lockstep with `cfg.componentSrcMap`** when components
  are added/removed.
- **Prop contracts are authored, not extracted.** With no shipped `.d.ts`, the
  converter can't extract props, so `cfg.dtsPropsFor` hand-writes a clean,
  self-contained `<Name>Props` for each component (faithful to the real props,
  but opaque handles like the journal `db` and `CryptoKey` are simplified). If a
  component's real props change, update `dtsPropsFor` to match.
- `import.meta.env` is read at module load by `src/lib/config.ts`. The converter
  defines a synthetic Vite env under IIFE, so config loads with defaults
  (`apiEndpoint = http://localhost:8080`, empty digest/controller). No action.

## Component render notes

- **JournalView** calls `useEnclaveSession()` internally, which fetches the API
  on mount. In a headless/preview render the fetch fails and the session lands
  in the `failed` state — the layout still renders. No provider needed.
- **ChatPane** and **JournalView** are full-height 3-column / pane layouts
  (`height: 100vh`, `#root { min-height: 100vh }`). They tripped `[GRID_OVERFLOW]`
  (wide), now resolved with `cfg.overrides.{ChatPane,JournalView}.cardMode =
  "column"`. Keep those overrides.
- All 5 components land in group `general` (they all live in `src/components/`,
  a generic dir, and have no `@category`). Acceptable for 5 components.

## Verify-loop learnings (first sync, 2026-06-23)

- **Playwright/chromium**: the render check needs a `playwright` module resolvable
  from `.ds-sync/` (the staged-scripts dir), not just the global CLI. `playwright`
  1.61.0 pins chromium build **1228**, which was already in `~/.cache/ms-playwright/`
  — no `playwright install` download was needed. `npm i playwright` in `.ds-sync/`.
- **Emoji render as boxes in headless chromium**: JournalView's enriched-entry
  markers (🏷️/✨) show as tofu boxes in the capture screenshots. This is a
  headless-font artifact only — real browsers (incl. claude.ai/design) render the
  emoji. Not a defect; do not "fix" it.
- **`.prompt.md` example comments are shifted by one**: the doc extractor appends
  each preview export's *trailing* JSDoc, so an example shows the *next* cell's
  comment. Cosmetic; the example code itself is correct. Left as-is.
- **KnowMorePage digest block** shows "(no digest configured — cannot verify)"
  because the preview build has no `VITE_EXPECTED_IMAGE_DIGEST`. Honest for a
  build-time-config component; can't be injected per-preview.

## Known render warns

None — the final validate run is fully clean (0 warnings).

## Re-sync risks (what can silently go stale)

- `dtsPropsFor` bodies are a hand-maintained mirror of the real props — they do
  **not** auto-update when the component source changes. Re-check on any prop
  change.
- `ds-entry.tsx` is a hand-maintained mirror of the component set — add/remove
  entries when `componentSrcMap` changes, or the new/removed component won't be
  in the importable bundle.
- The bundle pulls in the app's real deps (idb, jose, @hpke/*, hash-wasm) from
  `src/lib` and `src/attest`. A breaking change there could break the bundle.
