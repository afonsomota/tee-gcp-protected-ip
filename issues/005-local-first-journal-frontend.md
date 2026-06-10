---
id: 005
title: "Local-first journal frontend (passphrase key, IndexedDB, CRUD)"
type: AFK
labels: [ready]
status: done
---

> **Status note (2026-06-10):** Implemented in `frontend/`. All acceptance
> criteria covered by tests (vitest 18/18: crypto + store suites) and a clean
> production build. Not manually clicked through in a real browser.

## What to build

The journal app as a standalone local-first SPA (React + Vite + TypeScript,
pnpm) — fully usable offline with no enclave. The passphrase derives the
user's master key via Argon2id in the browser; login *is* key derivation,
there are no accounts. Entries are encrypted client-side and stored in
IndexedDB. Export/import moves the encrypted journal as a file.

Entry model should leave room for the enrichment metadata that arrives in
issue 011 (emotions, situations, life phases, summary, embedding).

## Acceptance criteria

- [ ] Create/read/update/delete journal entries, persisted across reloads
- [ ] All IndexedDB content is ciphertext (verifiable in devtools); nothing readable without the passphrase
- [ ] Wrong passphrase fails cleanly; correct passphrase decrypts the existing journal
- [ ] Export produces an encrypted file; import restores it in a fresh browser profile
- [ ] No network requests carry journal plaintext (there is no backend yet at all)

## Blocked by

None - can start immediately
