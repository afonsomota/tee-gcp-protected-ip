---
id: 010
title: "Tool manifest and client-side tool loop"
type: AFK
labels: [ready]
status: open
---

## What to build

The per-tool-policy machinery. The open launcher declares a tool manifest —
each tool's name, schema, and execution locus (client or enclave). The
harness emits structured tool-call requests; the launcher validates them
against the manifest and routes them.

This slice implements the client locus with two tools over IndexedDB:
`search_entries` (metadata/keyword filters for now; vector similarity arrives
in issue 011) and `attach_metadata`. A tool call travels enclave → frontend
inside the encrypted reply; the frontend executes it locally and returns the
result through HPKE for the next harness turn. Only search-matched entries
ever enter enclave memory — the data-minimization flow from the design.

The UI surfaces tool activity (e.g. "searched your entries: 3 matches") so
the user sees what leaves their device.

## Acceptance criteria

- [ ] Manifest lives in the open launcher; harness tool calls not in the manifest are rejected
- [ ] Multi-turn loop works: user message → harness → search_entries → client executes → harness uses results → reply
- [ ] Only matched entries cross the channel (verifiable in the client's network/log view)
- [ ] attach_metadata writes harness-provided metadata into local encrypted storage
- [ ] Tool activity is visible in the chat UI

## Blocked by

- 008-wasm-harness-sandbox
- 009-chat-ui-attestation-badge
