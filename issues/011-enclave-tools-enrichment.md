---
id: 011
title: "Enclave-side tools and the entry enrichment pipeline"
type: AFK
labels: [ready]
status: open
---

## What to build

The model-bound tools and the enrichment loop. A second llama-server instance
serves EmbeddingGemma; the manifest gains three enclave-locus tools:
`embed(text)`, `summarize(text)`, and `extract_metadata(text)` (emotions,
situations, life phases — via Gemma 4 E2B).

Entry-save enrichment flow: when the user saves an entry, the frontend sends
it through HPKE; the enclave runs extraction, summary, and embedding; results
return to the client, which stores them encrypted alongside the entry
(`attach_metadata` from issue 010).

`search_entries` upgrades to vector similarity over the locally stored
embeddings, combined with metadata filters.

## Acceptance criteria

- [ ] Both llama-server instances run within the machine's memory budget (re-measure issue 006's headroom)
- [ ] Saving an entry produces metadata + summary + embedding, stored encrypted in IndexedDB
- [ ] Harness can call enclave tools and client tools in the same conversation turn
- [ ] search_entries returns sensible semantic matches (manual demo with a seeded journal)
- [ ] Enrichment is asynchronous — journal CRUD remains usable while the enclave processes

## Blocked by

- 010-tool-manifest-client-tools
