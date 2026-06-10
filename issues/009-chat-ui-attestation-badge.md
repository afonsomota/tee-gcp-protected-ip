---
id: 009
title: "Chat UI with attestation badge and 'know more' page"
type: AFK
labels: [ready]
status: open
---

## What to build

The product experience. The journal SPA gains a chatbot pane wired to the
enclave: on session start it fetches and verifies the attestation token
(issue 003's logic, productionized into the app), pins the enclave keys, and
shows an attestation badge — green only when signature, image digest, and
key bindings all verify. The badge links to a "know more" page that explains
the trust chain in plain language and links the verify-it-yourself docs.

Verification failure degrades loudly: red badge, chat disabled, reason shown.

## Acceptance criteria

- [ ] Chat works end-to-end from the journal UI through HPKE to the enclave and back
- [ ] Badge turns green only when all attestation checks pass; each failure mode shows a distinct reason and disables chat
- [ ] "Know more" page explains: SEV-SNP, image digest ↔ open source, key binding, what the operator can and cannot see
- [ ] Expected image digest is a visible, documented configuration value in the frontend
- [ ] Session keys are re-verified on reconnect (enclave restart yields new keys and a fresh token)

## Blocked by

- 003-hpke-channel-attestation-bound-keys
- 005-local-first-journal-frontend
- 006-chat-inference-through-channel
