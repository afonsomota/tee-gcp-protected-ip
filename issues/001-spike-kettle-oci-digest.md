---
id: 001
title: "Spike: can Kettle attest an OCI image digest end-to-end?"
type: HITL
labels: [spike, ready]
status: open
---

## What to build

Determine whether Kettle (lunal-dev/kettle) can produce hardware-rooted build
provenance that covers the **OCI image digest** — the same digest Confidential
Space measures and embeds in its attestation token — not just a binary
artifact digest.

Run a kettle attested build of a hello-world Rust container inside an
SEV-SNP CVM, push the image, and compare the digest in the kettle provenance
document against the digest Confidential Space reports when running that image.

Deliverable is a short written report in `docs/spikes/` with a go/no-go:

- **Go**: kettle covers the image digest (built+pushed in-TEE) → issue 012
  proceeds as designed.
- **No-go**: kettle attests binaries only → specify the deterministic
  binary→image wrap (single layer on a digest-pinned base) that bridges the
  gap, and confirm it produces stable digests.

## Acceptance criteria

- [ ] Kettle build runs to completion inside an SEV-SNP CVM
- [ ] Report documents whether provenance covers the OCI manifest digest
- [ ] Report verifies the digest chain against a live Confidential Space attestation token for the same image, or documents exactly where the chain breaks
- [ ] Go/no-go decision recorded, with the fallback design specified if no-go
- [ ] Human review of the decision before issue 012 starts

## Blocked by

None - can start immediately
