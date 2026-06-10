---
id: 012
title: "Kettle attested-build release pipeline (make release / make deploy)"
type: AFK
labels: [ready]
status: open
---

## What to build

The build-time half of the trust story, per the issue 001 spike's outcome.

`make release`: Terraform spins up an ephemeral SEV-SNP build CVM, runs the
kettle attested build of the launcher image (or kettle + the deterministic
binary→image wrap, if the spike said no-go), pushes the image, exports the
hardware-signed provenance document, and tears the build VM down.

`make deploy`: pins the new image digest into the Confidential Space VM
config and updates the KMS attestation policies (issues 004/007) to admit
the new digest, then applies.

Provenance artifacts (document + report) are committed or published alongside
each release so verifiers can fetch them.

## Acceptance criteria

- [ ] `make release` produces an image digest + provenance chaining to the git commit, with no persistent build infrastructure left behind
- [ ] `kettle verify` (or equivalent) validates the provenance against hardware vendor keys
- [ ] `make deploy` rolls the enclave to the new digest; old digests lose KMS access
- [ ] The digest in a live attestation token matches the digest in the published provenance
- [ ] Best-effort reproducibility documented: pinned toolchain/base digests, plus a self-rebuild comparison script (fallback verification path)

## Blocked by

- 001-spike-kettle-oci-digest
- 002-walking-skeleton-attested-echo
