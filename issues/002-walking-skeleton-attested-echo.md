---
id: 002
title: "Walking skeleton: attested echo enclave on Confidential Space"
type: AFK
labels: [ready]
status: open
---

## What to build

The thinnest possible path through the whole cloud stack: Terraform that
brings up a GCP Confidential Space CVM (SEV-SNP) running a minimal Rust/axum
container with an `/echo` endpoint, plus a verifier CLI script.

The workload requests an attestation token from the Confidential Space
attestation service with a custom `eat_nonce`, and exposes it via an
`/attestation` endpoint. The verifier script fetches the token, validates
Google's signature (JWKS), and checks the image digest claim against an
expected value.

Image build can be a plain `docker build` pushed to Artifact Registry at this
stage — attested builds come later (issue 012).

## Acceptance criteria

- [ ] `terraform apply` from a clean GCP project brings up the CVM running the container
- [ ] `/echo` responds over HTTP on the VM's external IP
- [ ] Workload obtains an attestation token with a caller-supplied `eat_nonce`
- [ ] Verifier CLI validates token signature + image digest and prints a clear pass/fail
- [ ] `terraform destroy` tears everything down cleanly
- [ ] README section documents the one-time GCP project setup (APIs, workload identity pool)

## Blocked by

None - can start immediately
