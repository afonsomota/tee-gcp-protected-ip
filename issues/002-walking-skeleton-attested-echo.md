---
id: 002
title: "Walking skeleton: attested echo enclave on Confidential Space"
type: AFK
labels: [ready]
status: needs-review
---

> **Status note (2026-06-10, live run):** Live cloud run completed against
> project `tees-499001`: bootstrap apply, image build+push, CVM apply, `/echo`
> OK, verifier `RESULT: PASS` (signature, issuer, audience, nonce, image
> digest) on the **production** Confidential Space image. Three fixes were
> needed: (1) image family names corrected to `confidential-space` /
> `confidential-space-debug` (old `confidential-space-debian*` defaults don't
> exist); (2) Dockerfile builder bumped to rust:1.88 (post-HPKE `Cargo.lock`
> requires it); (3) `LABEL tee.launch_policy.log_redirect=always` added — the
> prod image otherwise gives the workload no usable stdout and the first
> `println!` kills the container ("Workload completed" ~0.1s after launch,
> no logs). Verifier updated for issue 003's `hpke:`/`tls:` key-binding
> entries in `eat_nonce` (membership check; pytest 8/8). `terraform destroy`
> of the infra root is pending human approval (permission gate); exact
> command in `infra/README.md` step 7.

> **Status note (2026-06-10):** Implemented in `launcher/`, `infra/`, `scripts/`.
> All local checks pass (cargo fmt/clippy/test, terraform validate both roots,
> verifier pytest 6/6). The live cloud run (apply → /echo → verify → destroy)
> is deferred to a human: gcloud credentials on this machine are expired
> (`invalid_grant`, interactive re-auth required). Exact ordered commands are
> in `infra/README.md` under "Live run".

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
