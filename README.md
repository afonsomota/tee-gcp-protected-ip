# tee-example

Demo: [Journal](https://journal.inner-apple.com/)

A demo of hardware-backed privacy guarantees: a journal app with a chatbot,
built to show how a company can make this pitch to its users — and have it
be *checkable*, not a promise:

> *"Your journal entries are processed only by open-source code running in a
> machine you can cryptographically verify. We cannot read your data — and
> neither can our cloud provider. Our proprietary code runs inside that
> machine too, but in a sandbox that the open code provably constrains:
> nothing leaves except the reply you see."*

Concretely: entries live encrypted in your browser (no server-side accounts
or data at rest), and are processed only inside a GCP Confidential Space CVM
(AMD SEV-SNP or Intel TDX) running an open, audited launcher whose container image digest
is attested by the hardware and re-derivable from this source code by
anyone. The company's closed model-orchestration code runs inside that same
enclave — as a deny-by-default WebAssembly sandbox the open code cages. The
company keeps its IP closed *without asking users to trust closed code*.

Don't take the README's word for any of this:

```sh
./scripts/verify-chain.py --url https://HOST --rebuild
```

walks the whole chain against a live deployment — fresh attestation token →
Google's signature → attested image digest → the GitHub release and git
commit that published it → a from-source rebuild on your machine that
re-derives the same digest. [docs/verifying.md](docs/verifying.md) explains
what each step proves.

## Documentation

| Doc | What it covers |
|---|---|
| [docs/architecture.md](docs/architecture.md) | components, data flows, and the open/closed boundary |
| [docs/threat-model.md](docs/threat-model.md) | the two TCBs (user privacy vs company IP), what each party can and cannot do, what's out of scope |
| [docs/verifying.md](docs/verifying.md) | verify it yourself, step by step — what each step proves and what's still assumed |
| [docs/DESIGN.md](docs/DESIGN.md) | the original design document: every major decision and its rationale |
| [docs/spikes/001-deterministic-oci-digest.md](docs/spikes/001-deterministic-oci-digest.md) | why reproducible builds are the trust anchor (and what was rejected) |
| [docs/spikes/002-llama-server-in-release-image.md](docs/spikes/002-llama-server-in-release-image.md) | how `llama-server` enters the release image without breaking the verifiable digest |
| [infra/README.md](infra/README.md) | deploy runbook (Terraform, two roots) |
| [frontend/README.md](frontend/README.md) | run the frontend locally; the trust-on-first-use caveat |

## Layout

- `launcher/` — the open, audited TCB that runs inside the enclave (Rust)
- `frontend/` — local-first SPA; client-side encryption, in-browser
  attestation verification (React + TypeScript)
- `infra/` — Terraform for the Confidential Space CVM
- `scripts/` — the verifier CLIs and the release build recipe

## Reproducible releases and the build-time trust model

The runtime guarantee of Confidential Space is that the attestation token
names the exact container image digest running in the enclave
(`submods.container.image_digest`). The build-time half of the story is
linking that digest back to this source code — and here **determinism is the
trust anchor**, not any build service
(`docs/spikes/001-deterministic-oci-digest.md`):

```
public source @ tag  →  pinned recipe  →  image digest D  →  attestation claim == D
```

The released image is produced by a short, fully pinned recipe
(`scripts/build-image.sh`, invoked as `make image`): a static musl binary
built in a digest-pinned Rust container at a fixed path, packed as a
metadata-stripped USTAR tar, appended with a version-pinned `crane` onto the
digest-pinned official llama.cpp server image (which provides the
`llama-server` binary the launcher supervises — spike 002). Every pinned
input, base-image digest included, is recorded in the release notes
(`release-pins.txt`). The dev `launcher/Dockerfile` is non-canonical; its
digests will not match a release.

Rebuild and check a release yourself (requires docker, python3, curl):

```sh
git checkout <tag>
make image     # prints the image manifest digest D
make digest    # re-prints dist/image-digest.txt
```

Compare against the digest published on the GitHub release and against a
live enclave with `./scripts/verify-attestation.py --url https://<host> \
--image-digest <D>` — or run the whole chain, release lookup and rebuild
included, with `./scripts/verify-chain.py --url https://<host> --rebuild`
([docs/verifying.md](docs/verifying.md)).

Known limitation: one recipe input (the `musl-dev` apk package, needed to
compile `ring`'s C code) is pinned by exact version, but Alpine keeps only
the latest version per branch. When Alpine rolls it, rebuilding *older*
releases fails loudly (`apk` refuses the pin) rather than silently producing
a different digest. The planned fix is a committed, digest-pinned builder
image with the toolchain baked in.

### What you trust, by tier

- **You rebuild (zero trust).** D is re-derivable from the tagged source on
  your own machine. A compromised CI or operator would publish a digest that
  your rebuild fails to reproduce — caught by any single independent rebuild.
  One honest asterisk: the *launcher layer* is re-derived from the Rust
  source in this repo, but the base image's bytes (`llama-server` and its
  userland) are upstream ggml-org's public content-addressed artifact at a
  pinned digest — the same image everyone pulls, impossible for the operator
  to substitute without changing D, but not re-derived from llama.cpp's C++
  source. A backdoor there would have to live in the public artifact used by
  everyone, not in something targeted at this deployment. Building
  llama-server reproducibly from source is recorded as future hardening
  (`docs/spikes/002-llama-server-in-release-image.md`).
- **You don't rebuild (detection, not prevention).** The release workflow
  (`.github/workflows/release.yml`) builds D and independently re-derives it
  on a separate runner; any mismatch blocks the release. But both the
  canonical and cross-check builds run on GitHub infrastructure, so a
  compromise there is **detectable by outside rebuilds, not prevented**.
  Planned hardening: gate `make deploy` on an independent local
  re-derivation of D, so nothing reaches the enclave on GitHub's say-so
  alone.
- **Artifact attestation (convenience tier).** Each release publishes a
  GitHub artifact attestation (sigstore) for D, verifiable with
  `gh attestation verify`. It proves the image was built by this repo's
  release workflow via GitHub's OIDC identity — nothing more. Strictly
  weaker than rebuilding.

### Releasing and deploying

```sh
git tag v0.x.y && git push origin v0.x.y   # CI: build + cross-rebuild gate + publish
make deploy PROJECT_ID=... IMAGE_DIGEST=sha256:...   # pin digest into the CVM, apply
make verify IMAGE_DIGEST=sha256:...                  # live token must bind to D
```

`make deploy` pins the digest into the Confidential Space VM config
(Terraform). Once attestation-gated KMS lands (issues 004/007), the same
apply rotates the attestation policy to admit only the new digest — old
images lose access to sealed material.

For testing a feature branch on a real CVM without touching prod, use
`make dev-deploy` / `make dev-destroy` (per-branch dev deployments,
ephemeral IP, buildx image) — see `infra/README.md`.
