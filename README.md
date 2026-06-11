# tee-example

A demo of hardware-backed privacy guarantees: a journal app with a chatbot
where user data is processed only by open-source, auditable code inside a GCP
Confidential Space CVM (AMD SEV-SNP). Architecture and trust model:
`docs/DESIGN.md`. Deploy instructions: `infra/README.md`.

- `launcher/` — the open, audited TCB that runs inside the enclave (Rust)
- `frontend/` — local-first SPA; client-side encryption, in-browser
  attestation verification (React + TypeScript)
- `infra/` — Terraform for the Confidential Space CVM
- `scripts/` — standalone attestation verifier and the release build recipe

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
metadata-stripped USTAR tar, assembled onto an empty base with a
version-pinned `crane`. Every pinned input is recorded in the release notes
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
--image-digest <D>`.

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
