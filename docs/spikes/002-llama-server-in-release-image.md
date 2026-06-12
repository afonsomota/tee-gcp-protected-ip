# Spike 002 — How llama-server enters the deterministic release image

**Date:** 2026-06-12 (decision recorded 2026-06-12)
**Question:** Issue 006 made the launcher supervise a `llama-server`
subprocess, but the deterministic release recipe (spike 001) produces an
image containing exactly the launcher binary — so a canonical release boots
with no inference engine and `/chat` serves 503 forever. How does
`llama-server` (and the model weights) get into the released image without
breaking the verifier-recomputable digest D?

## Answer

**Use the digest-pinned official llama.cpp server image as the base and
append the reproducible launcher layer onto it.** The recipe becomes:

```
base = ghcr.io/ggml-org/llama.cpp:server@sha256:df320e98…   (pinned, public)
  + launcher layer (reproducibly built from source, as in spike 001)
  → crane mutate (entrypoint /launcher, log_redirect label, env) → digest D
```

D stays fully deterministic and verifier-recomputable: the base layers are
fixed by the pinned digest, the launcher layer is bit-reproducible, and
crane is version-pinned. The verify-it-yourself instruction is unchanged in
shape — rebuild from the tagged source, compare D.

### What the proof still gives, and what it no longer gives

The verification claim splits per component:

| Component | Claim a verifier can make |
|---|---|
| launcher | bytes re-derived from public Rust source — zero trust in anyone |
| llama-server (base image) | bytes are exactly the public artifact ggml-org published at the pinned digest — content-addressed, the same image everyone pulls; the bytes↔source link rests on upstream's release process |

**Zero trust in the operator is preserved** — the operator cannot
substitute a byte of either component without changing D, and D is what the
attestation token binds. What is given up: an auditor can read llama.cpp's
source but cannot re-derive the server binary from it. A backdoor in
llama-server would have to live in the public artifact used by everyone,
not in something targeted at this deployment. This asterisk is documented
in `docs/DESIGN.md` (Build verification row) and must appear in the README
trust-model section when the recipe lands.

### Weights are not in the image

Releases ship **without weights** until issue 007 (attestation-gated
KMS/GCS delivery) lands: `LLAMA_MODEL_PATH` is unset, supervision never
starts, and `/chat` serves 503 on release builds. The dev image
(`launcher/Dockerfile`, weights optionally baked) remains the chat demo in
the interim. No interim fetch mechanism is built — issue 007 is the sole
activation path for `/chat` on releases and becomes the next priority.
Rejected interim variants: baking hash-pinned weights into the release
image (~3.4 GB artifact, couples weight updates to image releases, undone
by 007 anyway) and a plain hash-pinned boot-time fetch (a throwaway subset
of 007).

## Alternatives considered and rejected

1. **Build llama-server reproducibly from source** (static, pinned
   llama.cpp commit, same pinned-container pattern as the launcher). The
   strongest claim — every byte in the enclave re-derivable from source —
   but real C++ reproducibility work, and the deterministic constraints
   carry inference-performance risk: `-march=native` must be off (it bakes
   the build machine's CPU into the bytes and would fail the two-runner
   gate), static musl linking changes allocator/threading behaviour vs
   upstream's glibc build. Upstream's binary is the one issue 006 was
   validated against. **Recorded as future hardening**, same way spike 001
   shelved hardware-attested builds.
2. **Extract `/app/llama-server` + its shared libraries into the scratch
   layer.** Same trust profile as the chosen option but requires walking
   the dynamic-linker dependency closure (~6 libs + loader) and breaks
   whenever upstream's lib layout changes — exactly the kind of cleverness
   the audited recipe is supposed to resist.
3. **Multi-container / split VMs.** Confidential Space runs exactly one
   workload container per CVM (single `tee-image-reference`, one digest in
   the token) — there is no sidecar concept. Splitting launcher and
   llama-server across CVMs would push decrypted user prompts over a VM
   boundary, require the launcher to verify a second attestation and build
   an encrypted channel (a second copy of the attest-and-pin machinery
   inside the TCB), and double the verifier story — while the llama image
   would still be the same unreproducible upstream artifact. No trust
   gained, much complexity added.

## Consequences

- **The `scratch` base is gone from releases**: the image carries the base
  image's Ubuntu userland. Spike 001's "one artifact to look at" relaxes to
  "one pinned public artifact plus one re-derivable layer".
  `webpki-roots` stays compiled in (harmless either way).
- **Dev and release images converge on the same layout** —
  `/app/llama-server`, same env defaults — so `llama.rs` needs no changes
  (`DEFAULT_BIN` stays `/app/llama-server`).
- `crane mutate` must set: entrypoint `/launcher`,
  `tee.launch_policy.log_redirect=always`, `LLAMA_ARG_HOST=127.0.0.1`
  (overriding the base image's `0.0.0.0` default). No
  `tee.launch_policy.allow_env_override` label may ever list a `LLAMA_*`
  variable (see `launcher/src/llama.rs` module docs).
- **Pin the linux/amd64 platform manifest digest**, not the multi-arch
  index, so `crane append` operates on a concrete image.
- **Mirror the base image by digest into Artifact Registry** and record the
  digest in `release-pins.txt` — verifier rebuilds must not depend on ghcr
  retention; content-addressing makes the mirror trust-neutral.
- `RECIPE_VERSION` bumps to 2; the published D changes; release/verify docs
  update accordingly. (No KMS policy rotates yet — the attestation-gated
  KMS policy arrives with issues 004/007.)
- Found while settling this: `scripts/build-image.sh` did not copy
  `launcher/prompts/` into the build container, so `make image` failed to
  compile after issue 006's `include_str!` (fixed in PR #26).

Implementation: issue #29 (filed from this spike).
