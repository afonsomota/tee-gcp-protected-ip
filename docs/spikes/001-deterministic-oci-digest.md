# Spike 001 — A deterministic, verifier-recomputable OCI image digest

**Date:** 2026-06-10 (decision recorded 2026-06-10)
**Question:** How does a skeptical verifier link the digest Confidential Space
attests at runtime (`submods.container.image_digest`) back to the public
source code at a given commit?

## Answer

**Determinism is the trust anchor.** The released image is produced by a
short, fully pinned recipe — build a static binary in a pinned container,
pack it as a metadata-stripped tar layer, assemble the image with a pinned
`crane` — that any verifier can re-run offline and compare digests. The
recipe was prototyped in this spike and produces **byte-identical manifest
digests across independent runs**.

The verification chain becomes:

```
public source @ commit C
  → pinned build recipe (toolchain digest, tar rules, crane version)
  → image manifest digest D
  → Confidential Space token claim submods.container.image_digest == D
```

The recipe needs no trusted build infrastructure: a verifier who re-derives
D from source has verified the link with **zero trust** in the operator or
the CI provider.

### Alternative considered and rejected

A third-party hardware-attested build tool (build runs inside an SEV-SNP
CVM; provenance hash bound into the hardware report) was evaluated as the
primary provenance source. Rejected on two grounds:

1. **The evidence did not bind the build environment.** The tool's verifier
   checked the hardware vendor's certificate chain and the provenance hash in
   `report_data`, but never compared the launch measurement to a known-good
   value — and on plain GCP CVMs the SNP measurement covers only boot
   firmware, not the OS, toolchain, or the tool itself. The resulting
   statement ("some genuine SEV-SNP guest signed this hash") can be produced
   by anyone with any SNP machine and adds nothing over an operator
   signature.
2. **Audience mismatch.** This project's verification story targets auditors
   (Signal-style "trust those who look"). For an auditor, a boring,
   recomputable recipe is a strictly stronger and more legible claim than
   evidence from a young tool they would also have to audit.

Hardware-attested builds can be revisited if tooling matures to the point of
binding the full build environment into the measurement.

---

## 1. The deterministic recipe (prototyped)

1. **Binary:** build the launcher as a static
   `x86_64-unknown-linux-musl` binary inside a digest-pinned Rust container
   (committed `Cargo.lock`, fixed in-container build path). The binary build
   must itself be bit-reproducible — this is a release-blocking invariant
   (see issue 012).
2. **Layer tar (reproducible):** pack the binary as a USTAR tar with fixed
   metadata — fixed path, `mtime=0`, `uid=gid=0`, empty uname/gname, mode
   `0755`, entries in fixed order, no PAX headers. (Prototype: 20-line
   Python `tarfile` script; two runs produced identical tar sha256
   `65d09473…`. GNU tar `--sort=name --mtime=@0 --owner=0 --group=0
   --numeric-owner --format=ustar` is equivalent.)
3. **Base image: none (`scratch`).** The image is exactly one layer
   containing exactly the binary. No base digest to pin or update; an
   auditor inspecting "what runs in the enclave" has one artifact to look
   at. Consequence: trust roots for outbound TLS (ACME, issue 004) must be
   compiled into the binary (`webpki-roots`), not read from the filesystem.
4. **Assemble with crane** (go-containerregistry; **pin the crane version**
   — it gzips the layer, and gzip output is an input to the digest):

   ```sh
   crane append -f layer.tar -t "$REG/launcher:rc"          # empty base
   crane mutate "$REG/launcher:rc" --entrypoint /launcher -t "$REG/launcher:vX"
   crane digest "$REG/launcher:vX"   # → D, the value pinned everywhere
   ```

   Push by digest (`crane push` / `skopeo copy --digestfile`) so the
   registry preserves D.

### Measured digest stability

| Step | Run 1 | Run 2 |
|---|---|---|
| layer tar sha256 | `65d09473…3bbeb5a` | identical |
| `crane append` manifest digest | `sha256:3e8a11de…` | identical |
| `crane mutate --entrypoint` manifest digest | `sha256:7252856f…` | identical |

(The prototype runs used a digest-pinned base image; the scratch-base
variant changes the digests but not the determinism argument — the inputs
shrink to `(binary, tar rules, crane version)`.)

Result manifest is `application/vnd.oci.image.manifest.v1+json`; image
config `created` is epoch zero and layer history carries zero timestamps —
no wall-clock leakage into the digest.

### Determinism caveats to encode in issue 012

- **Pin the crane/go-containerregistry version** (gzip implementation
  details are digest inputs). Record it in the release notes next to D.
- **Pin the builder toolchain image by digest**, never by tag.
- **Cross-machine witness:** two runs on one machine were identical; the
  release pipeline must re-derive D on an independent machine and **block
  the release** on mismatch — this is what continuously proves the
  "rebuild it yourself" claim.
- The binary build was exercised on darwin/arm64 in this spike; digest math
  is byte-level so the determinism result transfers, but the pipeline must
  use the real `x86_64-unknown-linux-musl` target.

---

## 2. Decision

1. **Primary verification path:** deterministic recipe above; verifiers
   rebuild from source and compare D against the published digest and the
   live attestation token.
2. **Canonical builder:** GitHub Actions (public logs), with an independent
   cross-rebuild job that is release-blocking on digest mismatch. GitHub is
   **not** a trust anchor — its compromise is detectable by any rebuild —
   but the README must document the residual limitation: both the canonical
   and cross-check builds run on GitHub infrastructure, so detection relies
   on independent rebuilds. A deploy-time local re-derivation gate is noted
   as future work.
3. **Convenience tier:** GitHub artifact attestations (sigstore) published
   per release, honestly labeled as weaker than rebuilding (roots in
   GitHub's OIDC identity, proves repo/workflow origin only).
4. **`launcher/Dockerfile` is dev-only** and non-canonical; the released
   image is produced solely by the recipe above.

Implementation: issue 012 (reproducible release pipeline).

---

## Addendum (2026-06-12, issue 006): the recipe no longer matches the runtime

Chat inference (issue 006) changed what the launcher needs at runtime: it
supervises a `llama-server` binary (default `/app/llama-server`) and needs
model weights. An image built by the recipe above — exactly one layer,
exactly the launcher binary — boots, but `/chat` serves 503 permanently.

Direction (recommended in the issue 006 review, to be settled in issue 012):
extend the deterministic layer with a **digest-pinned `llama-server`
binary**, and deliver weights at boot via issue 007's attestation-gated
KMS/GCS path instead of baking ~3.4 GB into the reproducible image. That
keeps the image small and the rebuild-it-yourself story cheap; the weights'
integrity is covered by the KMS policy rather than the image digest.
Extending the recipe is an explicit task on issue 012.
