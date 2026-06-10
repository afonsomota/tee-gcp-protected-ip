# Spike 001 — Can Kettle attest an OCI image digest end-to-end?

**Date:** 2026-06-10
**Kettle version examined:** `lunal-dev/kettle` @ `c7859a81fdf4b32ab3642d27e217df3763f7d8d3` (2026-06-03, "update README with reproduction info"); released binary `kettle 1.0.0`.
**Question:** Does kettle's hardware-rooted provenance cover the **OCI image manifest digest** — the value Confidential Space embeds in its attestation token as `submods.container.image_digest` — or only a binary artifact digest?

## Answer

**No. Kettle attests binary artifacts only.** It has no concept of OCI images,
registries, or manifests anywhere in its source. The chain from kettle's
hardware evidence to a Confidential Space token's `image_digest` claim is
**broken by construction** and must be bridged by a deterministic
binary→image wrap. The wrap was prototyped in this spike and produces
byte-stable manifests digests (see "Fallback design").

**Recommendation: conditional GO for issue 012** — keep kettle as the
hardware-rooted provenance source for the **launcher binary**, and add the
deterministic wrap step (specified below) to extend the chain to the OCI
manifest digest. A plain "kettle covers the image digest" GO is **not**
available.

---

## 1. What kettle actually attests (source-code evidence)

All citations are to commit `c7859a8` of `lunal-dev/kettle`.

### 1.1 Build subjects are loose binary files, never images

- `src/commands/build.rs:6-26` — the toolchain enum is exactly
  `{Cargo, Nix, Pnpm}`, detected by `Cargo.lock` / `flake.nix` /
  `pnpm-lock.yaml`. There is no Docker/OCI toolchain and no detection of a
  `Dockerfile`.
- `src/toolchain/driver.rs:49-74` — `Artifact::in_dir` collects build outputs
  as **files** (extension-less or `.exe`) and checksums them with
  `sha256(file_bytes)`.
- `src/toolchain/cargo.rs:97-115` — for Rust, artifacts are the files in
  `target/release/`. These become the SLSA `subject` entries.
- `grep -rni "oci|docker|registry|push|manifest"` over `src/` yields **zero**
  hits related to container images. The only "registry" matches are cargo
  crates-io registry dependencies in `src/toolchain/cargo_lock.rs`. `PLAN.md`
  (the roadmap) contains no container/OCI items either.

### 1.2 What the hardware report binds

- `src/commands/attest.rs:28-54` — `kettle attest` builds the project, then
  puts `sha256(provenance.json)` into the **first 32 bytes of the SEV-SNP
  report's `report_data`** (optionally a 16-byte nonce in the remainder) and
  calls `attestation::attest(...)`, writing `evidence.json`.
- So the trust chain kettle provides is:
  `AMD VCEK cert chain → SNP report → report_data = sha256(provenance.json)
  → provenance.subject[i] = sha256(binary file)`.
- `src/provenance.rs:74-107` — `verify_artifacts` confirms exactly this:
  it compares `sha256` of each file in `kettle-build/artifacts/` against the
  provenance subjects. Files, not manifests.

### 1.3 Platform support (relevant to issue 012's build CVM)

- Kettle's attestation backend is `lunal-dev/attestation-rs` (branch `usize`,
  `Cargo.toml:61`). Its `crates/attestation/src/platforms/gcp_snp/attest.rs`
  detects GCP (`/dev/sev-guest` present + DMI board vendor `Google`) and
  produces a standard AMD SNP report. So **kettle does run on a plain GCP
  SEV-SNP Confidential VM** (not Confidential Space — a regular CVM with the
  SNP guest device).
- Caveat noted in that file: the GCP-vs-bare-metal classification is a
  heuristic; the cryptographic root is the AMD report either way.

### 1.4 A documentation claim that is not implemented

`docs/2-how-it-works.md:172` says: *"For artifacts that will run in
confidential VMs, Kettle also computes the expected launch measurement."*
No such computation exists in the code. The only `launch_digest` in the tree
(`src/commands/verify.rs:282`) is the launch measurement **of the build CVM
itself**, parsed out of its own SNP report — it is not a predicted runtime
measurement of the built artifact, and in any case Confidential Space's
`image_digest` is a container-manifest digest, not an SNP launch measurement.
Treat that doc line as aspirational.

### 1.5 What Confidential Space measures

Per Google's token-claims reference
(<https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims>),
the token carries `submods.container.image_digest` — "the image digest of the
workload container" — alongside `submods.container.image_reference`. This is
the registry **manifest digest** (the same value `crane digest` /
`docker pull <ref>@sha256:...` resolves), covering the image config and all
layer descriptors. Kettle's evidence never contains this value, and nothing
in kettle's provenance lets a verifier derive it: a manifest digest depends on
layer tar bytes, compression, config JSON, and base image — none of which
kettle records.

**Where the chain breaks:** kettle proves *"this binary (sha256 B) came from
commit C with toolchain T, on AMD hardware"*. Confidential Space proves
*"I am running image manifest digest D"*. Nothing links B to D.

---

## 2. What I ran vs. what I analyzed statically

### Ran (local, macOS arm64)

1. **`kettle build` 1.0.0 on a hello-world Rust crate** (`cargo new hello-tee`).
   Output `kettle-build/provenance.json` is SLSA v1 with a single subject:

   ```json
   "subject": [{ "digest": { "sha256": "18c26df36aa8a920b682a2509a11013d3011687291497f81fe58a8f3a21179c5" },
                 "name": "hello-tee" }]
   ```

   i.e. the sha256 of the binary file — no image digest, confirming the
   static analysis on a live run.
2. **`kettle attest`** on the same project fails locally with
   "Attestation is disabled. Rebuild Kettle with `--features attest`" —
   consistent with the hardware signature requiring a TEE.
3. **Fallback wrap prototype** (section 3): reproducible layer tar +
   `crane append`/`crane mutate` against a digest-pinned base, pushed to a
   local `registry:2`, digest-compared across two independent runs. Stable.

### Not run (and why)

**`kettle attest` inside a GCP SEV-SNP CVM was not executed.** The
environment's GCP credentials are unusable: the authenticated account's
refresh token and the application-default credentials both return
`invalid_grant` (revoked/expired), the remaining account has no IAM access to
`angular-yen-432616-r6`, and re-auth (`gcloud auth login`) requires an
interactive browser. Per the spike guardrails (two failures, same root cause)
the cloud attempt was stopped and the digest-chain question was settled from
source (section 1), which is conclusive: running kettle in a CVM cannot
change what its code hashes. **No cloud resources were created** — the
failure occurred before any create call; the only thing torn down was a local
Docker `registry:2` container (removed).

Consequence: acceptance criterion "kettle build runs to completion inside an
SEV-SNP CVM" is **not demonstrated** here and moves to issue 012's first
milestone (it is low-risk: `kettle attest` only adds an SNP report over the
locally-verified build path, and attestation-rs explicitly supports
GCP SNP via `/dev/sev-guest`).

---

## 3. Fallback design: deterministic binary→image wrap (for issue 012)

Bridges kettle's binary digest to Confidential Space's manifest digest with a
**pure function** any verifier can re-run.

### Recipe (prototyped in this spike)

1. **Layer tar (reproducible):** pack the kettle-attested binary as a USTAR
   tar with fixed metadata — path `/app/<name>`, `mtime=0`, `uid=gid=0`,
   empty uname/gname, mode `0755`, entries in fixed order, no PAX headers.
   (Prototype: 20-line Python `tarfile` script; two runs produced identical
   tar sha256 `65d09473…`. GNU tar `--sort=name --mtime=@0 --owner=0
   --group=0 --numeric-owner --format=ustar` is equivalent.)
2. **Base image pinned by digest:**
   `gcr.io/distroless/static-debian12@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639`
   (resolved 2026-06-10; issue 012 pins its own digest in-repo).
3. **Assemble with crane** (go-containerregistry; pin the crane version —
   it gzips the layer, and gzip output is an input to the digest):

   ```sh
   crane append -b "$BASE_DIGEST_REF" -f layer.tar -t "$REG/launcher:rc"
   crane mutate "$REG/launcher:rc" --entrypoint /app/launcher -t "$REG/launcher:vX"
   crane digest "$REG/launcher:vX"   # → the value to pin everywhere
   ```

4. **Verification chain becomes:**
   `AMD cert chain → SNP report → sha256(provenance.json) → sha256(binary)
   → wrap(binary, base_digest, tar_rules, crane_version) → manifest digest D
   → Confidential Space token claim submods.container.image_digest == D`.
   The wrap step is verifier-recomputable: given the attested binary and the
   pinned parameters, anyone re-derives D offline and compares it to the
   token. The wrap itself needs no TEE and no trust — determinism is the
   guarantee. (Optionally run it inside the same build CVM anyway and log it.)

### Measured digest stability

| Step | Run 1 | Run 2 |
|---|---|---|
| layer tar sha256 | `65d09473…3bbeb5a` | identical |
| `crane append` manifest digest | `sha256:3e8a11de038b075e0e12ff0dc2d75684a50c26bcd53e61714d7c59e315642c99` | identical |
| `crane mutate --entrypoint` manifest digest | `sha256:7252856f8648b302d8dd049e9cf0bc3d626111ee3406ed869049557eba646ffe` | identical |

Result manifest is `application/vnd.oci.image.manifest.v1+json`; image config
`created` is epoch zero and layer history carries zero timestamps — no
wall-clock leakage into the digest. Confirmation procedure for issue 012:
run the wrap twice (CI and a clean machine), compare `crane digest`
(or `skopeo inspect --format '{{.Digest}}'`); push by digest
(`crane push` / `skopeo copy --digestfile`) so the registry preserves D.

### Determinism caveats to encode in issue 012

- **Pin crane/go-containerregistry version** (gzip implementation details are
  digest inputs). Record the version in the release notes next to D.
- **Pin the base by digest, never by tag.** Base digest changes change D.
- The wrapped **binary itself need not be reproducible** for the chain to
  hold — kettle's hardware evidence vouches for the binary; reproducibility
  remains the documented best-effort fallback per DESIGN.md.
- The launcher must be built for `x86_64-unknown-linux-(gnu|musl)` in the
  build CVM (this spike's local artifact was darwin/arm64 — digest math is
  byte-level so the determinism result transfers, but issue 012 must use the
  real target).

---

## 4. Go / No-go

**Conditional GO for issue 012**, with the pipeline amended:

1. Ephemeral GCP SEV-SNP CVM (plain Confidential VM, `n2d` + `SEV_SNP`,
   image with `/dev/sev-guest`, e.g. Ubuntu 24.04) runs
   `kettle attest launcher/` → `provenance.json` + `evidence.json` +
   binary. *(First milestone: demonstrate this runs — it was not executed in
   this spike due to dead GCP credentials.)*
2. Deterministic wrap (section 3) → manifest digest D; push by digest to
   Artifact Registry.
3. Publish `{evidence.json, provenance.json, wrap parameters, D}`; pin D in
   the Confidential Space VM config and the KMS attestation policy.
4. Verify-it-yourself docs walk the full chain: AMD certs → report_data →
   provenance → binary sha256 → recompute wrap → D → token
   `submods.container.image_digest`.

If kettle-in-CVM fails at milestone 1, the wrap still works with any
auditable build (e.g. GitHub-attested or reproducible build) as the binary
provenance source — the wrap is independent of kettle.

---

## 5. Open for human review (HITL gate — required before issue 012 starts)

1. **Accept the conditional GO?** Kettle does *not* cover the OCI digest;
   the design's "Build verification" row should be reworded from "provenance
   (commit → digest) is committed into the hardware attestation report" to
   "provenance (commit → **binary** digest) is hardware-attested; the
   **image** digest is derived via a published deterministic wrap".
2. **Risk appetite for kettle's maturity:** v1.0.0, young project, the
   "expected launch measurement" doc claim is unimplemented (§1.4). Is a
   hard dependency acceptable, or should issue 012 treat kettle as optional
   alongside the wrap (which carries the digest chain either way)?
3. **Verify `kettle attest` on a real GCP SEV-SNP CVM** once credentials are
   restored (`gcloud auth login` is interactive). ~15 min, one
   `n2d-standard-2` CVM, teardown after. This spike could not do it.
4. **Confirm the base-image choice** (distroless static vs. scratch) and that
   the launcher links accordingly (musl static for scratch; distroless static
   provides CA certs + tzdata which the launcher's TLS/ACME path likely
   wants).
5. **Cross-machine digest check:** two runs on one machine were identical;
   issue 012 should add a second-machine/CI re-derivation before declaring
   the wrap stable (gzip determinism across crane builds is expected but
   should be witnessed, hence "pin crane version").
