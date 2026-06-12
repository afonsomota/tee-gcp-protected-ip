# Private Journal — a TEE Example

A journal app with a chatbot, built to demonstrate how a company can offer
**hardware-backed data-privacy guarantees** to users while **keeping its IP
closed** (model weights, harness/orchestration code).

## The story

The company's pitch to users: *"Your journal entries are processed only by
open-source code running in a machine you can cryptographically verify. We
cannot read your data — and neither can our cloud provider. Our proprietary
code runs inside that machine too, but in a sandbox that the open code
provably constrains: nothing leaves except the reply you see."*

## Decisions

| Area | Decision |
|---|---|
| TEE platform | **GCP Confidential Space** on AMD SEV-SNP. Attestation token (signed by Google) includes the workload container image digest. |
| Model | **Gemma 4 E2B** (GGUF) on CPU via a `llama-server` subprocess on `127.0.0.1`; **EmbeddingGemma** in a second instance for embeddings. Weights stored encrypted in GCS; decryption key in Cloud KMS, IAM-gated on a valid attestation of the published image digest. (Gemma weights are publicly licensed — the secrecy is simulated; the *mechanism* is real.) |
| Closed harness | Rust compiled to **WebAssembly**, run under **wasmtime** in the open launcher. Deny-by-default: its only capabilities are the host functions the launcher exposes. Delivered encrypted in GCS + KMS attestation-gated (same pipeline as weights), and signed with a company key pinned in the launcher. Users don't need to trust the harness at all — the sandbox is the guarantee. |
| Launcher (the audited TCB) | **Rust**: axum, wasmtime, hpke, rustls + rustls-acme, GCS/KMS clients, llama-server supervision. The smaller and more legible, the better — this is what skeptical auditors read. |
| Channel | **HPKE to an attestation-bound enclave key.** At boot the launcher generates X25519 (HPKE) and TLS keypairs and binds both pubkey hashes into the Confidential Space attestation token (`eat_nonce`). The frontend verifies the token (Google JWKS + image digest) in the browser, pins the keys, and HPKE-encrypts every payload. |
| Ingress | **TLS terminates inside the enclave** via rustls-acme (Let's Encrypt; owner-supplied domain, static IP, no LB, no proxy). ACME account/cert state is deliberately not persisted — fresh issuance every boot (see Trust model below). TLS adds defense-in-depth; HPKE carries the trust. |
| User auth & keys | **No server-side accounts.** The passphrase derives the user's master key in the browser (Argon2id). Login *is* key derivation. Enclave sessions are anonymous. |
| Storage | **Local-first**: ciphertext in browser IndexedDB (export/import supported). The cloud stores no user data at rest — "we cannot leak what we do not have". KMS/GCS exist only to protect company IP. |
| Data flow | **On-demand minimization.** Entries enter enclave memory only when the harness's search tool retrieves them (top-k), per session, never persisted server-side. |
| Tools | Manifest in the open launcher declares each tool's execution locus. Enclave-side (model-bound): `embed`, `summarize`, `extract_metadata` (emotions, situations, life phases). Client-side (data-bound): `attach_metadata`, `search_entries` (metadata filters + vector similarity over locally stored embeddings). The harness's secret sauce is *when/why* to call tools, not the tools themselves. |
| Build verification | **Reproducible builds as the trust anchor**: the released image is produced by a fully pinned, deterministic recipe (pinned-container musl build → fixed-metadata layer tar → pinned crane → single-layer `scratch` image) that any verifier re-runs offline to re-derive the digest — zero trust in the operator or CI. Canonical build on GitHub Actions with an independent cross-rebuild job, release-blocking on digest mismatch; sigstore artifact attestations as the convenience tier. Residual limitation (documented in README): both builds run on GitHub infra, so CI compromise is detectable by third-party rebuilds, not prevented. **Decided, not yet implemented (spike 002):** since issue 006 the runtime also needs `llama-server`; the release image becomes the digest-pinned official llama.cpp server image as base plus the reproducible launcher layer — D stays verifier-recomputable, with one honest asterisk: llama-server's bytes are upstream's public content-addressed artifact, not re-derived from source. Weights are never baked; until issue 007 lands, release builds serve 503 on `/chat`. See `docs/spikes/002-llama-server-in-release-image.md`. |
| Frontend | React + Vite + TypeScript SPA (pnpm), deployed to **GitHub Pages** by Actions. hpke-js + jose for crypto. Verifies attestation and shows a badge with a "know more" link to the verify docs. Trust-on-first-use caveat documented; paranoid users run it locally. |
| Release flow | Frontend: auto via Actions. Enclave: release tag triggers the reproducible build workflow (build + independent re-derivation + push by digest + attestation), then explicit `make deploy` (pin digest into the CVM, update KMS attestation policy). |
| Repo layout | Monorepo: `frontend/`, `launcher/`, `harness/` (simulated private repo with explanatory README), `infra/` (Terraform), `docs/` (architecture, threat model, verify-it-yourself). |

## Chat flow

1. Browser: passphrase → master key; verify attestation token; pin HPKE/TLS keys; badge turns green.
2. User message → HPKE envelope → enclave → harness (wasm).
3. Harness may emit tool calls: client-side ones return to the browser (e.g.
   `search_entries` over IndexedDB → top-k entries back through HPKE);
   enclave-side ones call the models.
4. Harness builds the prompt (the secret sauce), calls `llm_generate`, returns
   the reply → HPKE → browser.

## Entry-save enrichment flow

New entry → enclave (`extract_metadata`, `embed`, `summarize`) → results back
→ client attaches metadata and stores everything encrypted in IndexedDB.

## Trust model (summary)

**User privacy rests on:** AMD silicon, Google's Confidential Space stack
(firmware/OS/runtime — the acknowledged platform TCB), and the open launcher
(+ wasmtime, llama.cpp, rustls). The harness is *untrusted*: sandboxed,
no capabilities beyond host functions; its only output path is the reply and
tool-calls — all of which go to the user.

**Company IP rests on:** KMS attestation-gated key release (Google IAM is in
the *IP* TCB, not the *privacy* TCB).

**TLS is defense-in-depth; HPKE carries the trust.** The enclave terminates
TLS itself (rustls-acme, TLS-ALPN-01; the private key never leaves enclave
memory, and the serving key's SPKI hash is bound into the attestation token
as the `tls:` eat_nonce). But a mis-issued or CA-compromised certificate
gains an attacker nothing beyond what plain HTTP would: every payload is
HPKE-sealed to the attestation-verified enclave key, so user privacy does not
rest on the WebPKI. TLS exists for ordinary web hygiene (browser padlock,
mixed-content rules, casual snooping) and to protect *metadata* in transit.
ACME state (account key + cert) is deliberately not persisted: each boot
issues fresh. Sealing it for reuse (KMS-wrapped blobs in GCS, unwrap gated
on attestation) was built and then removed — it added GCS/KMS/STS client
code to the audited TCB to defend a property GCP cannot deliver against
this threat model's adversary: the KMS key lives in the operator's project,
and a project owner can always re-grant themselves decrypt. Because TLS is
defense-in-depth, fresh issuance per boot loses nothing that matters.

**Explicitly out of scope / documented caveats:** side-channel attacks;
compromised user device/browser extensions; frontend TOFU (mitigated by
local-run option); Google could in principle issue attestation tokens
falsely (platform trust); model-output IP leakage (distillation).

## Open spikes (verify before building)

1. **Deterministic OCI digest**: ✅ resolved — a fully pinned binary→image
   recipe produces byte-identical manifest digests across runs; reproducible
   builds are the trust anchor (`docs/spikes/001-deterministic-oci-digest.md`).
2. **`eat_nonce` capacity**: confirm binding two key hashes (HPKE + TLS) in
   the Confidential Space token request (or bind a hash of a combined
   structure).
3. **Memory fit**: Gemma 4 E2B (Q4) + EmbeddingGemma + launcher on
   `n2d-standard-4` (16 GB); bump to `-8` if tight.
4. **ACME at boot**: implemented in issue 004 (`launcher/src/tls.rs`):
   every boot orders a fresh certificate, and until one is deployed TLS
   handshakes simply fail — no plaintext window. The restart story is rate
   limits, not state: staging (the default directory) allows 30,000
   certs/week per domain; production allows 5 per exact identifier set per
   7 days, enough for occasional live demos
   (`launcher/src/acme_cache.rs` has the arithmetic). Live verification
   against a real domain still pending.
5. **hpke-js / WebCrypto** interop with the Rust `hpke` crate (suite choice:
   X25519-HKDF-SHA256 / ChaCha20-Poly1305).
6. **Weights provisioning**: Terraform/script downloads Gemma from HF with the
   operator's token, encrypts, uploads to GCS (license-compliant — no
   redistribution).
