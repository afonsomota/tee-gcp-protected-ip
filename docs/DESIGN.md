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
| Ingress | **TLS terminates inside the enclave** via rustls-acme (Let's Encrypt; owner-supplied domain, static IP, no LB, no proxy). ACME account/cert state persists across boots as a KMS-wrapped blob in GCS. TLS adds defense-in-depth; HPKE carries the trust. |
| User auth & keys | **No server-side accounts.** The passphrase derives the user's master key in the browser (Argon2id). Login *is* key derivation. Enclave sessions are anonymous. |
| Storage | **Local-first**: ciphertext in browser IndexedDB (export/import supported). The cloud stores no user data at rest — "we cannot leak what we do not have". KMS/GCS exist only to protect company IP and the ACME state. |
| Data flow | **On-demand minimization.** Entries enter enclave memory only when the harness's search tool retrieves them (top-k), per session, never persisted server-side. |
| Tools | Manifest in the open launcher declares each tool's execution locus. Enclave-side (model-bound): `embed`, `summarize`, `extract_metadata` (emotions, situations, life phases). Client-side (data-bound): `attach_metadata`, `search_entries` (metadata filters + vector similarity over locally stored embeddings). The harness's secret sauce is *when/why* to call tools, not the tools themselves. |
| Build verification | **Kettle (lunal-dev/kettle) attested builds** as the primary path: the image is built inside a measured CVM; provenance (commit → digest) is committed into the hardware attestation report — trust chains to AMD at build time and runtime alike. Best-effort reproducibility + documented self-rebuild as the trustless fallback. Build CVM is ephemeral, in the same GCP project, via Terraform. |
| Frontend | React + Vite + TypeScript SPA (pnpm), deployed to **GitHub Pages** by Actions. hpke-js + jose for crypto. Verifies attestation and shows a badge with a "know more" link to the verify docs. Trust-on-first-use caveat documented; paranoid users run it locally. |
| Release flow | Frontend: auto via Actions. Enclave: explicit `make release` (ephemeral kettle build CVM → attested image + provenance) and `make deploy` (pin digest into the CVM, update KMS attestation policy). |
| Repo layout | Monorepo: `frontend/`, `launcher/`, `harness/` (simulated private repo with explanatory README), `infra/` (Terraform + kettle config), `docs/` (architecture, threat model, verify-it-yourself). |

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

**Explicitly out of scope / documented caveats:** side-channel attacks;
compromised user device/browser extensions; frontend TOFU (mitigated by
local-run option); Google could in principle issue attestation tokens
falsely (platform trust); model-output IP leakage (distillation).

## Open spikes (verify before building)

1. **Kettle ↔ OCI digest**: confirm kettle can build+push the container image
   inside the TEE so the attested digest equals the Confidential Space
   measured digest; otherwise add a deterministic binary→image wrap.
2. **`eat_nonce` capacity**: confirm binding two key hashes (HPKE + TLS) in
   the Confidential Space token request (or bind a hash of a combined
   structure).
3. **Memory fit**: Gemma 4 E2B (Q4) + EmbeddingGemma + launcher on
   `n2d-standard-4` (16 GB); bump to `-8` if tight.
4. **ACME at boot**: KMS-wrapped cert-state unwrap must complete before
   first TLS accept; check LE rate limits for the restart story.
5. **hpke-js / WebCrypto** interop with the Rust `hpke` crate (suite choice:
   X25519-HKDF-SHA256 / ChaCha20-Poly1305).
6. **Weights provisioning**: Terraform/script downloads Gemma from HF with the
   operator's token, encrypts, uploads to GCS (license-compliant — no
   redistribution).
