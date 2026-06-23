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
| TEE platform | **GCP Confidential Space** on AMD SEV-SNP or Intel TDX. Attestation token (signed by Google) includes the workload container image digest. |
| Model | **Gemma 4 E2B** (GGUF) on CPU via a `llama-server` subprocess on `127.0.0.1`; **EmbeddingGemma** in a second instance for embeddings. Weights stored encrypted in GCS; decryption key in Cloud KMS, IAM-gated on a valid attestation of the published image digest. (Gemma weights are publicly licensed — the secrecy is simulated; the *mechanism* is real.) |
| Closed harness | Rust compiled to **WebAssembly**, run under **wasmtime** in the open launcher. Deny-by-default: its only capabilities are the host functions the launcher exposes. Delivered encrypted in GCS + KMS attestation-gated (same pipeline as weights), and signed with a company key pinned in the launcher. Users don't need to trust the harness at all — the sandbox is the guarantee. |
| Launcher (the audited TCB) | **Rust**: axum, wasmtime, hpke, rustls + rustls-acme, GCS/KMS clients, llama-server supervision. The smaller and more legible, the better — this is what skeptical auditors read. |
| Channel | **HPKE to an attestation-bound enclave key.** At boot the launcher generates X25519 (HPKE) and TLS keypairs and binds both pubkey hashes into the Confidential Space attestation token (`eat_nonce`). The frontend verifies the token (Google JWKS + image digest) in the browser, pins the keys, and HPKE-encrypts every payload. |
| Ingress | **TLS terminates inside the enclave** via rustls-acme (Let's Encrypt; owner-supplied domain, static IP, no LB, no proxy). ACME account/cert state is deliberately not persisted — fresh issuance every boot (see Trust model below). TLS adds defense-in-depth; HPKE carries the trust. |
| User auth & keys | **No server-side accounts.** The passphrase derives the user's master key in the browser (Argon2id). Login *is* key derivation. Enclave sessions are anonymous. |
| Storage | **Local-first**: ciphertext in browser IndexedDB (export/import supported). The cloud stores no user data at rest — "we cannot leak what we do not have". KMS/GCS exist only to protect company IP. |
| Data flow | **On-demand minimization.** Entries enter enclave memory only when the harness's search tool retrieves them (top-k), per session, never persisted server-side. |
| Tools | Manifest in the open launcher declares each tool's execution locus. Enclave-side (model-bound): `embed`, `summarize`, `extract_metadata` (emotions, situations, life phases). Client-side (data-bound): `attach_metadata`, `search_entries` (metadata filters + vector similarity over locally stored embeddings). The harness's secret sauce is *when/why* to call tools, not the tools themselves. |
| Build verification | **Reproducible builds as the trust anchor**: the released image is produced by a fully pinned, deterministic recipe (pinned-container musl build → fixed-metadata layer tar → pinned crane append onto the digest-pinned official llama.cpp server base, spike 002 / issue #29) that any verifier re-runs offline to re-derive the digest — zero trust in the operator or CI. Canonical build on GitHub Actions with an independent cross-rebuild job, release-blocking on digest mismatch; sigstore artifact attestations as the convenience tier. Residual limitations (documented in README): both builds run on GitHub infra, so CI compromise is detectable by third-party rebuilds, not prevented; and llama-server's bytes are upstream's public content-addressed artifact at the pinned digest, not re-derived from source (source rebuild recorded as future hardening). The base is mirrored by digest into Artifact Registry (`make mirror-base`), so rebuilds never depend on ghcr retention. Weights are never baked; until issue #7 lands, release builds serve 503 on `/chat`. See `docs/spikes/002-llama-server-in-release-image.md`. |
| Frontend | React + Vite + TypeScript SPA (pnpm), deployed to **GitHub Pages** by Actions. hpke-js + jose for crypto. Verifies attestation and shows a badge with a "know more" link to the verify docs. Trust-on-first-use caveat documented; paranoid users run it locally. |
| Release flow | Frontend: auto via Actions. Enclave: release tag triggers the reproducible build workflow (build + independent re-derivation + push by digest + attestation), then explicit `make deploy` (pin digest into the CVM, update KMS attestation policy). |
| Availability / cost | **Scale from zero** (issue #45): no always-on CVM. A tiny always-on **controller** (Cloud Function, outside the TCB) starts the stopped VM when the browser finds the API unreachable and stops it again after an idle timeout. Because Confidential Space re-encrypts disk per boot, every boot orders a *fresh* Let's Encrypt cert; rather than fight the 5-certs/7-days prod limit, the controller **budgets around it** — it declines to stop when a restart would breach `max_weekly_boots`, so the VM stays warm (pays compute) instead of locking out TLS. The limit is a cost knob, never a wall. |
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

**The scale-from-zero controller is untrusted** (issue #45): it can only
stop/start the VM, never read its memory. A restarted enclave generates fresh
HPKE/TLS keys and a fresh Google-signed token, and the frontend re-attests from
scratch on every reconnect — so the entity that pressed "start" is granted no
privacy trust. The launcher's only role in its own lifecycle is to *ask* (an
idle poke); the budget decision and the stop live in the untrusted controller,
keeping CT/HTTP-parse logic out of the audited TCB.

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
   `n2d-standard-4` (16 GB); bump to `-8` if tight. The chat model measures
   ≈4.5 GiB (issue #6), leaving >10 GiB for the ~0.3 GiB EmbeddingGemma
   instance the launcher now supervises (issue #11). The two-model headroom
   still needs a live re-measurement (`infra/README.md` → "Inference footprint").
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
6. **Weights provisioning**: ✅ resolved (issue #7) —
   `scripts/provision-weights.py` downloads Gemma from HF with the operator's
   token, envelope-encrypts (ChaCha20-Poly1305 STREAM, DEK wrapped by KMS),
   uploads ciphertext to GCS (license-compliant — no plaintext
   redistribution); the launcher decrypts onto a tmpfs only after attested
   KMS key release pinned to the image digest.
