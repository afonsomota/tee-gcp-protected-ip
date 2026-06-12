# Architecture

A journal app with a chatbot, arranged so that user data is processed only
by open-source, auditable code inside a hardware-attested enclave, while the
company's proprietary code runs sandboxed inside that same enclave. The
rationale for every decision here is in [DESIGN.md](DESIGN.md); the security
argument is in [threat-model.md](threat-model.md); how to check any of it is
in [verifying.md](verifying.md).

## Components

```
                 user's machine                          Google Cloud
  ┌────────────────────────────────────┐   ┌─────────────────────────────────────┐
  │  Browser (SPA, local-first)        │   │  Confidential Space CVM (SEV-SNP)   │
  │   passphrase → Argon2id master key │   │  ┌───────────────────────────────┐  │
  │   entries encrypted in IndexedDB   │   │  │ launcher (open, audited)      │  │
  │   verifies attestation (badge)     │◄──┼──┤  axum · attestation · HPKE    │  │
  │   HPKE-encrypts every payload      │   │  │  TLS (rustls-acme)     [#4]   │  │
  └────────────────────────────────────┘   │  │  llama-server supervision [#6]│  │
            ▲ static hosting               │  │ ┌───────────────────────────┐ │  │
  ┌─────────┴─────────────┐                │  │ │ harness (closed, wasm,    │ │  │
  │ GitHub Pages          │                │  │ │ deny-by-default)     [#8] │ │  │
  │  serves the SPA only; │                │  │ └───────────────────────────┘ │  │
  │  no user data ever    │                │  └───────────────────────────────┘  │
  └───────────────────────┘                │   ▲ attestation tokens               │
                                           │   │ (teeserver.sock → Google-signed) │
  ┌───────────────────────┐                │  GCS + KMS: encrypted weights &      │
  │ GitHub releases + CI  │                │  harness blob, key released only to  │
  │  reproducible image   │                │  the attested image digest      [#7] │
  │  digest D (the anchor)│                └─────────────────────────────────────┘
  └───────────────────────┘
```

| Component | Where | Openness | What it does |
|---|---|---|---|
| `launcher/` | inside the enclave | **open — the audited TCB** | Generates HPKE/TLS keys at boot, binds their hashes into the attestation token (`eat_nonce`), serves the HPKE channel, supervises `llama-server`, hosts the wasm sandbox. Kept small and legible on purpose. |
| harness | inside the enclave, inside wasmtime | **closed** (company IP) | Chat orchestration — when/why to call tools, prompt building. No capabilities beyond launcher-exposed host functions. Planned: [#8]. |
| model weights | GCS (encrypted), decrypted in enclave memory | licensed (Gemma) | Inference via a `llama-server` subprocess on `127.0.0.1`. In flight: [#6], KMS gating [#7]. |
| `frontend/` | user's browser, served by GitHub Pages | open | Local-first journal: client-side encryption, IndexedDB storage, in-browser attestation verification, HPKE channel. |
| `infra/` | Terraform | open | Two roots: `bootstrap/` (once, never destroyed) and the per-deployment CVM root. `infra/README.md` has the runbook. |
| release pipeline | GitHub Actions + `make` | open | Deterministic image build, cross-rebuild gate, publish by digest. See below. |
| `scripts/` | verifier's machine | open | `verify-chain.py` (full trust chain), `verify-attestation.py` (token check), `build-image.sh` (the canonical build recipe — also the rebuild instructions). |

Issue references mark the parts still in flight; everything else is built and
deployed by the runbook in `infra/README.md`.

## The open/closed boundary

Everything a *user* must trust is open: the launcher and its locked
dependency tree, the frontend, the infra, the build recipe. The company's
proprietary value — the harness and (notionally) the weights — is closed but
**caged**: the harness compiles to WebAssembly and runs under wasmtime with
no filesystem, network, clock, or thread access; its world is exactly the
host functions the open launcher exposes. The boundary is therefore:

- **code**: the wasm host-function interface declared in the open launcher;
- **artifact**: the container image digest D — open code is *in* the image
  (and re-derivable from source); closed artifacts arrive encrypted at boot
  and exist only in enclave memory.

Users audit the cage, not the animal: nothing the harness computes can leave
except the reply and tool-calls, all routed back to the requesting session.

## Flow 1 — attestation and channel establishment

1. At boot the launcher generates an X25519 HPKE keypair and a TLS keypair,
   and requests an attestation token with `eat_nonce` entries
   `hpke:<sha256(pubkey)>` and `tls:<sha256(pubkey)>` — the keys are thereby
   *bound to the hardware measurement* of this boot.
2. The browser generates a random challenge nonce and calls
   `GET /attestation?nonce=...`; the launcher requests a fresh token carrying
   the challenge plus both key bindings.
3. The browser verifies: Google's JWKS signature → issuer/audience → its own
   nonce (freshness) → `submods.container.image_digest` equals the expected,
   audited digest → the served HPKE key (`GET /hpke-key`) hashes to the bound
   `hpke:` entry. (`frontend/src/attest/verify.ts`; each failure mode is a
   distinct error.)
4. Badge turns green; the browser pins the key and HPKE-encrypts every
   payload to it. TLS (terminating inside the enclave, [#4]) wraps the
   transport as defense-in-depth — HPKE carries the trust.

## Flow 2 — chat

1. User message → HPKE envelope → launcher → harness (wasm).
2. The harness may emit tool calls. Client-side tools return to the browser
   (e.g. `search_entries` runs over IndexedDB locally and sends top-k entries
   back through the channel); enclave-side tools call the models (`embed`,
   `summarize`, `extract_metadata`).
3. The harness builds the prompt (the secret sauce), calls `llm_generate`,
   and the reply travels back through HPKE to the browser.

Entry data enters enclave memory only when a tool sends it, per session,
never persisted server-side ("on-demand minimization").

## Flow 3 — entry-save enrichment

New entry → enclave (`extract_metadata`, `embed`, `summarize`) → results
return through the channel → the client attaches metadata and stores
everything, encrypted, in IndexedDB. The cloud keeps nothing.

## Flow 4 — release and deploy

```
git tag v* ──► GitHub Actions: deterministic build (make image)
                 + independent cross-rebuild on a second runner
                 + release-blocking digest comparison
                 ──► push by digest + GitHub release publishing D
                 ──► artifact attestation (sigstore, convenience tier)
operator: make deploy IMAGE_DIGEST=D ──► Terraform pins D into the CVM
                 (and, with [#7], rotates KMS attestation policy to admit
                  only D — old images lose access to sealed material)
```

The digest D is the trust anchor connecting all of this: it is what
Confidential Space attests at runtime, what the release publishes, and what
anyone can re-derive from source with `make image`
(`docs/spikes/001-deterministic-oci-digest.md` for why determinism beats any
trusted build service). [verifying.md](verifying.md) walks the whole chain.

## Storage summary

| Data | Where | Protection |
|---|---|---|
| journal entries, embeddings, metadata | browser IndexedDB only | encrypted client-side (passphrase → Argon2id → master key) |
| chat/session plaintext | enclave memory, per session | SEV-SNP memory encryption; never written |
| model weights, harness blob | GCS, encrypted | KMS key released only to the attested digest [#7] |
| ACME/TLS cert state | enclave memory only — fresh account + cert per boot [#4] | dies with the instance; nothing cloud-side |
| user accounts | — | none exist; login *is* client-side key derivation |

[#4]: https://github.com/afonsomota/tee-gcp-protected-ip/issues/4
[#6]: https://github.com/afonsomota/tee-gcp-protected-ip/issues/6
[#7]: https://github.com/afonsomota/tee-gcp-protected-ip/issues/7
[#8]: https://github.com/afonsomota/tee-gcp-protected-ip/issues/8
