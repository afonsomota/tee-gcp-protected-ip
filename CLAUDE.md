# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A demo of hardware-backed privacy guarantees: a journal app with a chatbot where user data is processed only by open-source, auditable code inside a GCP Confidential Space CVM (AMD SEV-SNP), while the company's proprietary "harness" runs sandboxed (wasm) inside that same enclave. The architecture, trust model, and all major decisions live in `docs/DESIGN.md` — read it before making design-level changes.

Work is tracked in `issues/` (local markdown issue tracker). `issues/README.md` has the dependency graph; each issue is a vertical slice. Check the relevant issue before implementing — acceptance criteria live there. Resolved design questions are recorded in `docs/spikes/`.

## Layout

- `launcher/` — Rust. The open, audited TCB that runs inside the enclave: axum server with `/echo`, `/attestation` (Confidential Space token via `/run/container_launcher/teeserver.sock`), the HPKE channel (`/hpke-key`, `/hpke/echo`), and the model endpoints `/chat` and `/enrich`. Keys are generated at boot and bound into the attestation token via `eat_nonce` (`hpke:`/`tls:` prefixed hashes). It supervises one or two `llama-server` instances (chat on 8081; EmbeddingGemma on 8082 when configured), gates a tool manifest (`tools.rs`), runs enclave-locus tools in-enclave (`enclave_tools.rs`: `embed`/`summarize`/`extract_metadata`), and drives the harness tool loop (`chat.rs`).
- `frontend/` — React + Vite + TypeScript SPA (pnpm). Local-first: entries encrypted client-side (passphrase → Argon2id master key), stored in IndexedDB. Verifies the enclave attestation in the browser (`src/attest/`), HPKE-encrypts payloads. No server-side accounts or data at rest.
- `infra/` — Terraform, two roots: `infra/bootstrap/` (APIs + Artifact Registry, apply once, never destroy) and `infra/` (service account, firewall, CVM — apply/destroy per deployment). See `infra/README.md` for the full live-run command sequence.
- `scripts/verify-attestation.py` — standalone verifier: fresh nonce → fetch token → check Google JWKS signature, issuer, audience, `eat_nonce`, image digest.
- `.github/workflows/deploy-frontend.yml` — frontend CI → GitHub Pages on pushes to `main` touching `frontend/**`.

## Commands

### Launcher (run from `launcher/`)

```sh
cargo test                      # unit tests are inline (#[cfg(test)] in src/)
cargo test <name>               # single test
cargo run -- --dev              # local dev mode: serves an UNSIGNED attestation-shaped
                                # token so the frontend can run without a real enclave
                                # (also: LAUNCHER_DEV=1; PORT overrides 8080)
```

### Frontend (run from `frontend/`)

```sh
pnpm install
pnpm dev                        # talks to http://localhost:8080 by default
pnpm test                       # vitest
pnpm test src/lib/store.test.ts # single test file
pnpm build                      # tsc --noEmit + vite build
```

Config is build-time Vite env vars (`VITE_API_ENDPOINT`, `VITE_EXPECTED_IMAGE_DIGEST`), read by `src/lib/config.ts`; use `.env.local` for local dev.

### Verifier script tests

```sh
uv run --with 'PyJWT[crypto]' --with pytest --with requests pytest scripts/
```

### Deploy (requires GCP auth, costs money)

Full sequence in `infra/README.md`. Shape: build/push image with `docker buildx` → capture digest → `terraform -chdir=infra apply -var project_id=... -var image_digest=...` → curl + `verify-attestation.py` → `terraform destroy`. The buildx path is dev-only; release images must come from the deterministic pipeline (issue 012).

## Cross-cutting invariants

- **HPKE interop fixtures**: `launcher/tests/fixtures/hpke-interop.json` is sealed by the Rust `hpke` crate and opened by the TS test; `hpke-interop-ts.json` goes the other way. Tests on both sides (`launcher/src/hpke_channel.rs`, `frontend/src/attest/interop.test.ts`) share these files — if you change the HPKE suite, info string (`tee-example/hpke-interop/v1`), or envelope format, regenerate fixtures and run both `cargo test` and `pnpm test`.
- **The launcher is the audited TCB.** Keep it small and legible; resist dependencies and cleverness. Skeptical auditors reading this code *is* the product.
- **Reproducible image digest is the trust anchor** (spike 001). The launcher Dockerfile must keep `LABEL tee.launch_policy.log_redirect=always` — without it the production Confidential Space image gives the container no stdout and the VM self-terminates ~0.1s after launch with no logs.
- **No user data server-side.** The cloud stores only company IP (encrypted weights/harness) and ACME state. Don't add server-side persistence of user content.
- Confidential Space image families are `confidential-space` / `confidential-space-debug` (the `-debian*` names don't exist). Use the debug family for an SSH-able VM.
