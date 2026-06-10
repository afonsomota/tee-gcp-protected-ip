# Issues

Local markdown issue tracker for the TEE example. Each issue is a tracer-bullet
vertical slice — a thin but complete path through every layer, demoable on its
own. Source plan: [`docs/DESIGN.md`](../docs/DESIGN.md).

Types: **AFK** — implementable and mergeable without human interaction.
**HITL** — requires a human decision or review.

## Dependency graph

| # | Issue | Type | Blocked by |
|---|-------|------|-----------|
| [001](001-spike-kettle-oci-digest.md) | Spike: Kettle OCI image digest | HITL | — |
| [002](002-walking-skeleton-attested-echo.md) | Walking skeleton: attested echo enclave | AFK | — |
| [003](003-hpke-channel-attestation-bound-keys.md) | HPKE channel, attestation-bound keys | AFK | 002 |
| [004](004-tls-in-enclave.md) | TLS terminated in the enclave | AFK | 002 |
| [005](005-local-first-journal-frontend.md) | Local-first journal frontend | AFK | — |
| [006](006-chat-inference-through-channel.md) | Chat inference (Gemma 4 E2B) | AFK | 003 |
| [007](007-kms-gated-artifact-delivery.md) | KMS attestation-gated artifact delivery | AFK | 002 |
| [008](008-wasm-harness-sandbox.md) | Wasm harness sandbox + delivery | AFK | 006, 007 |
| [009](009-chat-ui-attestation-badge.md) | Chat UI + attestation badge | AFK | 003, 005, 006 |
| [010](010-tool-manifest-client-tools.md) | Tool manifest + client-side tools | AFK | 008, 009 |
| [011](011-enclave-tools-enrichment.md) | Enclave tools + enrichment pipeline | AFK | 010 |
| [012](012-kettle-release-pipeline.md) | Kettle release pipeline | AFK | 001, 002 |
| [013](013-frontend-ci-github-pages.md) | Frontend CI → GitHub Pages | AFK | 005 |
| [014](014-docs-verifier-cli.md) | Docs suite + verifier CLI | AFK | 012 |

## Parallel start set

001, 002, and 005 have no blockers and can start immediately.
