---
id: 008
title: "Wasm harness sandbox with signed, encrypted delivery"
type: AFK
labels: [ready]
status: open
---

## What to build

The closed-IP harness, sandboxed. A minimal Rust→wasm harness (in `harness/`,
the simulated private repo) that receives the chat context and produces the
reply by calling host functions. The launcher embeds wasmtime and exposes
exactly the host interface the design allows — `llm_generate` plus
context/reply plumbing — nothing else: no WASI, no filesystem, no network,
no clocks.

Delivery rides issue 007's pipeline: harness.wasm encrypted in GCS,
KMS-gated, plus an offline signature from the company key whose public half
is pinned in the launcher. Chat from issue 006 now routes through the
harness; the fixed prompt moves into it (the "secret sauce").

The host-function bindings should be a small, separate, heavily-commented
module — it is the centerpiece auditors read.

## Acceptance criteria

- [ ] harness.wasm builds from `harness/` and runs under wasmtime in the enclave
- [ ] Host interface exposes only the design's functions; a test harness attempting WASI/imports outside the manifest fails to instantiate
- [ ] Launcher rejects a harness with a bad or missing signature (demonstrated)
- [ ] Harness is delivered encrypted via the issue 007 pipeline
- [ ] Chat replies now come from the harness's prompt orchestration
- [ ] `harness/README.md` explains it stands in for a private repo

## Blocked by

- 006-chat-inference-through-channel
- 007-kms-gated-artifact-delivery
