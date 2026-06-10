---
id: 006
title: "Chat inference through the channel (Gemma 4 E2B via llama-server)"
type: AFK
labels: [ready]
status: open
---

## What to build

Real inference inside the enclave. The launcher supervises a llama.cpp
`llama-server` subprocess bound to `127.0.0.1`, loaded with Gemma 4 E2B
(GGUF, quantized). A `/chat` endpoint accepts an HPKE-encrypted message,
runs a simple fixed prompt against the model (no harness yet — that arrives
in issue 008), and returns the encrypted reply.

Weights may be baked into the image or fetched plaintext from GCS at this
stage; attestation-gated encrypted delivery is issue 007.

This slice absorbs the memory-fit spike: confirm Gemma 4 E2B (Q4) + launcher
fit on `n2d-standard-4` (16 GB), leaving headroom for the EmbeddingGemma
instance coming in issue 011; bump the Terraform machine type if not.

## Acceptance criteria

- [ ] llama-server starts under launcher supervision and is restarted if it dies
- [ ] llama-server is reachable only from localhost inside the container
- [ ] An HPKE-encrypted chat message returns a model-generated encrypted reply end-to-end
- [ ] Memory headroom measured and recorded; machine type adjusted if needed
- [ ] Cold-boot-to-ready time recorded (model load dominates; informs ops docs)

## Blocked by

- 003-hpke-channel-attestation-bound-keys
