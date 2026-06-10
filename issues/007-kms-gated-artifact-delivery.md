---
id: 007
title: "KMS attestation-gated artifact delivery (weights and blobs)"
type: AFK
labels: [ready]
status: open
---

## What to build

The generic "IP released only to the attested enclave" pipeline, used by both
the model weights and (later) the harness blob.

Operator side: a provisioning script downloads Gemma 4 E2B GGUF from Hugging
Face using the operator's token (license-compliant — no redistribution),
encrypts it with an envelope scheme, and uploads ciphertext to GCS.

Cloud side: a Cloud KMS key whose IAM policy admits decryption only with a
valid Confidential Space attestation of the published image digest (workload
identity pool condition), expressed in Terraform.

Enclave side: the launcher fetches, unwraps, and decrypts artifacts at boot.
Issue 006's weights move onto this pipeline.

## Acceptance criteria

- [ ] Provisioning script: HF download → encrypt → GCS upload, idempotent
- [ ] KMS IAM condition admits the attested workload and nothing else
- [ ] Negative test: a plain VM using the same service account is denied decryption (demonstrated and scripted)
- [ ] Launcher boots from a clean VM, decrypts weights in memory, serves chat
- [ ] Rotating the published image digest in Terraform revokes old images' access

## Blocked by

- 002-walking-skeleton-attested-echo
