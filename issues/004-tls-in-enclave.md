---
id: 004
title: "TLS terminated inside the enclave (rustls-acme + sealed cert state)"
type: AFK
labels: [ready]
status: open
---

## What to build

Serve HTTPS directly from the enclave on the project's domain. The launcher
obtains and renews a Let's Encrypt certificate via rustls-acme. ACME account
and certificate state persist across enclave restarts as a KMS-wrapped blob
in GCS (only attested workloads can unwrap), so VM recreation does not hit
Let's Encrypt rate limits or change identity needlessly.

Terraform additions: static external IP, DNS instructions (or managed zone),
KMS key + GCS bucket for the sealed ACME state.

The TLS public key hash is already bound into the attestation token by
issue 003 — confirm the binding still holds for the ACME-issued cert chain.

## Acceptance criteria

- [ ] `https://api.<domain>` serves with a valid Let's Encrypt cert issued from inside the enclave
- [ ] ACME state survives `terraform destroy`/`apply` of the VM: the same cert is reused, no re-issuance
- [ ] A non-attested principal cannot unwrap the sealed ACME state (demonstrated)
- [ ] TLS key hash in the attestation token matches the serving cert's key
- [ ] Threat-model note added: TLS is defense-in-depth; HPKE carries the trust

## Blocked by

- 002-walking-skeleton-attested-echo
