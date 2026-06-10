---
id: 003
title: "HPKE channel with attestation-bound enclave keys"
type: AFK
labels: [ready]
status: open
---

## What to build

The core trust mechanism, end-to-end. At boot the launcher generates an
X25519 HPKE keypair and a TLS keypair, and binds both public-key hashes into
the attestation token's `eat_nonce`. A bare-bones test page (no journal UI
yet) verifies the token in the browser — Google JWKS signature, image digest,
key-hash binding — pins the keys, then round-trips an HPKE-encrypted echo
request and decrypts the response.

This slice absorbs two spikes from `docs/DESIGN.md`: `eat_nonce` capacity for
two key hashes (if it doesn't fit, bind a hash of a combined structure), and
hpke-js ↔ Rust `hpke` crate interop (suite: X25519-HKDF-SHA256 /
ChaCha20-Poly1305).

## Acceptance criteria

- [ ] Launcher generates fresh keypairs per boot and binds their hashes into the attestation token
- [ ] Browser page verifies token signature, digest claim, and key binding with no server assistance
- [ ] HPKE-encrypted echo round-trips browser → enclave → browser; payloads on the wire are ciphertext only
- [ ] Tampered token, wrong digest, or mismatched key hash each produce a distinct, visible verification failure
- [ ] Rust and TypeScript HPKE suites verified interoperable with a shared test vector

## Blocked by

- 002-walking-skeleton-attested-echo
