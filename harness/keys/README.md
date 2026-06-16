# DEMO SIGNING KEY — NOT A SECRET

`demo-signing-key.seed` is a 32-byte Ed25519 private seed used to sign
`harness.wasm` in this demo. **It is committed to the repository on purpose**
so that anyone cloning the project can rebuild and re-sign the harness fixture
and watch the launcher accept it.

**A real deployment would do the opposite:**

- The company's signing key lives offline (HSM / air-gapped signer), never in
  any repo.
- Only its *public* half is pinned in the launcher
  (`COMPANY_PUBLIC_KEY` in `launcher/src/harness.rs`).
- Releases are signed out-of-band; CI/operators only ever handle the public key
  and the detached signature.

The seed here is the deliberately non-random value `d3b0…d3b0` so it is
obvious at a glance that it is demo material. The matching public key is pinned
in the launcher; if you change this seed you must update that constant (and
re-sign the fixture with `scripts/build-harness.sh`).
