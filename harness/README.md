# harness/ — the closed-IP orchestration, sandboxed

**This directory stands in for a *separate, private* repository.** In a real
deployment the company would keep its harness — the prompt engineering, the
tool-selection policy, the orchestration that is the actual product — in a
closed source tree the public could never read. The demo keeps it in-tree, in
its own crate, so the whole system builds with one checkout; treat it as if it
lived behind a wall.

The point of the architecture (see `docs/DESIGN.md`) is that **you do not have
to trust this code**. It runs as WebAssembly under wasmtime *inside* the
audited launcher (the TCB), with deny-by-default capabilities: the launcher
links exactly two host functions and nothing else — no WASI, no filesystem, no
network, no clock. Whatever this harness does, it can only:

1. read the chat context the launcher hands it, and
2. ask the launcher's enclave-local model to generate (`llm_generate`).

It cannot exfiltrate your journal, phone home, or touch the disk. The sandbox
is the guarantee, which is why the launcher — not the harness — is what
skeptical auditors read.

## What it does

`src/lib.rs` is the whole thing. `run()` parses `{"messages":[...]}`, prepends
the (closed) system prompt, calls the host model, and returns `{"reply":"..."}`.
The ABI it shares with the launcher is documented at the top of that file and
mirrored in `launcher/src/harness.rs`.

## Build, sign, deliver

The launcher loads the *compiled, signed* `harness.wasm` at runtime — this
crate is never a Rust dependency of the launcher.

```sh
scripts/build-harness.sh      # cargo build --target wasm32-unknown-unknown
                              # --release, then sign with the demo company key
```

That produces `launcher/tests/fixtures/harness/harness.wasm` and `.wasm.sig`
(the test/dev artifact). In production the same `.wasm` is encrypted and
uploaded with `scripts/provision-harness.py` and delivered to the enclave over
issue #7's KMS-gated pipeline; the launcher verifies the Ed25519 signature
against the company public key **pinned in `launcher/src/harness.rs`** before it
will instantiate the module. A bad or missing signature is refused.

## Local dev

`/chat` only runs once a signed harness is loaded. In dev mode the launcher
reads it straight off disk — point it at the fixture (no encryption, no GCS):

```sh
scripts/build-harness.sh                      # build + sign the fixture once
cd launcher
HARNESS_PATH=tests/fixtures/harness/harness.wasm \
HARNESS_SIG_PATH=tests/fixtures/harness/harness.wasm.sig \
LLAMA_UPSTREAM=127.0.0.1:8081 \
  cargo run -- --dev
```

Without `HARNESS_PATH`/`HARNESS_SIG_PATH`, `/chat` serves 503 (the launcher
refuses to run unsigned or undelivered orchestration).

## Keys

`keys/demo-signing-key.seed` is a **DEMO** Ed25519 private seed, committed on
purpose so anyone can reproduce the signed fixture. A real company key would
never live in the repo — it would sign offline, and only its public half would
be pinned in the launcher. See `keys/README.md`.
