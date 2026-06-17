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

`src/lib.rs` is the whole thing. `run()` parses the chat context and routes by
task:

- **chat** — when the deployment offers an `embed` tool, it first asks the
  enclave to embed the query (semantic recall), then asks the client to
  `search_entries` with that embedding, then prepends the (closed) system prompt
  and the retrieved entries and calls the host model for `{"reply":"..."}`.
  Without `embed` it goes straight to a keyword search.
- **enrich** — on entry save, it asks the enclave to `summarize`,
  `extract_metadata`, and (when available) `embed` the entry, folds the results
  into one enrichment object, and asks the client to `attach_metadata`.

The orchestration — *which* tools to call and *when* — is the secret sauce; the
tools themselves (the embed/summarize/extract primitives in-enclave, and the
client's local search/store) live outside this sandbox. The ABI it shares with
the launcher is documented at the top of `src/lib.rs` and mirrored in
`launcher/src/harness.rs`; the launcher re-validates every tool call the harness
emits against its manifest.

The prompt text lives outside the code in `prompts/` (`prompts/system.md`
today), embedded into the wasm at build time via `include_str!` — the sandbox
has no filesystem, so there is no runtime load and the prompt stays inside the
signed, encrypted artifact. Edit a `.md` file and rebuild to change it; add a
file + a `const` in the `prompts` module of `src/lib.rs` to grow toward
sub-agents or composed prompts.

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
LLAMA_EMBED_UPSTREAM=127.0.0.1:8082 \
  cargo run -- --dev
```

Without `HARNESS_PATH`/`HARNESS_SIG_PATH`, `/chat` serves 503 (the launcher
refuses to run unsigned or undelivered orchestration). `LLAMA_EMBED_UPSTREAM`
(or `LLAMA_EMBED_MODEL_PATH`) is optional: point it at a second `llama-server`
started with `--embeddings` to exercise semantic search and entry enrichment's
embedding step; omit it and search falls back to keywords (the `embed` tool is
dropped from the manifest). Both `LLAMA_*_UPSTREAM` overrides are honored only
in `--dev`.

## Keys

`keys/demo-signing-key.seed` is a **DEMO** Ed25519 private seed, committed on
purpose so anyone can reproduce the signed fixture. A real company key would
never live in the repo — it would sign offline, and only its public half would
be pinned in the launcher. See `keys/README.md`.
