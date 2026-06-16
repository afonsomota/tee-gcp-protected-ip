//! The wasm harness sandbox (issue #8) — host side of the ABI.
//!
//! The closed-IP harness (`harness/`, a stand-in for a private repo) is
//! compiled to `wasm32-unknown-unknown` and run here under wasmtime. It is
//! *untrusted*: deny-by-default capabilities. We build a fresh `Linker` that
//! exposes exactly two host functions — `llm_generate` and `llm_read` — and
//! nothing else. No WASI, no filesystem, no network, no clock. A module that
//! imports anything outside that surface fails to instantiate; that is the
//! guarantee, and it is why this small module is what auditors read.
//!
//! Trust in the *bytes* comes from an offline Ed25519 signature by the
//! company key whose public half is pinned below as `COMPANY_PUBLIC_KEY`. The
//! launcher verifies the signature before it will compile the module; a bad or
//! missing signature is refused. Delivery of the (encrypted) wasm rides issue
//! #7's KMS-gated pipeline (see `artifacts::deliver_harness`).
//!
//! # The ABI (mirrored in harness/src/lib.rs)
//!
//! Guest exports: `alloc(len)->ptr`, `dealloc(ptr,len)`,
//! `run(ctx_ptr,ctx_len)->u64` (packed `(ptr<<32)|len` of the reply JSON, or
//! `0` for failure). Host imports (module `host`): `llm_generate(ptr,len)->i32`
//! (reply length, or -1) and `llm_read(ptr,len)` (copy stashed reply into
//! guest memory). Length-then-copy avoids a re-entrant host→guest `alloc`,
//! which wasmtime forbids mid-call.

use std::sync::Arc;

use ed25519_dalek::{Signature, VerifyingKey};
use wasmtime::{Caller, Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

/// Public half of the **DEMO** company signing key (see
/// harness/keys/README.md). A real deployment pins a key whose private half
/// never touches the repo. If you re-key the harness, regenerate this from the
/// new seed.
const COMPANY_PUBLIC_KEY: [u8; 32] = [
    0x0f, 0x88, 0x4e, 0x99, 0xc6, 0x05, 0x7d, 0xf0, 0x3f, 0x18, 0x91, 0x03, 0xec, 0x6d, 0x97, 0xbe,
    0xff, 0x5c, 0xd8, 0x29, 0x1a, 0x08, 0xd7, 0x75, 0xe6, 0xb6, 0x33, 0xef, 0xa7, 0x9b, 0xd7, 0x66,
];

/// Cap on the guest's linear memory. The harness only shuffles small JSON, so
/// a generous cap still bounds a buggy/hostile module's RAM growth (the guest
/// grows wasm memory via its own allocator). This is a confidentiality
/// architecture, so memory is bounded but guest *CPU* time is not fuel/epoch
/// limited — the harness is signed by the company, and a self-inflicted
/// compute hang affects only availability of one request, not user-data
/// confidentiality. Add epoch interruption here if that ever matters.
const MAX_GUEST_MEMORY: usize = 64 * 1024 * 1024;

/// Per-request host state. `upstream` is the loopback llama-server `/chat`
/// reaches; `reply` stashes one model reply between `llm_generate` (which
/// returns its length) and `llm_read` (which copies it into the guest);
/// `limits` enforces `MAX_GUEST_MEMORY`.
struct HostState {
    upstream: String,
    reply: Vec<u8>,
    limits: StoreLimits,
}

/// A compiled, signature-verified harness, ready to run per request.
pub struct Harness {
    engine: Engine,
    module: Module,
    /// Built once: the entire capability surface granted to the guest.
    linker: Linker<HostState>,
}

impl Harness {
    /// Verify the Ed25519 signature over `wasm` with the pinned company key,
    /// then compile the module and wire up the (only) two host functions.
    /// Returns an error — and never compiles or runs the bytes — if the
    /// signature is missing or invalid.
    pub fn new(wasm: &[u8], signature: &[u8]) -> Result<Self, String> {
        verify_signature(wasm, signature)?;

        // Async host functions: `llm_generate` does (loopback) HTTP, so the
        // guest call must be able to suspend; `run` is driven by `call_async`.
        // (wasmtime 45 enables async at the call site — `Config` no longer
        // gates it.)
        let config = Config::new();
        let engine =
            Engine::new(&config).map_err(|e| format!("wasmtime engine init failed: {e}"))?;
        let module =
            Module::new(&engine, wasm).map_err(|e| format!("harness wasm is invalid: {e}"))?;

        let mut linker = Linker::new(&engine);
        link_host_functions(&mut linker)?;

        Ok(Self {
            engine,
            module,
            linker,
        })
    }

    /// Run one chat turn. `context` is `{"messages":[...]}` (host-validated);
    /// the returned bytes are the harness's reply JSON (`{"reply":"..."}`),
    /// sealed verbatim by the caller. A fresh `Store`/`Instance` per call keeps
    /// turns isolated — no state survives between requests.
    ///
    /// Errors carry no plaintext (status/shape only), preserving the no-leak
    /// invariant from `chat.rs`.
    pub async fn run(&self, upstream: &str, context: &[u8]) -> Result<Vec<u8>, String> {
        let mut store = Store::new(
            &self.engine,
            HostState {
                upstream: upstream.to_string(),
                reply: Vec::new(),
                limits: StoreLimitsBuilder::new()
                    .memory_size(MAX_GUEST_MEMORY)
                    .build(),
            },
        );
        store.limiter(|state| &mut state.limits);
        let instance = self
            .linker
            .instantiate_async(&mut store, &self.module)
            .await
            // Deny-by-default surfaces here: a module importing anything beyond
            // the two host functions cannot be instantiated.
            .map_err(|e| format!("harness failed to instantiate: {e}"))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or("harness exports no memory")?;
        let alloc = instance
            .get_typed_func::<u32, u32>(&mut store, "alloc")
            .map_err(|e| format!("harness exports no alloc: {e}"))?;
        let dealloc = instance
            .get_typed_func::<(u32, u32), ()>(&mut store, "dealloc")
            .map_err(|e| format!("harness exports no dealloc: {e}"))?;
        let run = instance
            .get_typed_func::<(u32, u32), u64>(&mut store, "run")
            .map_err(|e| format!("harness exports no run: {e}"))?;

        // Copy the context into guest memory and run.
        let ctx_len = context.len() as u32;
        let ctx_ptr = alloc
            .call_async(&mut store, ctx_len)
            .await
            .map_err(|e| format!("harness alloc trapped: {e}"))?;
        memory
            .write(&mut store, ctx_ptr as usize, context)
            .map_err(|e| format!("harness memory write failed: {e}"))?;

        let packed = run
            .call_async(&mut store, (ctx_ptr, ctx_len))
            .await
            .map_err(|e| format!("harness run trapped: {e}"))?;
        dealloc.call_async(&mut store, (ctx_ptr, ctx_len)).await.ok();

        let out_ptr = (packed >> 32) as u32;
        let out_len = (packed & 0xffff_ffff) as u32;
        // 0 == the guest's failure signal (see harness `run`): map to an error
        // without reading any plaintext.
        if out_len == 0 {
            return Err("harness produced no reply (inference failed)".to_string());
        }
        let mut out = vec![0u8; out_len as usize];
        memory
            .read(&store, out_ptr as usize, &mut out)
            .map_err(|e| format!("harness memory read failed: {e}"))?;
        dealloc.call_async(&mut store, (out_ptr, out_len)).await.ok();
        Ok(out)
    }
}

/// Verify a 64-byte detached Ed25519 signature over `wasm`. `verify_strict`
/// rejects the malleable/low-order edge cases plain `verify` would accept.
fn verify_signature(wasm: &[u8], signature: &[u8]) -> Result<(), String> {
    let key = VerifyingKey::from_bytes(&COMPANY_PUBLIC_KEY)
        .map_err(|e| format!("pinned company key is invalid: {e}"))?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| format!("signature must be 64 bytes, got {}", signature.len()))?;
    let signature = Signature::from_bytes(&sig_bytes);
    key.verify_strict(wasm, &signature)
        .map_err(|_| "harness signature does not match the pinned company key".to_string())
}

/// Wire up the *entire* capability surface: exactly `host.llm_generate` and
/// `host.llm_read`. Adding nothing else is what makes the sandbox
/// deny-by-default — keep it that way.
fn link_host_functions(linker: &mut Linker<HostState>) -> Result<(), String> {
    // llm_generate(req_ptr, req_len) -> i32: POST the guest-built request body
    // to the enclave-local model, stash the reply, return its length (or -1).
    // Async because it does (loopback) HTTP.
    linker
        .func_wrap_async(
            "host",
            "llm_generate",
            |mut caller: Caller<'_, HostState>, (req_ptr, req_len): (u32, u32)| {
                Box::new(async move {
                    let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory())
                    else {
                        return -1i32;
                    };
                    // Copy the request out of guest memory so the borrow ends
                    // before we await.
                    let request = {
                        let data = memory.data(&caller);
                        let (start, end) = (req_ptr as usize, req_ptr as usize + req_len as usize);
                        match data.get(start..end) {
                            Some(bytes) => bytes.to_vec(),
                            None => return -1i32,
                        }
                    };
                    let upstream = caller.data().upstream.clone();
                    match host_generate(&upstream, &request).await {
                        Ok(reply) => {
                            let reply = reply.into_bytes();
                            let len = reply.len() as i32;
                            caller.data_mut().reply = reply;
                            len
                        }
                        Err(()) => -1i32,
                    }
                })
            },
        )
        .map_err(|e| format!("failed to link host.llm_generate: {e}"))?;

    // llm_read(out_ptr, out_len): copy the stashed reply into guest memory.
    linker
        .func_wrap(
            "host",
            "llm_read",
            |mut caller: Caller<'_, HostState>, out_ptr: u32, out_len: u32| -> wasmtime::Result<()> {
                let reply = std::mem::take(&mut caller.data_mut().reply);
                let memory = caller
                    .get_export("memory")
                    .and_then(|e| e.into_memory())
                    .ok_or_else(|| wasmtime::Error::msg("harness exports no memory"))?;
                let n = reply.len().min(out_len as usize);
                let data = memory.data_mut(&mut caller);
                let (start, end) = (out_ptr as usize, out_ptr as usize + n);
                let dest = data
                    .get_mut(start..end)
                    .ok_or_else(|| wasmtime::Error::msg("llm_read out of bounds"))?;
                dest.copy_from_slice(&reply[..n]);
                Ok(())
            },
        )
        .map_err(|e| format!("failed to link host.llm_read: {e}"))?;
    Ok(())
}

/// Transport the guest-built request body to the enclave-local model. The
/// no-leak transport + JSON extraction live in `crate::upstream::chat_completion`
/// (shared with the rest of the launcher); here we only enforce the guest→host
/// UTF-8 boundary before handing the bytes off.
async fn host_generate(upstream: &str, request_body: &[u8]) -> Result<String, ()> {
    let body = std::str::from_utf8(request_body).map_err(|_| ())?.to_string();
    crate::upstream::chat_completion(upstream, body).await
}

/// A slot the `/chat` handler reads each request. Harness delivery (signed +
/// encrypted) can lag boot — just like weights — so the slot starts empty and
/// `/chat` serves 503 until it is filled. Mirrors the "errors until ready"
/// window of artifact-delivered weights.
pub struct HarnessSlot(std::sync::RwLock<Option<Arc<Harness>>>);

impl HarnessSlot {
    pub fn empty() -> Self {
        Self(std::sync::RwLock::new(None))
    }

    /// Pre-filled slot (tests, and the synchronous dev/`HARNESS_PATH` path).
    pub fn loaded(harness: Arc<Harness>) -> Self {
        Self(std::sync::RwLock::new(Some(harness)))
    }

    pub fn get(&self) -> Option<Arc<Harness>> {
        self.0.read().unwrap().clone()
    }

    fn set(&self, harness: Arc<Harness>) {
        *self.0.write().unwrap() = Some(harness);
    }
}

/// Resolve the harness bytes + signature, verify, compile, and fill `slot`.
/// Backgrounded so boot is never blocked on KMS/IAM propagation (the harness
/// is small, but its delivery is attestation-gated like the weights).
///
/// Source order: `HARNESS_PATH` + `HARNESS_SIG_PATH` env (dev/test), else the
/// issue #7 metadata-driven pipeline (`artifacts::deliver_harness`).
pub fn init(dev: bool, slot: Arc<HarnessSlot>) {
    tokio::spawn(async move {
        match load_source(dev).await {
            Ok(Some((wasm, sig))) => match Harness::new(&wasm, &sig) {
                Ok(harness) => {
                    println!("harness: loaded and signature-verified ({} bytes)", wasm.len());
                    slot.set(Arc::new(harness));
                }
                // A signature failure is fatal-by-design for this boot: /chat
                // keeps serving 503 rather than run unverified code.
                Err(e) => eprintln!("harness: rejected ({e}); /chat will serve 503"),
            },
            Ok(None) => {
                // Either unconfigured, or every delivery attempt failed — the
                // pipeline already logged which (and any per-attempt cause).
                println!("harness: not delivered (unconfigured, or delivery failed after retries); /chat will serve 503")
            }
            Err(e) => eprintln!("harness: delivery failed ({e}); /chat will serve 503"),
        }
    });
}

/// Read the wasm + detached signature from their dev/test env paths, or fetch
/// them over the encrypted pipeline. `Ok(None)` = not configured.
async fn load_source(dev: bool) -> Result<Option<(Vec<u8>, Vec<u8>)>, String> {
    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    if let Some(path) = env("HARNESS_PATH") {
        let sig_path = env("HARNESS_SIG_PATH")
            .ok_or("HARNESS_PATH is set but HARNESS_SIG_PATH is not")?;
        let wasm = std::fs::read(&path).map_err(|e| format!("cannot read {path}: {e}"))?;
        let sig =
            std::fs::read(&sig_path).map_err(|e| format!("cannot read {sig_path}: {e}"))?;
        return Ok(Some((wasm, sig)));
    }
    // The pipeline path resolves + retries internally; it logs the cause of any
    // failure and folds "unconfigured" and "delivery exhausted" into `None`.
    Ok(crate::artifacts::deliver_harness(dev).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed fixture (built + signed by scripts/build-harness.sh; CI
    /// rebuilds it fresh against current source).
    fn fixture_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/harness")
    }

    fn fixture_wasm() -> Vec<u8> {
        let path = fixture_dir().join("harness.wasm");
        std::fs::read(&path).unwrap_or_else(|e| {
            panic!("missing {path:?} (run scripts/build-harness.sh): {e}")
        })
    }

    fn fixture_sig() -> Vec<u8> {
        let path = fixture_dir().join("harness.wasm.sig");
        std::fs::read(&path).unwrap_or_else(|e| {
            panic!("missing {path:?} (run scripts/build-harness.sh): {e}")
        })
    }

    /// A llama-server stand-in that echoes every message it received —
    /// *including* the system role — so tests can prove the harness's own
    /// prompt orchestration drove the reply.
    async fn mock_llama_echoing_system() -> String {
        use axum::routing::post;
        use axum::{Json, Router};
        async fn completions(
            Json(body): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            let seen: Vec<String> = body["messages"]
                .as_array()
                .map(|messages| {
                    messages
                        .iter()
                        .map(|m| {
                            format!(
                                "{}: {}",
                                m["role"].as_str().unwrap_or_default(),
                                m["content"].as_str().unwrap_or_default()
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            Json(serde_json::json!({
                "choices": [
                    { "message": { "role": "assistant", "content": format!("saw [{}]", seen.join(" | ")) } }
                ]
            }))
        }
        let app = Router::new().route("/v1/chat/completions", post(completions));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("127.0.0.1:{}", addr.port())
    }

    #[test]
    fn valid_signature_is_accepted() {
        assert!(Harness::new(&fixture_wasm(), &fixture_sig()).is_ok());
    }

    /// `Harness` holds wasmtime internals that aren't `Debug`, so unwrap the
    /// error arm with a let-else instead of `unwrap_err`.
    fn reject(wasm: &[u8], sig: &[u8]) -> String {
        let Err(err) = Harness::new(wasm, sig) else {
            panic!("expected the harness to be rejected");
        };
        err
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let mut sig = fixture_sig();
        sig[0] ^= 1;
        let err = reject(&fixture_wasm(), &sig);
        assert!(err.contains("signature"), "unexpected error: {err}");
    }

    #[test]
    fn tampered_wasm_is_rejected() {
        // Flip a byte so the existing signature no longer matches. Pick a late
        // byte to stay inside the module body.
        let mut wasm = fixture_wasm();
        let last = wasm.len() - 1;
        wasm[last] ^= 1;
        // Either signature mismatch or wasm-invalid is a rejection; both keep
        // the unverified bytes from running.
        let err = reject(&wasm, &fixture_sig());
        assert!(
            err.contains("signature") || err.contains("invalid"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn missing_signature_is_rejected() {
        let err = reject(&fixture_wasm(), &[]);
        assert!(err.contains("64 bytes"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn deny_by_default_blocks_wasi_imports() {
        // A module importing a WASI function must fail to instantiate: the
        // linker exposes only host.llm_generate / host.llm_read. We sign the
        // .wat bytes with the demo key so it gets past signature verification
        // and the *instantiation* is what rejects it.
        // `Module::new` parses `.wat` text directly (wasmtime `wat` feature),
        // so we sign the text bytes and let instantiation be what rejects it.
        let wat = br#"(module
            (import "wasi_snapshot_preview1" "fd_write"
                (func (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "alloc") (param i32) (result i32) i32.const 0)
            (func (export "dealloc") (param i32 i32))
            (func (export "run") (param i32 i32) (result i64) i64.const 0))"#;
        let sig = sign_with_demo_key(wat);

        let harness = Harness::new(wat, &sig).expect("signature should pass");
        let err = harness.run("127.0.0.1:1", b"{\"messages\":[]}").await.unwrap_err();
        assert!(
            err.contains("instantiate"),
            "expected an instantiation failure, got: {err}"
        );
    }

    #[tokio::test]
    async fn reply_comes_from_the_harness_prompt_orchestration() {
        let upstream = mock_llama_echoing_system().await;
        let harness = Harness::new(&fixture_wasm(), &fixture_sig()).unwrap();
        let context = serde_json::json!({
            "messages": [{ "role": "user", "content": "how was my week?" }]
        })
        .to_string();

        let out = harness.run(&upstream, context.as_bytes()).await.unwrap();
        let reply: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let text = reply["reply"].as_str().unwrap();
        // The harness injected its own system prompt ahead of the user turn.
        assert!(
            text.contains("system: You are a private journaling assistant"),
            "harness prompt not applied: {text}"
        );
        assert!(text.contains("user: how was my week?"), "history dropped: {text}");
    }

    #[tokio::test]
    async fn upstream_failure_yields_an_empty_reply_not_a_leak() {
        // Unreachable upstream → host_generate errs → guest returns 0 → run
        // surfaces an error carrying no plaintext.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        drop(listener);

        let harness = Harness::new(&fixture_wasm(), &fixture_sig()).unwrap();
        let context = br#"{"messages":[{"role":"user","content":"secret-journal-text"}]}"#;
        let err = harness.run(&upstream, context).await.unwrap_err();
        assert!(err.contains("no reply"), "unexpected error: {err}");
        assert!(!err.contains("secret-journal"), "plaintext leaked: {err}");
    }

    /// Sign bytes with the committed demo seed — test-only, mirrors
    /// scripts/sign-harness.py so inline `.wat` modules can be exercised.
    fn sign_with_demo_key(bytes: &[u8]) -> Vec<u8> {
        use ed25519_dalek::{Signer, SigningKey};
        let seed = std::fs::read(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../harness/keys/demo-signing-key.seed"),
        )
        .unwrap();
        let seed: [u8; 32] = seed.as_slice().try_into().unwrap();
        let signing = SigningKey::from_bytes(&seed);
        signing.sign(bytes).to_bytes().to_vec()
    }
}
