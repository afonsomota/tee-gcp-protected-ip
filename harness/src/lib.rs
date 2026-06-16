//! The closed-IP harness — the company's "secret sauce", sandboxed.
//!
//! This crate compiles to `wasm32-unknown-unknown` and runs under wasmtime
//! inside the launcher (the audited TCB). It is *untrusted*: the launcher
//! grants it exactly two host functions and nothing else — no WASI, no
//! filesystem, no network, no clock. The sandbox is the guarantee, so users
//! never have to trust this code. See harness/README.md.
//!
//! # ABI (the launcher's `launcher/src/harness.rs` is the other half)
//!
//! Exports:
//!   * `alloc(len) -> ptr`        — allocate `len` bytes of guest memory
//!   * `dealloc(ptr, len)`        — free a previous `alloc`
//!   * `run(ctx_ptr, ctx_len) -> u64`
//!         Reads the chat context JSON at `[ctx_ptr, ctx_ptr+ctx_len)`,
//!         produces the reply, and returns a packed `(ptr << 32) | len`
//!         pointing at the reply JSON in guest memory (which the host reads
//!         then `dealloc`s). A return of `0` signals failure with no output.
//!
//! Imports (module `host` — the ONLY capabilities the launcher exposes):
//!   * `llm_generate(req_ptr, req_len) -> i32`
//!         Hands the host a chat-completions request body; the host calls the
//!         enclave-local model and returns the reply length in bytes, or `-1`
//!         on error. The reply itself is stashed host-side.
//!   * `llm_read(out_ptr, out_len)`
//!         Copies the stashed reply into guest memory. Splitting generate
//!         (length) from read (copy) avoids re-entrant host→guest `alloc`
//!         calls, which wasmtime forbids mid-call.

use serde::{Deserialize, Serialize};

/// Prompt text lives outside the code, in `harness/prompts/`, so the
/// orchestration — the company's closed IP — can be edited without touching
/// Rust. Each file is embedded into the (signed, encrypted) wasm at build time:
/// the sandbox has no filesystem, so there is no runtime load, and the prompt
/// never leaves the sandbox in the clear. Add a file + a `const` here per role
/// as the harness grows (sub-agents, composed prompts).
mod prompts {
    /// The top-level system prompt prepended to every conversation.
    pub const SYSTEM: &str = include_str!("../prompts/system.md");
}

/// How many tokens the model may generate per turn.
const MAX_TOKENS: u32 = 512;

// The module the host functions are imported from. Naming it explicitly keeps
// the import surface auditable: the launcher links exactly these two.
#[link(wasm_import_module = "host")]
extern "C" {
    fn llm_generate(req_ptr: u32, req_len: u32) -> i32;
    fn llm_read(out_ptr: u32, out_len: u32);
}

#[derive(Deserialize)]
struct Context {
    /// The conversation so far, oldest first, validated host-side to contain
    /// only `user`/`assistant` roles (the system prompt is ours, below).
    messages: Vec<Message>,
}

#[derive(Deserialize, Serialize)]
struct Message {
    role: String,
    content: String,
}

/// Allocate `len` bytes and hand the raw pointer to the host. The boxed slice
/// keeps capacity == len so `dealloc` can reconstruct it exactly.
#[no_mangle]
pub extern "C" fn alloc(len: u32) -> u32 {
    let buf = vec![0u8; len as usize].into_boxed_slice();
    let ptr = buf.as_ptr() as u32;
    std::mem::forget(buf);
    ptr
}

/// Free a buffer previously returned by `alloc` (or by `run`).
///
/// # Safety
/// `ptr`/`len` must come from a prior `alloc`/`run` and be freed at most once.
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: u32, len: u32) {
    drop(Vec::from_raw_parts(ptr as *mut u8, len as usize, len as usize));
}

/// Entry point: chat context in, reply JSON out (see module ABI docs).
///
/// # Safety
/// `ctx_ptr`/`ctx_len` must describe a valid buffer the host allocated and
/// filled before the call; the host owns and frees it afterwards.
#[no_mangle]
pub unsafe extern "C" fn run(ctx_ptr: u32, ctx_len: u32) -> u64 {
    let ctx = std::slice::from_raw_parts(ctx_ptr as *const u8, ctx_len as usize);
    // Empty output (return 0) is the failure signal: the reply JSON is never
    // empty on success, so the host maps 0 → 502 without seeing any plaintext.
    let Some(out) = orchestrate(ctx) else {
        return 0;
    };
    let boxed = out.into_boxed_slice();
    let len = boxed.len() as u64;
    let ptr = boxed.as_ptr() as u64;
    std::mem::forget(boxed);
    (ptr << 32) | len
}

/// The orchestration: parse the context, build the prompt (the secret sauce),
/// ask the host's model, and wrap the reply. `None` on any failure.
fn orchestrate(ctx: &[u8]) -> Option<Vec<u8>> {
    let context: Context = serde_json::from_slice(ctx).ok()?;

    // Prepend our system prompt to the client's history. This is the only
    // place the prompt lives — it never leaves the sandbox in the clear.
    let mut messages = Vec::with_capacity(context.messages.len() + 1);
    messages.push(Message {
        role: "system".to_string(),
        // `trim` drops the trailing newline editors leave in the .md file.
        content: prompts::SYSTEM.trim().to_string(),
    });
    messages.extend(context.messages);

    let request = serde_json::json!({
        "messages": messages,
        "max_tokens": MAX_TOKENS,
    });
    let reply = call_model(&serde_json::to_vec(&request).ok()?)?;

    serde_json::to_vec(&serde_json::json!({ "reply": reply })).ok()
}

/// Two-step host call: `llm_generate` returns the reply length (or -1), then
/// `llm_read` copies the bytes into a buffer we own.
fn call_model(request: &[u8]) -> Option<String> {
    let len = unsafe { llm_generate(request.as_ptr() as u32, request.len() as u32) };
    if len < 0 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    unsafe { llm_read(buf.as_mut_ptr() as u32, buf.len() as u32) };
    String::from_utf8(buf).ok()
}
