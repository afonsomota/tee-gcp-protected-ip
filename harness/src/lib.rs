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
//!
//! # Tool loop (issue #10)
//!
//! The reply JSON is now one of two shapes:
//!   * `{"reply": "<text>"}`                          — final answer
//!   * `{"tool_calls": [{"id","name","arguments"}]}`  — run these client-side
//!
//! The context JSON the host hands in grows to carry the loop state (the
//! launcher is stateless, so each turn replays everything):
//!   * `messages`     — the user/assistant transcript, oldest first
//!   * `tool_results` — results of the tool calls the harness asked for last
//!                      turn (empty on the first turn of a user message)
//!   * `tools`        — the launcher's tool manifest (informational; the
//!                      launcher re-validates every call we emit against it)
//!
//! This module's policy is a deliberately simple stand-in for the closed
//! "secret sauce": on a fresh user turn it retrieves the user's relevant
//! entries via `search_entries` (the on-demand data-minimization flow — entries
//! enter the enclave only when this tool pulls them), then on the next turn it
//! answers grounded in whatever the client returned. A real harness would plan
//! with the model; the *machinery* (manifest, validation, multi-turn routing)
//! is what issue #10 builds.

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
    /// Results of the tool calls we asked for on the previous turn. Empty on
    /// the first turn of a user message; populated by the client once it has
    /// executed our `search_entries`/`attach_metadata` requests.
    #[serde(default)]
    tool_results: Vec<ToolResult>,
    /// The launcher's manifest, handed in for reference. We don't enforce it —
    /// the launcher does, re-validating every call below — so it's accepted but
    /// otherwise unused here.
    #[serde(default)]
    #[allow(dead_code)]
    tools: serde_json::Value,
}

#[derive(Deserialize, Serialize)]
struct Message {
    role: String,
    content: String,
}

/// A tool result the client fed back: the call id, the tool name, and the
/// tool's JSON output (shape is tool-specific — `search_entries` returns
/// `{ "matches": [...] }`).
#[derive(Deserialize)]
struct ToolResult {
    #[allow(dead_code)]
    id: String,
    name: String,
    result: serde_json::Value,
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
    drop(Vec::from_raw_parts(
        ptr as *mut u8,
        len as usize,
        len as usize,
    ));
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

/// The orchestration (the secret sauce): parse the context and either request
/// a tool call or, once the client has answered one, build the prompt and ask
/// the model. `None` on any failure.
fn orchestrate(ctx: &[u8]) -> Option<Vec<u8>> {
    let context: Context = serde_json::from_slice(ctx).ok()?;

    if context.tool_results.is_empty() {
        // Fresh user turn: retrieve the entries relevant to it before answering.
        // This is the data-minimization step — the only path that pulls entries
        // into the enclave, and only the ones the client's search matches.
        return retrieve(&context.messages);
    }

    // The client has executed our tool calls; answer grounded in the results.
    answer(&context.messages, &context.tool_results)
}

/// Emit a `search_entries` call seeded from the latest user message. The
/// launcher re-validates this against its manifest before it reaches the
/// client.
fn retrieve(messages: &[Message]) -> Option<Vec<u8>> {
    let query = messages
        .iter()
        .rev()
        .find(|m| m.role == "user")?
        .content
        .clone();
    // The id must be unique per turn: the client keys tool-activity UI on it,
    // so reusing a constant would make a later turn's search clobber an earlier
    // turn's record. `messages.len()` strictly increases each user turn (every
    // turn appends at least the new user message plus any prior reply) and is
    // stable across the retrieve/answer legs of one turn, so it gives a stable,
    // collision-free id without the harness having to carry state.
    let call = serde_json::json!({
        "id": format!("search-{}", messages.len()),
        "name": "search_entries",
        "arguments": { "query": query, "limit": 5 },
    });
    serde_json::to_vec(&serde_json::json!({ "tool_calls": [call] })).ok()
}

/// Build the prompt — system + retrieved-entry context + the conversation —
/// and return the model's reply. The retrieved entries ride as a system turn so
/// they are clearly the assistant's grounding, not user input.
fn answer(messages: &[Message], tool_results: &[ToolResult]) -> Option<Vec<u8>> {
    let mut prompt = Vec::with_capacity(messages.len() + 2);
    prompt.push(Message {
        role: "system".to_string(),
        // `trim` drops the trailing newline editors leave in the .md file.
        content: prompts::SYSTEM.trim().to_string(),
    });
    if let Some(context) = format_retrieved(tool_results) {
        prompt.push(Message {
            role: "system".to_string(),
            content: context,
        });
    }
    prompt.extend(messages.iter().map(|m| Message {
        role: m.role.clone(),
        content: m.content.clone(),
    }));

    let request = serde_json::json!({
        "messages": prompt,
        "max_tokens": MAX_TOKENS,
    });
    let reply = call_model(&serde_json::to_vec(&request).ok()?)?;

    serde_json::to_vec(&serde_json::json!({ "reply": reply })).ok()
}

/// Render the `search_entries` matches the client returned into a grounding
/// block for the prompt. Returns `None` when nothing relevant came back.
fn format_retrieved(tool_results: &[ToolResult]) -> Option<String> {
    let mut lines = Vec::new();
    for tr in tool_results {
        if tr.name != "search_entries" {
            continue;
        }
        let matches = tr.result.get("matches").and_then(|m| m.as_array());
        for entry in matches.into_iter().flatten() {
            let title = entry.get("title").and_then(|v| v.as_str()).unwrap_or("");
            let body = entry.get("body").and_then(|v| v.as_str()).unwrap_or("");
            let date = entry
                .get("createdAt")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            lines.push(format!("- ({date}) {title}: {body}"));
        }
    }
    if lines.is_empty() {
        return None;
    }
    Some(format!(
        "The user's relevant journal entries (use them to answer; do not invent others):\n{}",
        lines.join("\n")
    ))
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
