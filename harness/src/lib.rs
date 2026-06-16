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
//! # Tool loop (issues #10, #11)
//!
//! The reply JSON is one of two shapes:
//!   * `{"reply": "<text>"}`                          — final answer
//!   * `{"tool_calls": [{"id","name","arguments"}]}`  — run these tools
//!
//! Tool calls run on one of two loci (declared in the launcher manifest):
//!   * *client* tools (`search_entries`, `attach_metadata`) go back to the
//!     browser, over the user's local data;
//!   * *enclave* tools (`embed`, `summarize`, `extract_metadata`) are executed
//!     in-enclave by the launcher against the models and looped straight back
//!     to us — the browser never sees them.
//!
//! The launcher is stateless, so each turn replays everything in the context:
//!   * `task`         — `"chat"` (default) or `"enrich"`
//!   * `messages`     — the user/assistant transcript, oldest first (chat)
//!   * `entry`        — the journal entry to enrich (enrich)
//!   * `tool_results` — results of the tool calls we asked for last turn
//!                      (client- *or* enclave-executed), empty on the first turn
//!   * `tools`        — the launcher's tool manifest. We read it only to learn
//!                      which enclave tools are *available* this deployment
//!                      (e.g. `embed` exists only when an embeddings model is
//!                      loaded); the launcher re-validates every call we emit.
//!
//! This module is a deliberately simple stand-in for the closed orchestration:
//!   * *chat* — embed the query (enclave) for semantic recall when available,
//!     then `search_entries` (client) the user's local journal, then answer
//!     grounded in whatever came back. Entries enter the enclave only via that
//!     client search (on-demand data minimization).
//!   * *enrich* — on entry save, run `summarize` + `extract_metadata` (+ `embed`
//!     when available) in the enclave, then write the result back with
//!     `attach_metadata` (client). One turn, both loci.
//!
//! A real harness would plan with the model; the *machinery* (manifest,
//! validation, multi-locus routing) is what issues #10/#11 build.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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
    /// `"chat"` (default) or `"enrich"`. Absent on legacy chat contexts.
    #[serde(default = "default_task")]
    task: String,
    /// The conversation so far, oldest first, validated host-side to contain
    /// only `user`/`assistant` roles (the system prompt is ours, below).
    #[serde(default)]
    messages: Vec<Message>,
    /// The entry to enrich (enrich task only).
    #[serde(default)]
    entry: Option<Entry>,
    /// Results of the tool calls we asked for on the previous turn — client- or
    /// enclave-executed. Empty on the first turn; populated by the launcher
    /// (enclave tools) or the client (`search_entries`/`attach_metadata`).
    #[serde(default)]
    tool_results: Vec<ToolResult>,
    /// The launcher's manifest. We read only the advertised tool *names* (to
    /// learn which enclave tools this deployment offers); the launcher enforces
    /// the rest, re-validating every call below.
    #[serde(default)]
    tools: Value,
}

fn default_task() -> String {
    "chat".to_string()
}

#[derive(Deserialize, Serialize)]
struct Message {
    role: String,
    content: String,
}

/// The journal entry handed in for enrichment. Title/body are the user's data;
/// they stay inside the enclave (and this sandbox) for the duration of the call.
#[derive(Deserialize)]
struct Entry {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    body: String,
}

/// A tool result fed back: the call id, the tool name, and the tool's JSON
/// output (shape is tool-specific — `search_entries` → `{ "matches": [...] }`,
/// `embed` → `{ "embedding": [...] }`, `summarize` → `{ "summary": "..." }`,
/// `extract_metadata` → `{ "emotions", "situations", "lifePhases" }`).
#[derive(Deserialize)]
struct ToolResult {
    #[allow(dead_code)]
    id: String,
    name: String,
    result: Value,
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

/// The orchestration (the secret sauce): parse the context and route by task.
/// `None` on any failure.
fn orchestrate(ctx: &[u8]) -> Option<Vec<u8>> {
    let context: Context = serde_json::from_slice(ctx).ok()?;
    match context.task.as_str() {
        "enrich" => enrich(&context),
        _ => chat(&context),
    }
}

// ── chat ──────────────────────────────────────────────────────────────────

/// Chat orchestration. Drives the retrieve→answer loop, optionally embedding the
/// query first (enclave) so the client search can rank by semantic similarity.
fn chat(context: &Context) -> Option<Vec<u8>> {
    let results = &context.tool_results;

    // The client has searched: answer grounded in the matched entries.
    if has_result(results, "search_entries") {
        return answer(&context.messages, results);
    }

    // We asked to embed the query last turn (enclave). Now ask the client to
    // search: carry the embedding for semantic recall when it came back, but if
    // the embed failed (a result with no `embedding` — the launcher degrades a
    // down embeddings server to this) fall through to a keyword search instead
    // of re-embedding forever.
    if has_result(results, "embed") {
        let embedding = result_field(results, "embed", "embedding").cloned();
        return emit_search(&context.messages, embedding);
    }

    // Fresh user turn. Embed the query first when the deployment offers it;
    // otherwise go straight to a keyword search (graceful degradation).
    if tool_available(&context.tools, "embed") {
        return emit_embed(&context.messages);
    }
    emit_search(&context.messages, None)
}

/// Emit an `embed` call (enclave) seeded from the latest user message.
fn emit_embed(messages: &[Message]) -> Option<Vec<u8>> {
    let query = latest_user(messages)?;
    let call = json!({
        "id": format!("embed-{}", messages.len()),
        "name": "embed",
        "arguments": { "text": query },
    });
    serde_json::to_vec(&json!({ "tool_calls": [call] })).ok()
}

/// Emit a `search_entries` call (client) seeded from the latest user message,
/// optionally carrying the query embedding so the client can rank by similarity.
/// The id is keyed on the transcript length so a later turn's search never
/// clobbers an earlier turn's record (the client keys tool-activity UI on it).
fn emit_search(messages: &[Message], query_embedding: Option<Value>) -> Option<Vec<u8>> {
    let query = latest_user(messages)?;
    let mut arguments = json!({ "query": query, "limit": 5 });
    if let Some(embedding) = query_embedding {
        arguments["query_embedding"] = embedding;
    }
    let call = json!({
        "id": format!("search-{}", messages.len()),
        "name": "search_entries",
        "arguments": arguments,
    });
    serde_json::to_vec(&json!({ "tool_calls": [call] })).ok()
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

    let request = json!({ "messages": prompt, "max_tokens": MAX_TOKENS });
    let reply = call_model(&serde_json::to_vec(&request).ok()?)?;
    serde_json::to_vec(&json!({ "reply": reply })).ok()
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

// ── enrich ──────────────────────────────────────────────────────────────────

/// Entry-save enrichment. First turn: ask the enclave to summarize, extract
/// metadata, and (when available) embed the entry. Next turn: fold those
/// results into one enrichment object and write it back with `attach_metadata`
/// (client). Final turn: acknowledge once the client confirms the write.
fn enrich(context: &Context) -> Option<Vec<u8>> {
    let entry = context.entry.as_ref()?;
    let results = &context.tool_results;

    // The client has stored the enrichment — we are done.
    if has_result(results, "attach_metadata") {
        return serde_json::to_vec(&json!({
            "reply": "Reflected on your entry and saved the notes locally."
        }))
        .ok();
    }

    let want_embed = tool_available(&context.tools, "embed");
    if enclave_enrichment_ready(results, want_embed) {
        // Fold the enclave tool outputs into one enrichment object.
        let enrichment = assemble_enrichment(results);
        let call = json!({
            "id": format!("attach-{}", entry.id),
            "name": "attach_metadata",
            "arguments": { "entry_id": entry.id, "enrichment": enrichment },
        });
        return serde_json::to_vec(&json!({ "tool_calls": [call] })).ok();
    }

    // First turn: request the enclave enrichment primitives as one batch.
    let text = entry_text(entry);
    let mut calls = vec![
        json!({ "id": format!("summarize-{}", entry.id), "name": "summarize", "arguments": { "text": text } }),
        json!({ "id": format!("extract-{}", entry.id), "name": "extract_metadata", "arguments": { "text": text } }),
    ];
    if want_embed {
        calls.push(json!({
            "id": format!("embed-{}", entry.id),
            "name": "embed",
            "arguments": { "text": text },
        }));
    }
    serde_json::to_vec(&json!({ "tool_calls": calls })).ok()
}

/// Have all the enclave enrichment primitives come back? `summarize` and
/// `extract_metadata` always; `embed` only when this deployment offers it.
fn enclave_enrichment_ready(results: &[ToolResult], want_embed: bool) -> bool {
    has_result(results, "summarize")
        && has_result(results, "extract_metadata")
        && (!want_embed || has_result(results, "embed"))
}

/// Merge the `summarize`/`extract_metadata`/`embed` outputs into the enrichment
/// object the client stores. Missing fields are simply omitted — the client
/// sanitizes whatever it receives before persisting it.
fn assemble_enrichment(results: &[ToolResult]) -> Value {
    let mut enrichment = serde_json::Map::new();
    if let Some(summary) = result_field(results, "summarize", "summary") {
        enrichment.insert("summary".to_string(), summary.clone());
    }
    for field in ["emotions", "situations", "lifePhases"] {
        if let Some(value) = result_field(results, "extract_metadata", field) {
            enrichment.insert(field.to_string(), value.clone());
        }
    }
    if let Some(embedding) = result_field(results, "embed", "embedding") {
        enrichment.insert("embedding".to_string(), embedding.clone());
    }
    Value::Object(enrichment)
}

fn entry_text(entry: &Entry) -> String {
    if entry.title.is_empty() {
        entry.body.clone()
    } else {
        format!("{}\n\n{}", entry.title, entry.body)
    }
}

// ── shared helpers ──────────────────────────────────────────────────────────

/// The most recent user message's content.
fn latest_user(messages: &[Message]) -> Option<String> {
    messages
        .iter()
        .rev()
        .find(|m| m.role == "user")
        .map(|m| m.content.clone())
}

/// Is a tool with this name advertised in the launcher manifest? Used to learn
/// which optional enclave tools the deployment offers (e.g. `embed`).
fn tool_available(tools: &Value, name: &str) -> bool {
    tools
        .get("tools")
        .and_then(|t| t.as_array())
        .is_some_and(|arr| {
            arr.iter()
                .any(|t| t.get("name").and_then(|n| n.as_str()) == Some(name))
        })
}

/// Has any result with this tool name come back?
fn has_result(results: &[ToolResult], name: &str) -> bool {
    results.iter().any(|r| r.name == name)
}

/// Pull `result[field]` from the first result with this tool name.
fn result_field<'a>(results: &'a [ToolResult], name: &str, field: &str) -> Option<&'a Value> {
    results
        .iter()
        .find(|r| r.name == name)
        .and_then(|r| r.result.get(field))
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
