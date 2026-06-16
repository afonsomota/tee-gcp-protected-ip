//! POST /chat — model inference through the HPKE channel.
//!
//! Same envelope and key handling as `/hpke/echo` (see `hpke_channel.rs`
//! module docs), with chat-specific info strings. Request plaintext:
//!
//! ```json
//! {
//!   "messages": [{"role": "user|assistant", "content": "<utf-8 text>"}, ...],
//!   "reply_pub": "<base64 raw 32-byte X25519 key>"
//! }
//! ```
//!
//! `messages` is the full conversation so far, oldest first. Conversation
//! state lives only on the client (no server-side persistence of user
//! content), so each request carries the whole history; the launcher holds
//! it in memory only for the duration of the request. The decrypted history
//! is handed to the sandboxed wasm harness (`harness.rs`), which owns the
//! prompt orchestration and calls the supervised llama-server; the launcher
//! itself no longer constructs the prompt.
//!
//! # Tool loop (issues #10, #11)
//!
//! The harness may ask for tools instead of replying. The request carries an
//! optional `tool_results` array — the output of the tool calls the harness
//! asked for on the previous round — so the (stateless) launcher can replay the
//! loop each turn:
//!
//! ```json
//! {
//!   "messages": [{"role": "user|assistant", "content": "..."}, ...],
//!   "tool_results": [{"id": "...", "name": "...", "result": <json>}],
//!   "reply_pub": "<base64 raw 32-byte X25519 key>"
//! }
//! ```
//!
//! Each `tool_calls` batch the harness emits runs on a single *locus*
//! (`tools.rs`):
//!   * **client** tools (`search_entries`, `attach_metadata`) are sealed to
//!     `reply_pub` and returned to the browser, which runs them over local data
//!     and POSTs the results back for the next turn;
//!   * **enclave** tools (`embed`, `summarize`, `extract_metadata`) are executed
//!     in-enclave here (`enclave_tools.rs`) and looped straight back to the
//!     harness within the *same* request — the browser never sees them.
//!
//! So one user turn can drive several harness rounds: the launcher keeps
//! running the harness, executing any enclave tools it asks for, until the
//! harness either replies or asks for client tools. `MAX_ENCLAVE_ROUNDS` bounds
//! that internal loop.
//!
//! Response plaintext, sealed to `reply_pub`, is one of:
//!
//! ```json
//! {"reply": "<model-generated utf-8 text>"}
//! {"tool_calls": [{"id": "...", "name": "...", "arguments": <json>}]}  // client locus
//! ```
//!
//! # POST /enrich (issue #11)
//!
//! Entry-save enrichment shares this channel (distinct info strings) and the
//! same loop. The request carries the entry to enrich instead of a transcript:
//!
//! ```json
//! { "entry": {"id":"...","title":"...","body":"..."}, "tool_results": [...],
//!   "reply_pub": "..." }
//! ```
//!
//! The harness runs `summarize`/`extract_metadata`/`embed` (enclave), folds the
//! results into one enrichment object, and asks the client to `attach_metadata`
//! (the only thing returned to the browser). One turn, both loci.
//!
//! Crucially, the launcher re-validates every `tool_calls` entry the harness
//! emits against its own manifest (`tools.rs`) before sealing or executing it:
//! the harness is untrusted, so it must not be able to ask for an undeclared
//! capability, mix loci in one batch, or hand the browser an enclave tool.
//! Plaintext exists only inside these handlers; the model's input and output
//! never leave the enclave unencrypted.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::enclave_tools::Upstreams;
use crate::hpke_channel::{open, seal, Envelope};
use crate::AppState;

pub const REQUEST_INFO: &[u8] = b"tee-example/hpke/chat/request/v1";
pub const RESPONSE_INFO: &[u8] = b"tee-example/hpke/chat/response/v1";
pub const ENRICH_REQUEST_INFO: &[u8] = b"tee-example/hpke/enrich/request/v1";
pub const ENRICH_RESPONSE_INFO: &[u8] = b"tee-example/hpke/enrich/response/v1";

/// Bound on how many times one request may run the harness while executing the
/// enclave tools it asks for, before giving up. Generous: chat needs 1–2
/// (embed → search), enrich needs 2 (enclave batch → attach), but a buggy
/// harness must not spin forever.
const MAX_ENCLAVE_ROUNDS: usize = 6;

/// Cap on the per-field entry text fed to the enclave models on `/enrich`. The
/// token budgets in `enclave_tools.rs` bound model *output*; this bounds *input*
/// so an over-large entry can't turn one save into unbounded in-enclave
/// inference. The text never leaves the enclave, so this is a work cap, not a
/// privacy one; the limits are generous for a journal entry.
const MAX_ENRICH_TITLE_CHARS: usize = 1_024;
const MAX_ENRICH_BODY_CHARS: usize = 16_384;

#[derive(Deserialize)]
struct ChatRequest {
    /// Full conversation so far, oldest first.
    messages: Vec<Message>,
    /// Results of the tool calls the harness asked for on the previous round.
    /// Empty/absent on the first turn of a user message. Passed through to the
    /// harness verbatim; these are the user's own data flowing back in.
    #[serde(default)]
    tool_results: Vec<ToolResult>,
    /// Base64 raw 32-byte X25519 public key the response is sealed to.
    reply_pub: String,
}

/// /enrich request: the entry to enrich plus any prior tool results.
#[derive(Deserialize)]
struct EnrichRequest {
    entry: Entry,
    #[serde(default)]
    tool_results: Vec<ToolResult>,
    reply_pub: String,
}

/// The journal entry handed in for enrichment. Round-trips into the harness
/// context verbatim; `title`/`body` are the user's data and stay in-enclave.
#[derive(Deserialize, Serialize)]
struct Entry {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    body: String,
}

#[derive(Deserialize, Serialize)]
struct Message {
    role: String,
    content: String,
}

/// One tool result (client- or enclave-executed), echoed back for the next
/// harness turn.
#[derive(Deserialize, Serialize)]
struct ToolResult {
    id: String,
    name: String,
    result: Value,
}

/// An enclave-locus tool call the harness asked for, already manifest-validated,
/// ready to execute in-enclave.
#[derive(Debug)]
struct EnclaveCall {
    id: String,
    name: String,
    arguments: Value,
}

/// How the launcher routes one harness reply.
#[derive(Debug)]
enum Routed {
    /// A final `{"reply":...}` or a client-locus `{"tool_calls":...}` batch —
    /// seal the harness bytes verbatim and return them to the browser.
    ToClient,
    /// An enclave-locus `{"tool_calls":...}` batch — execute in-enclave and
    /// loop the results back to the harness.
    Enclave(Vec<EnclaveCall>),
}

/// The system prompt is the launcher's (and later the harness's), never the
/// client's; anything else here would let a client smuggle in roles
/// llama-server treats specially.
fn validate(messages: &[Message]) -> Result<(), String> {
    if messages.is_empty() {
        return Err("messages must not be empty".to_string());
    }
    // Error responses go back unencrypted; name the offending index, never
    // the decrypted value (see the invariant in `chat` below).
    if let Some(i) = messages
        .iter()
        .position(|m| m.role != "user" && m.role != "assistant")
    {
        return Err(format!(
            "message {i}: role must be \"user\" or \"assistant\""
        ));
    }
    Ok(())
}

pub async fn chat(State(state): State<AppState>, Json(envelope): Json<Envelope>) -> Response {
    let (upstream, harness) = match ready(&state) {
        Ok(pair) => pair,
        Err(message) => return error(StatusCode::SERVICE_UNAVAILABLE, message),
    };
    // Decrypt and validate before touching the model. Error strings up to
    // and including decryption describe only attacker-supplied ciphertext
    // (bad base64, bad envelope) — never decrypted content. Keep that
    // invariant: client-visible errors must not carry plaintext fragments.
    let request: ChatRequest = match decrypt_request(&state, &envelope, REQUEST_INFO) {
        Ok(r) => r,
        Err(message) => return error(StatusCode::BAD_REQUEST, &message),
    };
    // Defense in depth: reject client-smuggled roles before the sandbox ever
    // sees them, even though the harness re-derives the system prompt itself.
    if let Err(message) = validate(&request.messages) {
        return error(StatusCode::BAD_REQUEST, &message);
    }
    let reply_pub = match decode_reply_pub(&request.reply_pub) {
        Ok(k) => k,
        Err(message) => return error(StatusCode::BAD_REQUEST, &message),
    };

    let upstreams = Upstreams {
        chat: upstream,
        embeddings: state.embeddings.clone(),
    };
    let manifest = crate::tools::manifest_json(upstreams.embeddings.is_some());
    let ChatRequest {
        messages,
        tool_results,
        ..
    } = request;

    // Run the harness, executing any enclave tools it asks for, until it
    // replies or asks the client to run a tool. The manifest tells the harness
    // which enclave tools this deployment offers (e.g. `embed`). On the chat
    // path a transient `embed` failure degrades to keyword search rather than
    // failing the whole turn (`degrade_embed`).
    let result = drive_loop(&upstreams, &harness, tool_results, true, |results| {
        json!({
            "task": "chat",
            "messages": &messages,
            "tool_results": results,
            "tools": &manifest,
        })
        .to_string()
    })
    .await;
    seal_or_error(result, &reply_pub, RESPONSE_INFO)
}

pub async fn enrich(State(state): State<AppState>, Json(envelope): Json<Envelope>) -> Response {
    let (upstream, harness) = match ready(&state) {
        Ok(pair) => pair,
        Err(message) => return error(StatusCode::SERVICE_UNAVAILABLE, message),
    };
    let request: EnrichRequest = match decrypt_request(&state, &envelope, ENRICH_REQUEST_INFO) {
        Ok(r) => r,
        Err(message) => return error(StatusCode::BAD_REQUEST, &message),
    };
    if request.entry.id.is_empty() {
        return error(StatusCode::BAD_REQUEST, "entry.id must not be empty");
    }
    let reply_pub = match decode_reply_pub(&request.reply_pub) {
        Ok(k) => k,
        Err(message) => return error(StatusCode::BAD_REQUEST, &message),
    };

    let upstreams = Upstreams {
        chat: upstream,
        embeddings: state.embeddings.clone(),
    };
    let manifest = crate::tools::manifest_json(upstreams.embeddings.is_some());
    let EnrichRequest {
        mut entry,
        tool_results,
        ..
    } = request;
    // Bound the work one save can trigger: cap the text handed to the enclave
    // models. Stays in-enclave, so this is a work cap, not a privacy boundary.
    truncate_chars(&mut entry.title, MAX_ENRICH_TITLE_CHARS);
    truncate_chars(&mut entry.body, MAX_ENRICH_BODY_CHARS);

    // Enrich is best-effort and the client swallows a failure, so an enclave
    // tool error fails the turn (no `degrade_embed`) rather than half-enriching.
    let result = drive_loop(&upstreams, &harness, tool_results, false, |results| {
        json!({
            "task": "enrich",
            "entry": &entry,
            "tool_results": results,
            "tools": &manifest,
        })
        .to_string()
    })
    .await;
    seal_or_error(result, &reply_pub, ENRICH_RESPONSE_INFO)
}

/// Both endpoints need a chat upstream and a loaded harness; resolve them or
/// return the (503) message to serve (the same "errors until ready" window as
/// artifact-delivered weights).
fn ready(
    state: &AppState,
) -> Result<(String, std::sync::Arc<crate::harness::Harness>), &'static str> {
    let Some(upstream) = state.inference.clone() else {
        return Err("inference not configured: no model loaded in this launcher");
    };
    let Some(harness) = state.harness.get() else {
        return Err("harness not ready: signed orchestration not yet loaded");
    };
    Ok((upstream, harness))
}

/// Drive the harness, executing the enclave tools it asks for in-enclave and
/// looping their results back, until it replies or asks the client to run a
/// tool. Returns the harness's reply bytes (a `{"reply":...}` or a client-locus
/// `{"tool_calls":...}`) to seal, or `Err(())` on any failure (logged with no
/// plaintext). `build_context` produces the harness context for the current
/// accumulated tool results.
///
/// When `degrade_embed` is set (the chat path), a failing `embed` does not abort
/// the turn: the harness is fed an embed result with no embedding and falls
/// through to keyword `search_entries`, so a momentarily-down embeddings server
/// degrades to keyword search instead of 502-ing the whole chat. Other tools,
/// and the enrich path, still abort on failure.
async fn drive_loop(
    upstreams: &Upstreams,
    harness: &crate::harness::Harness,
    mut results: Vec<ToolResult>,
    degrade_embed: bool,
    build_context: impl Fn(&[ToolResult]) -> String,
) -> Result<Vec<u8>, ()> {
    for _round in 0..MAX_ENCLAVE_ROUNDS {
        let context = build_context(&results);
        let output = match harness.run(&upstreams.chat, context.as_bytes()).await {
            Ok(bytes) => bytes,
            // harness.run errors carry no plaintext; the (status/len-only)
            // detail goes to logs, the caller serves a generic 502.
            Err(detail) => {
                eprintln!("chat: harness run failed: {detail}");
                return Err(());
            }
        };
        // The harness is untrusted: gate every call it emits against the
        // manifest before sealing it to the client or executing it in-enclave.
        match classify_harness_output(&output) {
            Ok(Routed::ToClient) => return Ok(output),
            Ok(Routed::Enclave(calls)) => {
                for call in calls {
                    match crate::enclave_tools::execute(&call.name, &call.arguments, upstreams)
                        .await
                    {
                        Ok(result) => results.push(ToolResult {
                            id: call.id,
                            name: call.name,
                            result,
                        }),
                        // Chat-path embed: degrade to keyword search. Feed the
                        // harness an embed result with no `embedding` field; its
                        // chat branch falls through to a keyword search_entries.
                        // The detail is plaintext-free (tool + shape only).
                        Err(detail) if degrade_embed && call.name == "embed" => {
                            eprintln!("chat: embed failed, degrading to keyword search: {detail}");
                            results.push(ToolResult {
                                id: call.id,
                                name: call.name,
                                result: json!({ "error": "embedding unavailable" }),
                            });
                        }
                        Err(detail) => {
                            eprintln!("chat: enclave tool failed: {detail}");
                            return Err(());
                        }
                    }
                }
                // Loop: re-run the harness with the enclave results appended.
            }
            Err(detail) => {
                eprintln!("chat: harness output rejected: {detail}");
                return Err(());
            }
        }
    }
    eprintln!("chat: enclave tool loop exceeded {MAX_ENCLAVE_ROUNDS} rounds");
    Err(())
}

/// Truncate `s` in place to at most `max` characters (UTF-8-safe). No-op when
/// already within bound.
fn truncate_chars(s: &mut String, max: usize) {
    if let Some((idx, _)) = s.char_indices().nth(max) {
        s.truncate(idx);
    }
}

/// Seal the harness reply bytes to `reply_pub`, or turn a loop failure into a
/// generic 502 (the detail was already logged).
fn seal_or_error(result: Result<Vec<u8>, ()>, reply_pub: &[u8], info: &[u8]) -> Response {
    let plaintext = match result {
        Ok(bytes) => bytes,
        Err(()) => return error(StatusCode::BAD_GATEWAY, "inference failed"),
    };
    match seal(reply_pub, info, &plaintext) {
        Ok((enc, ct)) => Json(Envelope {
            enc: B64.encode(enc),
            ct: B64.encode(ct),
        })
        .into_response(),
        Err(message) => error(StatusCode::BAD_REQUEST, &message),
    }
}

fn decode_reply_pub(reply_pub: &str) -> Result<Vec<u8>, String> {
    B64.decode(reply_pub)
        .map_err(|e| format!("reply_pub is not valid base64: {e}"))
}

fn decrypt_request<T: serde::de::DeserializeOwned>(
    state: &AppState,
    envelope: &Envelope,
    info: &[u8],
) -> Result<T, String> {
    let enc = B64
        .decode(&envelope.enc)
        .map_err(|e| format!("enc is not valid base64: {e}"))?;
    let ct = B64
        .decode(&envelope.ct)
        .map_err(|e| format!("ct is not valid base64: {e}"))?;
    let plaintext = open(state.keys.hpke_private(), &enc, info, &ct)?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| format!("request plaintext is not valid JSON: {e}"))
}

/// Classify and validate the harness's reply JSON against the manifest. A
/// `{"reply":...}` answer or a client-locus `{"tool_calls":...}` batch routes
/// `ToClient` (seal verbatim); an enclave-locus batch routes `Enclave` (execute
/// in-enclave). Every call must name a manifest tool and be well-formed, and a
/// `tool_calls` batch must be single-locus — a harness must not mix loci or
/// hand the browser an enclave tool. Anything else is rejected.
fn classify_harness_output(bytes: &[u8]) -> Result<Routed, String> {
    let output: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("harness reply is not JSON: {e}"))?;

    let Some(tool_calls) = output.get("tool_calls") else {
        // No tool calls: must be a plain reply.
        if output.get("reply").and_then(Value::as_str).is_some() {
            return Ok(Routed::ToClient);
        }
        return Err("harness reply has neither \"reply\" nor \"tool_calls\"".to_string());
    };

    let calls = tool_calls
        .as_array()
        .ok_or("harness \"tool_calls\" must be an array")?;
    if calls.is_empty() {
        return Err("harness emitted an empty \"tool_calls\" array".to_string());
    }

    let mut enclave_calls = Vec::new();
    let mut saw_client = false;
    for call in calls {
        let name = call
            .get("name")
            .and_then(Value::as_str)
            .ok_or("tool call missing a string \"name\"")?;
        let arguments = call.get("arguments").unwrap_or(&Value::Null);
        let spec = crate::tools::validate_call(name, arguments)?;
        match spec.locus {
            crate::tools::Locus::Client => saw_client = true,
            crate::tools::Locus::Enclave => enclave_calls.push(EnclaveCall {
                id: call
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                name: name.to_string(),
                arguments: arguments.clone(),
            }),
        }
    }
    // A batch must be single-locus: mixing would mean partly returning to the
    // browser and partly executing in-enclave, which the loop can't represent
    // and the harness has no need to do.
    if saw_client && !enclave_calls.is_empty() {
        return Err("harness mixed client and enclave tools in one batch".to_string());
    }
    if enclave_calls.is_empty() {
        Ok(Routed::ToClient)
    } else {
        Ok(Routed::Enclave(enclave_calls))
    }
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    // Shared with harness.rs's tests; chat asserts only on the non-system
    // turns it sent, so it forwards `false` to the mock.
    use crate::keys::EnclaveKeys;
    use crate::test_support::{fixture_file, mock_embeddings, mock_llama};
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::post;
    use axum::Router;
    use hpke::{Deserializable, Kem as KemTrait, Serializable};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    type Kem = hpke::kem::X25519HkdfSha256;

    fn test_state(inference: Option<String>) -> AppState {
        test_state_with_embeddings(inference, None)
    }

    fn test_state_with_embeddings(
        inference: Option<String>,
        embeddings: Option<String>,
    ) -> AppState {
        AppState {
            keys: Arc::new(EnclaveKeys::generate()),
            dev: false,
            inference,
            embeddings,
            harness: Arc::new(load_fixture_harness()),
        }
    }

    /// Load the committed, signed harness fixture into a ready slot so `/chat`
    /// routes through the real wasm module (built by scripts/build-harness.sh).
    fn load_fixture_harness() -> crate::harness::HarnessSlot {
        let harness = crate::harness::Harness::new(
            &fixture_file("harness.wasm"),
            &fixture_file("harness.wasm.sig"),
        )
        .expect("fixture harness should verify");
        crate::harness::HarnessSlot::loaded(Arc::new(harness))
    }

    async fn post_chat(
        state: AppState,
        envelope: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let response = crate::app(state)
            .oneshot(
                Request::post("/chat")
                    .header("content-type", "application/json")
                    .body(Body::from(envelope.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn sealed_history(
        state: &AppState,
        messages: serde_json::Value,
    ) -> (serde_json::Value, <Kem as KemTrait>::PrivateKey) {
        let mut csprng = <rand::rngs::StdRng as rand::SeedableRng>::from_os_rng();
        let (reply_sk, reply_pk) = Kem::gen_keypair(&mut csprng);
        let request = json!({ "messages": messages, "reply_pub": B64.encode(reply_pk.to_bytes()) });
        let (enc, ct) = seal(
            &state.keys.hpke_public_bytes(),
            REQUEST_INFO,
            request.to_string().as_bytes(),
        )
        .unwrap();
        (
            json!({ "enc": B64.encode(enc), "ct": B64.encode(ct) }),
            reply_sk,
        )
    }

    /// A one-turn conversation: a single user message.
    fn sealed_request(
        state: &AppState,
        msg: &str,
    ) -> (serde_json::Value, <Kem as KemTrait>::PrivateKey) {
        sealed_history(state, json!([{ "role": "user", "content": msg }]))
    }

    /// A follow-up turn carrying the results of a prior tool call, which sends
    /// the harness down its "answer" branch (it calls the model).
    fn sealed_turn(
        state: &AppState,
        messages: serde_json::Value,
        tool_results: serde_json::Value,
    ) -> (serde_json::Value, <Kem as KemTrait>::PrivateKey) {
        let mut csprng = <rand::rngs::StdRng as rand::SeedableRng>::from_os_rng();
        let (reply_sk, reply_pk) = Kem::gen_keypair(&mut csprng);
        let request = json!({
            "messages": messages,
            "tool_results": tool_results,
            "reply_pub": B64.encode(reply_pk.to_bytes()),
        });
        let (enc, ct) = seal(
            &state.keys.hpke_public_bytes(),
            REQUEST_INFO,
            request.to_string().as_bytes(),
        )
        .unwrap();
        (
            json!({ "enc": B64.encode(enc), "ct": B64.encode(ct) }),
            reply_sk,
        )
    }

    /// A `search_entries` tool result wrapping the given matched entries.
    fn search_results(matches: serde_json::Value) -> serde_json::Value {
        json!([{ "id": "search-1", "name": "search_entries", "result": { "matches": matches } }])
    }

    fn open_reply(
        reply_sk: &<Kem as KemTrait>::PrivateKey,
        reply: &serde_json::Value,
    ) -> serde_json::Value {
        let plaintext = open(
            reply_sk,
            &B64.decode(reply["enc"].as_str().unwrap()).unwrap(),
            RESPONSE_INFO,
            &B64.decode(reply["ct"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        serde_json::from_slice(&plaintext).unwrap()
    }

    #[tokio::test]
    async fn chat_first_turn_requests_a_client_search() {
        // A fresh user message (no tool_results) makes the harness ask the
        // client to retrieve relevant entries before answering — the
        // data-minimization step. The sealed reply carries a manifest-valid
        // tool call, not a model reply.
        let upstream = mock_llama(false).await;
        let state = test_state(Some(upstream));
        let (envelope, reply_sk) = sealed_request(&state, "how was my week?");

        let (status, reply) = post_chat(state, envelope).await;
        assert_eq!(status, StatusCode::OK);

        let body = open_reply(&reply_sk, &reply);
        assert!(
            body.get("reply").is_none(),
            "expected a tool call, got a reply"
        );
        let calls = body["tool_calls"].as_array().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["name"], "search_entries");
        assert_eq!(calls[0]["arguments"]["query"], "how was my week?");
    }

    #[tokio::test]
    async fn chat_answers_once_tool_results_arrive() {
        // Second leg of the loop: the client has run the search and fed back a
        // matched entry. The harness now calls the model, grounding the reply
        // in the retrieved entry, and the launcher seals the answer.
        let upstream = mock_llama(true).await;
        let state = test_state(Some(upstream));
        let (envelope, reply_sk) = sealed_turn(
            &state,
            json!([{ "role": "user", "content": "how was my week?" }]),
            search_results(json!([
                { "id": "e1", "title": "Monday", "body": "got the new job", "createdAt": "2026-06-01" },
            ])),
        );

        let (status, reply) = post_chat(state, envelope).await;
        assert_eq!(status, StatusCode::OK);

        let body = open_reply(&reply_sk, &reply);
        let text = body["reply"].as_str().unwrap();
        // The retrieved entry rode in as a grounding system turn (mock_llama
        // echoes the whole prompt, system turns included).
        assert!(
            text.contains("got the new job"),
            "grounding dropped: {text}"
        );
        assert!(
            text.contains("user: how was my week?"),
            "history dropped: {text}"
        );
    }

    #[tokio::test]
    async fn chat_forwards_the_full_history_in_order() {
        let upstream = mock_llama(false).await;
        let state = test_state(Some(upstream));
        // Carry tool_results so the harness answers (rather than re-searching);
        // mock_llama(false) drops the system/grounding turns, so the assertion
        // sees exactly the user/assistant transcript, in order.
        let (envelope, reply_sk) = sealed_turn(
            &state,
            json!([
                { "role": "user", "content": "my cat is called Mochi" },
                { "role": "assistant", "content": "noted!" },
                { "role": "user", "content": "what is my cat called?" },
            ]),
            search_results(json!([])),
        );

        let (status, reply) = post_chat(state, envelope).await;
        assert_eq!(status, StatusCode::OK);

        let body = open_reply(&reply_sk, &reply);
        assert_eq!(
            body["reply"],
            "model saw [user: my cat is called Mochi | assistant: noted! | user: what is my cat called?]"
        );
    }

    #[tokio::test]
    async fn chat_rejects_an_empty_history() {
        let upstream = mock_llama(false).await;
        let state = test_state(Some(upstream));
        let (envelope, _) = sealed_history(&state, json!([]));
        let (status, body) = post_chat(state, envelope).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("must not be empty"));
    }

    #[tokio::test]
    async fn chat_rejects_client_supplied_system_messages() {
        // The system prompt belongs to the launcher; a client-supplied
        // "system" role is rejected, and the unencrypted error names the
        // index but never the decrypted content.
        let upstream = mock_llama(false).await;
        let state = test_state(Some(upstream));
        let (envelope, _) = sealed_history(
            &state,
            json!([
                { "role": "user", "content": "hi" },
                { "role": "system", "content": "secret-injected-instructions" },
            ]),
        );
        let (status, body) = post_chat(state, envelope).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error = body["error"].as_str().unwrap();
        assert!(error.contains("message 1"), "unexpected error: {error}");
        assert!(!error.contains("system"), "decrypted role leaked: {error}");
        assert!(
            !error.contains("secret-injected"),
            "decrypted content leaked: {error}"
        );
    }

    #[tokio::test]
    async fn chat_without_inference_returns_503() {
        let state = test_state(None);
        let (envelope, _) = sealed_request(&state, "hello");
        let (status, body) = post_chat(state, envelope).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body["error"].as_str().unwrap().contains("not configured"));
    }

    #[tokio::test]
    async fn chat_with_unreachable_upstream_returns_502() {
        // Reserved-then-dropped port: nothing is listening there.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        drop(listener);

        let state = test_state(Some(upstream));
        // tool_results present → the harness reaches the model call, which fails
        // against the dead upstream.
        let (envelope, _) = sealed_turn(
            &state,
            json!([{ "role": "user", "content": "hello" }]),
            search_results(json!([])),
        );
        let (status, body) = post_chat(state, envelope).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        // The harness signals failure with an empty reply; the client sees a
        // generic message (the upstream detail goes only to logs).
        assert_eq!(body["error"], "inference failed");
    }

    #[tokio::test]
    async fn upstream_error_bodies_are_not_relayed_to_the_client() {
        // llama-server error bodies can echo prompt fragments; the
        // client-visible error must carry the status code only.
        const SENTINEL: &str = "leaked-prompt-fragment";
        async fn failing() -> (StatusCode, String) {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("context overflow while processing: {SENTINEL}"),
            )
        }
        let app = Router::new().route("/v1/chat/completions", post(failing));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let state = test_state(Some(upstream));
        // tool_results present → the harness reaches the model call, whose
        // error body must not be relayed.
        let (envelope, _) = sealed_turn(
            &state,
            json!([{ "role": "user", "content": "hello" }]),
            search_results(json!([])),
        );
        let (status, body) = post_chat(state, envelope).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        let error = body["error"].as_str().unwrap();
        // Generic message, and crucially no echoed prompt fragment.
        assert_eq!(error, "inference failed");
        assert!(!error.contains(SENTINEL), "upstream body leaked: {error}");
    }

    // ── manifest enforcement + locus routing on harness output ────────────────

    fn routes_to_client(bytes: &[u8]) -> bool {
        matches!(classify_harness_output(bytes), Ok(Routed::ToClient))
    }

    #[test]
    fn classify_routes_a_plain_reply_to_the_client() {
        assert!(routes_to_client(br#"{"reply":"hello"}"#));
    }

    #[test]
    fn classify_routes_a_client_tool_call_to_the_client() {
        let ok =
            br#"{"tool_calls":[{"id":"1","name":"search_entries","arguments":{"query":"x"}}]}"#;
        assert!(routes_to_client(ok));
    }

    #[test]
    fn classify_routes_enclave_tool_calls_for_in_enclave_execution() {
        // An enclave-locus batch is executed in-enclave, never returned to the
        // browser; classify hands back the parsed calls to run.
        let bytes = br#"{"tool_calls":[
            {"id":"s","name":"summarize","arguments":{"text":"x"}},
            {"id":"e","name":"extract_metadata","arguments":{"text":"x"}}
        ]}"#;
        let Ok(Routed::Enclave(calls)) = classify_harness_output(bytes) else {
            panic!("expected enclave routing");
        };
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].name, "summarize");
    }

    #[test]
    fn classify_rejects_a_mixed_locus_batch() {
        // A batch that mixes a client tool with an enclave tool is refused — the
        // launcher cannot both seal it to the browser and run it in-enclave.
        let bad = br#"{"tool_calls":[
            {"id":"1","name":"search_entries","arguments":{"query":"x"}},
            {"id":"2","name":"summarize","arguments":{"text":"x"}}
        ]}"#;
        let err = classify_harness_output(bad).unwrap_err();
        assert!(err.contains("mixed"), "unexpected error: {err}");
    }

    #[test]
    fn classify_rejects_an_unknown_tool() {
        // A hostile/buggy harness cannot smuggle an undeclared capability
        // anywhere: anything not in the manifest is refused.
        let bad = br#"{"tool_calls":[{"id":"1","name":"exfiltrate","arguments":{}}]}"#;
        let err = classify_harness_output(bad).unwrap_err();
        assert!(err.contains("not in manifest"), "unexpected error: {err}");
    }

    #[test]
    fn classify_rejects_a_malformed_call() {
        // Missing the required `query` argument for search_entries.
        let bad = br#"{"tool_calls":[{"id":"1","name":"search_entries","arguments":{}}]}"#;
        let err = classify_harness_output(bad).unwrap_err();
        assert!(err.contains("query"), "unexpected error: {err}");
    }

    #[test]
    fn classify_rejects_a_shapeless_reply() {
        let err = classify_harness_output(br#"{"nonsense":true}"#).unwrap_err();
        assert!(err.contains("neither"), "unexpected error: {err}");
    }

    // ── enclave-tool loop: chat semantic recall + entry enrichment ────────────

    /// Seal an /enrich request for `entry`, optionally carrying prior tool
    /// results. Mirrors `sealed_turn` but for the enrich channel + info string.
    fn sealed_enrich(
        state: &AppState,
        entry: serde_json::Value,
        tool_results: serde_json::Value,
    ) -> (serde_json::Value, <Kem as KemTrait>::PrivateKey) {
        let mut csprng = <rand::rngs::StdRng as rand::SeedableRng>::from_os_rng();
        let (reply_sk, reply_pk) = Kem::gen_keypair(&mut csprng);
        let request = json!({
            "entry": entry,
            "tool_results": tool_results,
            "reply_pub": B64.encode(reply_pk.to_bytes()),
        });
        let (enc, ct) = seal(
            &state.keys.hpke_public_bytes(),
            ENRICH_REQUEST_INFO,
            request.to_string().as_bytes(),
        )
        .unwrap();
        (
            json!({ "enc": B64.encode(enc), "ct": B64.encode(ct) }),
            reply_sk,
        )
    }

    async fn post_to(
        state: AppState,
        path: &str,
        envelope: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let response = crate::app(state)
            .oneshot(
                Request::post(path)
                    .header("content-type", "application/json")
                    .body(Body::from(envelope.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn open_enrich_reply(
        reply_sk: &<Kem as KemTrait>::PrivateKey,
        reply: &serde_json::Value,
    ) -> serde_json::Value {
        let plaintext = open(
            reply_sk,
            &B64.decode(reply["enc"].as_str().unwrap()).unwrap(),
            ENRICH_RESPONSE_INFO,
            &B64.decode(reply["ct"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        serde_json::from_slice(&plaintext).unwrap()
    }

    #[tokio::test]
    async fn chat_embeds_the_query_in_enclave_then_asks_the_client_to_search() {
        // With an embeddings instance configured, a fresh user turn drives an
        // in-enclave `embed` (executed here, never returned) and *then* a client
        // `search_entries` carrying the query embedding for semantic ranking.
        let chat = mock_llama(false).await;
        let embed = mock_embeddings().await;
        let state = test_state_with_embeddings(Some(chat), Some(embed));
        let (envelope, reply_sk) = sealed_request(&state, "how was my week?");

        let (status, reply) = post_chat(state, envelope).await;
        assert_eq!(status, StatusCode::OK);

        let body = open_reply(&reply_sk, &reply);
        let calls = body["tool_calls"].as_array().expect("expected a tool call");
        assert_eq!(calls[0]["name"], "search_entries");
        assert_eq!(calls[0]["arguments"]["query"], "how was my week?");
        // The query embedding (from the in-enclave embed) rides along so the
        // client can rank by similarity. mock_embeddings returns len-derived
        // values; "how was my week?" is 16 chars.
        assert_eq!(
            calls[0]["arguments"]["query_embedding"],
            json!([16.0, 17.0, 18.0])
        );
    }

    #[tokio::test]
    async fn chat_degrades_to_keyword_search_when_embed_fails() {
        // Embeddings configured but momentarily down (server mid-restart): the
        // chat turn must not 502. The in-enclave embed fails, the launcher
        // degrades, and the harness falls through to a keyword search_entries
        // (carrying no query_embedding) rather than aborting the whole turn.
        let chat = mock_llama(false).await;
        // Reserved-then-dropped port: the embeddings upstream refuses connections.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_embed = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        drop(listener);

        let state = test_state_with_embeddings(Some(chat), Some(dead_embed));
        let (envelope, reply_sk) = sealed_request(&state, "how was my week?");

        let (status, reply) = post_chat(state, envelope).await;
        assert_eq!(status, StatusCode::OK);

        let body = open_reply(&reply_sk, &reply);
        let calls = body["tool_calls"].as_array().expect("expected a tool call");
        assert_eq!(calls[0]["name"], "search_entries");
        assert_eq!(calls[0]["arguments"]["query"], "how was my week?");
        // Embed failed → no semantic embedding rides along; keyword-only fallback.
        assert!(
            calls[0]["arguments"].get("query_embedding").is_none(),
            "expected keyword fallback, got a query_embedding"
        );
    }

    #[test]
    fn truncate_chars_caps_at_boundary_and_is_utf8_safe() {
        let mut s = "abcdef".to_string();
        truncate_chars(&mut s, 3);
        assert_eq!(s, "abc");
        // Already within bound: untouched.
        let mut short = "ab".to_string();
        truncate_chars(&mut short, 3);
        assert_eq!(short, "ab");
        // Counts chars, not bytes, and never splits a multi-byte char.
        let mut multi = "áéíóú".to_string();
        truncate_chars(&mut multi, 2);
        assert_eq!(multi, "áé");
    }

    #[tokio::test]
    async fn enrich_runs_enclave_tools_then_asks_the_client_to_store() {
        // One enrich turn: the harness runs summarize + extract_metadata + embed
        // in-enclave (executed here), folds them into one enrichment object, and
        // asks the client to attach_metadata — the only thing returned.
        let chat = mock_llama(false).await;
        let embed = mock_embeddings().await;
        let state = test_state_with_embeddings(Some(chat), Some(embed));
        let entry =
            json!({ "id": "e1", "title": "New job", "body": "first week, nervous but excited" });
        let (envelope, reply_sk) = sealed_enrich(&state, entry, json!([]));

        let (status, reply) = post_to(state, "/enrich", envelope).await;
        assert_eq!(status, StatusCode::OK);

        let body = open_enrich_reply(&reply_sk, &reply);
        let calls = body["tool_calls"].as_array().expect("expected a tool call");
        assert_eq!(calls[0]["name"], "attach_metadata");
        assert_eq!(calls[0]["arguments"]["entry_id"], "e1");
        let enrichment = &calls[0]["arguments"]["enrichment"];
        // summarize echoed the entry text (mock_llama), so the summary carries it.
        assert!(enrichment["summary"]
            .as_str()
            .unwrap()
            .contains("first week"));
        // extract_metadata's reply isn't JSON (mock_llama echoes), so the tags
        // degrade to empty arrays — present, not absent.
        assert_eq!(enrichment["emotions"], json!([]));
        // The embedding threaded through from the in-enclave embed tool.
        assert!(enrichment["embedding"].as_array().unwrap().len() == 3);
    }

    #[tokio::test]
    async fn enrich_acknowledges_once_the_client_has_stored() {
        // Second enrich leg: the client reports attach_metadata done; the
        // harness replies with a confirmation (no further tool calls).
        let chat = mock_llama(false).await;
        let state = test_state_with_embeddings(Some(chat), None);
        let entry = json!({ "id": "e1", "title": "New job", "body": "..." });
        let (envelope, reply_sk) = sealed_enrich(
            &state,
            entry,
            json!([{ "id": "attach-e1", "name": "attach_metadata", "result": { "ok": true } }]),
        );

        let (status, reply) = post_to(state, "/enrich", envelope).await;
        assert_eq!(status, StatusCode::OK);

        let body = open_enrich_reply(&reply_sk, &reply);
        assert!(body["reply"].as_str().is_some(), "expected a final reply");
        assert!(body.get("tool_calls").is_none());
    }

    #[tokio::test]
    async fn enrich_rejects_an_empty_entry_id() {
        let state = test_state(Some(mock_llama(false).await));
        let (envelope, _) = sealed_enrich(&state, json!({ "id": "" }), json!([]));
        let (status, body) = post_to(state, "/enrich", envelope).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("entry.id"));
    }

    #[tokio::test]
    async fn chat_rejects_envelope_sealed_with_echo_info_string() {
        // Domain separation: an /hpke/echo request must not decrypt as /chat.
        let upstream = mock_llama(false).await;
        let state = test_state(Some(upstream));
        let mut csprng = <rand::rngs::StdRng as rand::SeedableRng>::from_os_rng();
        let (_, reply_pk) = Kem::gen_keypair(&mut csprng);
        let request = json!({ "msg": "x", "reply_pub": B64.encode(reply_pk.to_bytes()) });
        let (enc, ct) = seal(
            &state.keys.hpke_public_bytes(),
            crate::hpke_channel::REQUEST_INFO,
            request.to_string().as_bytes(),
        )
        .unwrap();
        let envelope = json!({ "enc": B64.encode(enc), "ct": B64.encode(ct) });
        let (status, body) = post_chat(state, envelope).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("open failed"));
    }

    // ── HPKE chat channel interop fixtures ────────────────────────────────────
    // The same fixture pattern as hpke_channel.rs: Rust generates its own
    // vectors (request and response info strings separately); pnpm test
    // generates the TS-side vectors; each side opens the other's.

    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
    }

    fn generate_chat_fixture(path: &std::path::Path, info: &[u8], plaintext: &[u8]) {
        let mut csprng = <rand::rngs::StdRng as rand::SeedableRng>::from_os_rng();
        let (sk, pk) = Kem::gen_keypair(&mut csprng);
        let (enc, ct) = seal(&pk.to_bytes(), info, plaintext).unwrap();
        let fixture = json!({
            "suite": {
                "kem": "DHKEM(X25519, HKDF-SHA256)",
                "kdf": "HKDF-SHA256",
                "aead": "ChaCha20Poly1305",
            },
            "generator": "rust hpke v0.13",
            "recipient_private_key": B64.encode(sk.to_bytes()),
            "recipient_public_key": B64.encode(pk.to_bytes()),
            "info": B64.encode(info),
            "aad": "",
            "plaintext": B64.encode(plaintext),
            "enc": B64.encode(enc),
            "ct": B64.encode(ct),
        });
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
    }

    fn open_chat_fixture(path: &std::path::Path, expected_info: &[u8]) {
        let raw = std::fs::read_to_string(path).unwrap();
        let fixture: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let b64_field = |k: &str| B64.decode(fixture[k].as_str().unwrap()).unwrap();
        let sk =
            <Kem as KemTrait>::PrivateKey::from_bytes(&b64_field("recipient_private_key")).unwrap();
        let info = b64_field("info");
        assert_eq!(info, expected_info, "info string mismatch in {path:?}");
        let plaintext = open(&sk, &b64_field("enc"), &info, &b64_field("ct"))
            .unwrap_or_else(|e| panic!("failed to open {path:?}: {e}"));
        assert_eq!(
            plaintext,
            b64_field("plaintext"),
            "plaintext mismatch in {path:?}"
        );
    }

    #[test]
    fn rust_chat_request_fixture_exists_and_opens_in_rust() {
        let path = fixtures_dir().join("hpke-chat-request.json");
        if !path.exists() {
            generate_chat_fixture(
                &path,
                REQUEST_INFO,
                b"hpke chat/request interop vector, sealed by the rust `hpke` crate",
            );
        }
        open_chat_fixture(&path, REQUEST_INFO);
    }

    #[test]
    fn rust_chat_response_fixture_exists_and_opens_in_rust() {
        let path = fixtures_dir().join("hpke-chat-response.json");
        if !path.exists() {
            generate_chat_fixture(
                &path,
                RESPONSE_INFO,
                b"hpke chat/response interop vector, sealed by the rust `hpke` crate",
            );
        }
        open_chat_fixture(&path, RESPONSE_INFO);
    }

    #[test]
    fn ts_generated_chat_request_fixture_opens_in_rust() {
        let path = fixtures_dir().join("hpke-chat-request-ts.json");
        assert!(
            path.exists(),
            "missing {path:?}: run `pnpm test` in frontend/ to generate it"
        );
        open_chat_fixture(&path, REQUEST_INFO);
    }

    #[test]
    fn ts_generated_chat_response_fixture_opens_in_rust() {
        let path = fixtures_dir().join("hpke-chat-response-ts.json");
        assert!(
            path.exists(),
            "missing {path:?}: run `pnpm test` in frontend/ to generate it"
        );
        open_chat_fixture(&path, RESPONSE_INFO);
    }
}
