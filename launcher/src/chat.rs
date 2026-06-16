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
//! # Tool loop (issues #10 and #11)
//!
//! The harness may ask the launcher to run a tool instead of replying. There
//! are two types:
//!
//! - *Client tools* (issue #10): executed by the browser over local data.
//!   The launcher returns them to the client via HPKE.
//! - *Enclave tools* (issue #11): executed in-enclave using the models.
//!   The launcher executes them immediately and includes results in the next
//!   harness turn.
//!
//! The request carries an optional `tool_results` array — the output of tool
//! calls the harness asked for on the previous round:
//!
//! ```json
//! {
//!   "messages": [{"role": "user|assistant", "content": "..."}, ...],
//!   "tool_results": [{"id": "...", "name": "...", "result": <json>}],
//!   "reply_pub": "<base64 raw 32-byte X25519 key>"
//! }
//! ```
//!
//! Response plaintext, sealed to `reply_pub`, is one of:
//!
//! ```json
//! {"reply": "<model-generated utf-8 text>"}
//! {"tool_calls": [{"id": "...", "name": "...", "arguments": <json>}]}
//! ```
//!
//! The launcher re-validates every `tool_calls` entry the harness emits
//! against its own manifest (`tools.rs`) before sealing it (for client tools)
//! or executing it (for enclave tools): the harness is untrusted.
//! Plaintext exists only inside this handler; the model's input and output
//! never leave the enclave unencrypted.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::hpke_channel::{open, seal, Envelope};
use crate::AppState;

pub const REQUEST_INFO: &[u8] = b"tee-example/hpke/chat/request/v1";
pub const RESPONSE_INFO: &[u8] = b"tee-example/hpke/chat/response/v1";

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

#[derive(Clone, Deserialize, Serialize)]
struct Message {
    role: String,
    content: String,
}

/// One client-executed tool result, echoed back for the next harness turn.
#[derive(Clone, Deserialize, Serialize)]
struct ToolResult {
    id: String,
    name: String,
    result: serde_json::Value,
}

/// A tool call the harness emitted, validated but not yet executed.
#[derive(Debug, Serialize)]
struct ValidatedToolCall {
    id: String,
    name: String,
    arguments: serde_json::Value,
    locus: crate::tools::Locus,
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
    let Some(upstream) = state.inference.clone() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "inference not configured: no model loaded in this launcher",
        );
    };
    let Some(harness) = state.harness.get() else {
        // Delivery + signature verification hasn't completed (or failed); the
        // same "errors until ready" window as artifact-delivered weights.
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "harness not ready: signed orchestration not yet loaded",
        );
    };
    // Decrypt and validate before touching the model. Error strings up to
    // and including decryption describe only attacker-supplied ciphertext
    // (bad base64, bad envelope) — never decrypted content. Keep that
    // invariant: client-visible errors must not carry plaintext fragments.
    let request = match decrypt_request(&state, &envelope) {
        Ok(r) => r,
        Err(message) => return error(StatusCode::BAD_REQUEST, &message),
    };
    // Defense in depth: reject client-smuggled roles before the sandbox ever
    // sees them, even though the harness re-derives the system prompt itself.
    if let Err(message) = validate(&request.messages) {
        return error(StatusCode::BAD_REQUEST, &message);
    }
    let reply_pub = match B64.decode(&request.reply_pub) {
        Ok(k) => k,
        Err(e) => {
            return error(
                StatusCode::BAD_REQUEST,
                &format!("reply_pub is not valid base64: {e}"),
            )
        }
    };

    // Tool execution loop: the harness may emit enclave tools, which we execute
    // immediately and feed back to the harness for the next turn. Client tools
    // are returned to the browser for execution. Loop until the harness produces
    // either a final reply or only client tools (no enclave tools).
    let messages = request.messages.clone();
    let mut tool_results = request.tool_results.clone();

    loop {
        let context = json!({
            "messages": messages,
            "tool_results": tool_results,
            "tools": crate::tools::manifest_json(),
        })
        .to_string();

        let reply_plaintext = match harness.run(&upstream, context.as_bytes()).await {
            Ok(bytes) => bytes,
            Err(detail) => {
                eprintln!("chat: harness run failed: {detail}");
                return error(StatusCode::BAD_GATEWAY, "inference failed");
            }
        };

        // Parse and validate the harness output
        let reply = match validate_harness_reply(&reply_plaintext) {
            Ok(r) => r,
            Err(detail) => {
                eprintln!("chat: harness output rejected: {detail}");
                return error(StatusCode::BAD_GATEWAY, "inference failed");
            }
        };

        match reply {
            // Final reply: seal and return
            Ok(reply_text) => {
                let reply_json = json!({ "reply": reply_text });
                match seal(&reply_pub, RESPONSE_INFO, reply_json.to_string().as_bytes()) {
                    Ok((enc, ct)) => {
                        return Json(Envelope {
                            enc: B64.encode(enc),
                            ct: B64.encode(ct),
                        })
                        .into_response()
                    }
                    Err(message) => return error(StatusCode::BAD_REQUEST, &message),
                }
            }
            // Tool calls: separate by locus
            Err(tool_calls) => {
                let (enclave_tools, client_tools): (Vec<_>, Vec<_>) =
                    tool_calls.iter().partition(|t| t.locus == crate::tools::Locus::Enclave);

                // Execute all enclave tools immediately and collect results
                let mut enclave_results = Vec::new();
                for tool in &enclave_tools {
                    let result = execute_enclave_tool(&state, tool).await;
                    enclave_results.push(ToolResult {
                        id: tool.id.clone(),
                        name: tool.name.clone(),
                        result,
                    });
                }

                // If we have enclave tools, add their results to the loop and continue
                if !enclave_tools.is_empty() {
                    tool_results.extend(enclave_results);
                    continue;
                }

                // No enclave tools; return client tools to the browser
                if !client_tools.is_empty() {
                    let tool_calls_response = json!({
                        "tool_calls": client_tools
                            .iter()
                            .map(|t| json!({
                                "id": t.id,
                                "name": t.name,
                                "arguments": t.arguments,
                            }))
                            .collect::<Vec<_>>()
                    });
                    match seal(&reply_pub, RESPONSE_INFO, tool_calls_response.to_string().as_bytes()) {
                        Ok((enc, ct)) => {
                            return Json(Envelope {
                                enc: B64.encode(enc),
                                ct: B64.encode(ct),
                            })
                            .into_response()
                        }
                        Err(message) => return error(StatusCode::BAD_REQUEST, &message),
                    }
                }

                // Should not reach here (harness output validation ensures non-empty tool_calls)
                return error(StatusCode::BAD_GATEWAY, "inference failed");
            }
        }
    }
}

fn decrypt_request(state: &AppState, envelope: &Envelope) -> Result<ChatRequest, String> {
    let enc = B64
        .decode(&envelope.enc)
        .map_err(|e| format!("enc is not valid base64: {e}"))?;
    let ct = B64
        .decode(&envelope.ct)
        .map_err(|e| format!("ct is not valid base64: {e}"))?;
    let plaintext = open(state.keys.hpke_private(), &enc, REQUEST_INFO, &ct)?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| format!("request plaintext is not valid JSON: {e}"))
}

/// Parse and validate the harness's reply. Returns either a plain reply text
/// or validated tool calls (separated by locus). Both client and enclave tools
/// must pass manifest validation.
fn validate_harness_reply(
    bytes: &[u8],
) -> Result<
    std::result::Result<String, Vec<ValidatedToolCall>>,
    String,
> {
    let output: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("harness reply is not JSON: {e}"))?;

    let Some(tool_calls) = output.get("tool_calls") else {
        // No tool calls: must be a plain reply.
        if let Some(reply) = output.get("reply").and_then(|r| r.as_str()) {
            return Ok(Ok(reply.to_string()));
        }
        return Err("harness reply has neither \"reply\" nor \"tool_calls\"".to_string());
    };

    let calls = tool_calls
        .as_array()
        .ok_or("harness \"tool_calls\" must be an array")?;
    if calls.is_empty() {
        return Err("harness emitted an empty \"tool_calls\" array".to_string());
    }

    let mut validated = Vec::new();
    for call in calls {
        let id = call
            .get("id")
            .and_then(|i| i.as_str())
            .ok_or("tool call missing a string \"id\"")?
            .to_string();
        let name = call
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or("tool call missing a string \"name\"")?;
        let arguments = call.get("arguments").unwrap_or(&serde_json::Value::Null);
        let spec = crate::tools::validate_call(name, arguments)?;
        validated.push(ValidatedToolCall {
            id,
            name: name.to_string(),
            arguments: arguments.clone(),
            locus: spec.locus,
        });
    }

    Ok(Err(validated))
}

/// Execute an enclave-locus tool and return its JSON result, or an error.
async fn execute_enclave_tool(
    state: &AppState,
    tool: &ValidatedToolCall,
) -> serde_json::Value {
    let Some(embedding_upstream) = &state.embedding else {
        return json!({"error": "embedding model not configured"});
    };
    let Some(chat_upstream) = &state.inference else {
        return json!({"error": "chat model not configured"});
    };

    match tool.name.as_str() {
        "embed" => {
            let text = tool
                .arguments
                .get("text")
                .and_then(|t| t.as_str())
                .unwrap_or("");
            embed_text(embedding_upstream, text).await
        }
        "summarize" => {
            let text = tool
                .arguments
                .get("text")
                .and_then(|t| t.as_str())
                .unwrap_or("");
            summarize_text(chat_upstream, text).await
        }
        "extract_metadata" => {
            let text = tool
                .arguments
                .get("text")
                .and_then(|t| t.as_str())
                .unwrap_or("");
            extract_metadata_text(chat_upstream, text).await
        }
        _ => json!({"error": format!("unknown enclave tool: {}", tool.name)}),
    }
}

/// Call the embedding model to embed text to a vector.
async fn embed_text(upstream: &str, text: &str) -> serde_json::Value {
    let request = json!({
        "input": text,
        "encoding_format": "float",
    });
    match crate::upstream::request(
        upstream,
        hyper::Method::POST,
        "/v1/embeddings",
        Some(request.to_string()),
    )
    .await
    {
        Ok((status, body)) => {
            if !status.is_success() {
                eprintln!("embed: embedding model returned {status}");
                return json!({"error": "embedding failed"});
            }
            match serde_json::from_slice::<serde_json::Value>(&body) {
                Ok(response) => {
                    if let Some(embedding) = response
                        .get("data")
                        .and_then(|d| d.get(0))
                        .and_then(|d| d.get("embedding"))
                    {
                        json!({"embedding": embedding})
                    } else {
                        json!({"error": "invalid embedding response"})
                    }
                }
                Err(e) => {
                    eprintln!("embed: failed to parse embedding response: {e}");
                    json!({"error": "invalid embedding response"})
                }
            }
        }
        Err(e) => {
            eprintln!("embed: embedding model unreachable: {e}");
            json!({"error": "embedding model unreachable"})
        }
    }
}

/// Call the chat model to generate a summary.
async fn summarize_text(upstream: &str, text: &str) -> serde_json::Value {
    let prompt = format!(
        "Provide a brief 1-2 sentence summary of the following text:\n\n{}",
        text
    );
    let request = json!({
        "messages": [
            {"role": "system", "content": "You are a helpful assistant that creates concise summaries."},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 100,
        "temperature": 0.3,
    });

    match crate::upstream::chat_completion(upstream, request.to_string()).await {
        Ok(summary) => json!({"summary": summary}),
        Err(()) => json!({"error": "summarization failed"}),
    }
}

/// Call the chat model to extract metadata (emotions, situations, life phases).
async fn extract_metadata_text(upstream: &str, text: &str) -> serde_json::Value {
    let prompt = format!(
        "Analyze the following journal entry and extract structured metadata. \
         Return a JSON object with arrays for 'emotions', 'situations', and 'lifePhases'.\n\n{}",
        text
    );
    let request = json!({
        "messages": [
            {"role": "system", "content": "You are a metadata extraction assistant. \
             Extract emotions (joy, anxiety, etc), situations (work, family, etc), \
             and life phases (new job, parenthood, etc) as string arrays in JSON format. \
             Return ONLY valid JSON with keys 'emotions', 'situations', 'lifePhases'."},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 200,
        "temperature": 0.3,
    });

    match crate::upstream::chat_completion(upstream, request.to_string()).await {
        Ok(response_text) => {
            match serde_json::from_str::<serde_json::Value>(&response_text) {
                Ok(metadata) => {
                    // Validate and extract only recognized fields
                    let mut result = json!({});
                    if let Some(emotions) = metadata.get("emotions").and_then(|e| e.as_array()) {
                        if emotions
                            .iter()
                            .all(|e| e.is_string())
                        {
                            result["emotions"] = json!(emotions);
                        }
                    }
                    if let Some(situations) = metadata.get("situations").and_then(|s| s.as_array()) {
                        if situations
                            .iter()
                            .all(|s| s.is_string())
                        {
                            result["situations"] = json!(situations);
                        }
                    }
                    if let Some(phases) = metadata.get("lifePhases").and_then(|p| p.as_array()) {
                        if phases
                            .iter()
                            .all(|p| p.is_string())
                        {
                            result["lifePhases"] = json!(phases);
                        }
                    }
                    if result.is_object() && !result.as_object().unwrap().is_empty() {
                        result
                    } else {
                        json!({"error": "no valid metadata extracted"})
                    }
                }
                Err(_) => json!({"error": "failed to parse metadata response"}),
            }
        }
        Err(()) => json!({"error": "metadata extraction failed"}),
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
    use crate::test_support::{fixture_file, mock_llama};
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
        AppState {
            keys: Arc::new(EnclaveKeys::generate()),
            dev: false,
            inference,
            embedding: None,
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

    // ── manifest enforcement on harness output ────────────────────────────────

    #[test]
    fn validate_harness_reply_accepts_a_plain_reply() {
        let result = validate_harness_reply(br#"{"reply":"hello"}"#).unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn validate_harness_reply_accepts_client_tool_calls() {
        let ok =
            br#"{"tool_calls":[{"id":"1","name":"search_entries","arguments":{"query":"x"}}]}"#;
        let result = validate_harness_reply(ok).unwrap();
        assert!(result.is_err()); // tool_calls are returned as Err variant
        let calls = result.unwrap_err();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "search_entries");
    }

    #[test]
    fn validate_harness_reply_accepts_enclave_tool_calls() {
        let ok =
            br#"{"tool_calls":[{"id":"1","name":"embed","arguments":{"text":"hello"}}]}"#;
        let result = validate_harness_reply(ok).unwrap();
        assert!(result.is_err());
        let calls = result.unwrap_err();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "embed");
    }

    #[test]
    fn validate_harness_reply_rejects_an_unknown_tool() {
        // A hostile/buggy harness cannot smuggle an undeclared capability.
        let bad = br#"{"tool_calls":[{"id":"1","name":"exfiltrate","arguments":{}}]}"#;
        let err = validate_harness_reply(bad).unwrap_err();
        assert!(err.contains("not in manifest"), "unexpected error: {err}");
    }

    #[test]
    fn validate_harness_reply_rejects_a_malformed_call() {
        // Missing the required `query` argument for search_entries.
        let bad = br#"{"tool_calls":[{"id":"1","name":"search_entries","arguments":{}}]}"#;
        let err = validate_harness_reply(bad).unwrap_err();
        assert!(err.contains("query"), "unexpected error: {err}");
    }

    #[test]
    fn validate_harness_reply_rejects_a_shapeless_reply() {
        let err = validate_harness_reply(br#"{"nonsense":true}"#).unwrap_err();
        assert!(err.contains("neither"), "unexpected error: {err}");
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
