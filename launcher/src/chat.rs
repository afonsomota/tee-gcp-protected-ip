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
//! itself no longer constructs the prompt. Response plaintext, sealed to
//! `reply_pub`:
//!
//! ```json
//! {"reply": "<model-generated utf-8 text>"}
//! ```
//!
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
    /// Base64 raw 32-byte X25519 public key the response is sealed to.
    reply_pub: String,
}

#[derive(Deserialize, Serialize)]
struct Message {
    role: String,
    content: String,
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
    // Hand the validated history to the sandboxed harness; it builds the
    // prompt and produces the reply JSON, which we seal verbatim. The harness
    // can only call back into the enclave-local model (no other capability).
    let context = json!({ "messages": request.messages }).to_string();
    let reply_plaintext = match harness.run(&upstream, context.as_bytes()).await {
        Ok(bytes) => bytes,
        // harness.run errors carry no plaintext; keep the client message
        // generic and let the (status/len-only) detail go to logs.
        Err(detail) => {
            eprintln!("chat: harness run failed: {detail}");
            return error(StatusCode::BAD_GATEWAY, "inference failed");
        }
    };
    match seal(&reply_pub, RESPONSE_INFO, &reply_plaintext) {
        Ok((enc, ct)) => Json(Envelope {
            enc: B64.encode(enc),
            ct: B64.encode(ct),
        })
        .into_response(),
        Err(message) => error(StatusCode::BAD_REQUEST, &message),
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

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::EnclaveKeys;
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
            harness: Arc::new(load_fixture_harness()),
        }
    }

    /// Load the committed, signed harness fixture into a ready slot so `/chat`
    /// routes through the real wasm module (built by scripts/build-harness.sh).
    fn load_fixture_harness() -> crate::harness::HarnessSlot {
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/harness");
        let read = |name: &str| {
            std::fs::read(dir.join(name)).unwrap_or_else(|e| {
                panic!("missing {name} (run scripts/build-harness.sh): {e}")
            })
        };
        let harness = crate::harness::Harness::new(&read("harness.wasm"), &read("harness.wasm.sig"))
            .expect("fixture harness should verify");
        crate::harness::HarnessSlot::loaded(Arc::new(harness))
    }

    /// Serve an OpenAI-shaped completion (echoing every non-system message it
    /// received back inside the reply) on an ephemeral loopback port.
    async fn mock_llama_server() -> String {
        async fn completions(Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
            let seen: Vec<String> = body["messages"]
                .as_array()
                .map(|messages| {
                    messages
                        .iter()
                        .filter(|m| m["role"] != "system")
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
            Json(json!({
                "choices": [
                    { "message": { "role": "assistant", "content": format!("model saw [{}]", seen.join(" | ")) } }
                ]
            }))
        }
        let app = Router::new().route("/v1/chat/completions", post(completions));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("127.0.0.1:{}", addr.port())
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
    async fn chat_roundtrips_an_encrypted_model_reply() {
        let upstream = mock_llama_server().await;
        let state = test_state(Some(upstream));
        let (envelope, reply_sk) = sealed_request(&state, "how was my week?");

        let (status, reply) = post_chat(state, envelope).await;
        assert_eq!(status, StatusCode::OK);

        let body = open_reply(&reply_sk, &reply);
        assert_eq!(body["reply"], "model saw [user: how was my week?]");
    }

    #[tokio::test]
    async fn chat_forwards_the_full_history_in_order() {
        let upstream = mock_llama_server().await;
        let state = test_state(Some(upstream));
        let (envelope, reply_sk) = sealed_history(
            &state,
            json!([
                { "role": "user", "content": "my cat is called Mochi" },
                { "role": "assistant", "content": "noted!" },
                { "role": "user", "content": "what is my cat called?" },
            ]),
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
        let upstream = mock_llama_server().await;
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
        let upstream = mock_llama_server().await;
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
        let (envelope, _) = sealed_request(&state, "hello");
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
        let (envelope, _) = sealed_request(&state, "hello");
        let (status, body) = post_chat(state, envelope).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        let error = body["error"].as_str().unwrap();
        // Generic message, and crucially no echoed prompt fragment.
        assert_eq!(error, "inference failed");
        assert!(!error.contains(SENTINEL), "upstream body leaked: {error}");
    }

    #[tokio::test]
    async fn chat_rejects_envelope_sealed_with_echo_info_string() {
        // Domain separation: an /hpke/echo request must not decrypt as /chat.
        let upstream = mock_llama_server().await;
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
