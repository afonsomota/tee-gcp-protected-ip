//! POST /chat — model inference through the HPKE channel.
//!
//! Same envelope and key handling as `/hpke/echo` (see `hpke_channel.rs`
//! module docs), with chat-specific info strings. Request plaintext:
//!
//! ```json
//! {"msg": "<utf-8 text>", "reply_pub": "<base64 raw 32-byte X25519 key>"}
//! ```
//!
//! The decrypted message is run against the supervised llama-server
//! (`llama.rs`) with a fixed prompt — prompt construction moves to the
//! sandboxed harness in issue 008. Response plaintext, sealed to
//! `reply_pub`:
//!
//! ```json
//! {"reply": "<model-generated utf-8 text>"}
//! ```
//!
//! Plaintext exists only inside this handler; the model's input and output
//! never leave the enclave unencrypted.

use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use crate::hpke_channel::{open, seal, Envelope};
use crate::AppState;

pub const REQUEST_INFO: &[u8] = b"tee-example/hpke/chat/request/v1";
pub const RESPONSE_INFO: &[u8] = b"tee-example/hpke/chat/response/v1";

/// Fixed for this slice; the harness (issue 008) takes over prompting.
/// Edit `launcher/prompts/system.txt` to change it (embedded at compile time).
const SYSTEM_PROMPT: &str = include_str!("../prompts/system.txt").trim_ascii();

/// CPU inference is slow; give a long-prompt completion room to finish.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Deserialize)]
struct ChatRequest {
    msg: String,
    /// Base64 raw 32-byte X25519 public key the response is sealed to.
    reply_pub: String,
}

pub async fn chat(State(state): State<AppState>, Json(envelope): Json<Envelope>) -> Response {
    let Some(upstream) = state.inference.clone() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "inference not configured: no model loaded in this launcher",
        );
    };
    // Decrypt and validate before touching the model.
    let request = match decrypt_request(&state, &envelope) {
        Ok(r) => r,
        Err(message) => return error(StatusCode::BAD_REQUEST, &message),
    };
    let reply_pub = match B64.decode(&request.reply_pub) {
        Ok(k) => k,
        Err(e) => return error(StatusCode::BAD_REQUEST, &format!("reply_pub is not valid base64: {e}")),
    };
    let reply = match complete(&upstream, &request.msg).await {
        Ok(r) => r,
        Err(message) => return error(StatusCode::BAD_GATEWAY, &message),
    };
    let reply_plaintext = json!({ "reply": reply }).to_string();
    match seal(&reply_pub, RESPONSE_INFO, reply_plaintext.as_bytes()) {
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
    serde_json::from_slice(&plaintext).map_err(|e| format!("request plaintext is not valid JSON: {e}"))
}

/// One OpenAI-style chat completion against llama-server.
async fn complete(upstream: &str, msg: &str) -> Result<String, String> {
    let body = json!({
        "messages": [
            { "role": "system", "content": SYSTEM_PROMPT },
            { "role": "user", "content": msg },
        ],
        "max_tokens": 512,
    })
    .to_string();
    let (status, response) = tokio::time::timeout(
        UPSTREAM_TIMEOUT,
        crate::upstream::request(
            upstream,
            hyper::Method::POST,
            "/v1/chat/completions",
            Some(body),
        ),
    )
    .await
    .map_err(|_| format!("inference timed out after {UPSTREAM_TIMEOUT:?}"))?
    .map_err(|e| format!("inference upstream unreachable: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "inference upstream returned {status}: {}",
            String::from_utf8_lossy(&response)
        ));
    }
    let completion: serde_json::Value = serde_json::from_slice(&response)
        .map_err(|e| format!("inference upstream returned invalid JSON: {e}"))?;
    completion["choices"][0]["message"]["content"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "inference upstream response had no message content".to_string())
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
    use hpke::{Kem as KemTrait, Serializable};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    type Kem = hpke::kem::X25519HkdfSha256;

    fn test_state(inference: Option<String>) -> AppState {
        AppState {
            keys: Arc::new(EnclaveKeys::generate()),
            dev: false,
            inference,
        }
    }

    /// Serve an OpenAI-shaped completion (echoing the user message back
    /// inside the reply) on an ephemeral loopback port.
    async fn mock_llama_server() -> String {
        async fn completions(Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
            let user_msg = body["messages"]
                .as_array()
                .and_then(|m| m.iter().find(|m| m["role"] == "user"))
                .and_then(|m| m["content"].as_str())
                .unwrap_or_default()
                .to_string();
            Json(json!({
                "choices": [
                    { "message": { "role": "assistant", "content": format!("model says: {user_msg}") } }
                ]
            }))
        }
        let app = Router::new().route("/v1/chat/completions", post(completions));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("127.0.0.1:{}", addr.port())
    }

    async fn post_chat(state: AppState, envelope: serde_json::Value) -> (StatusCode, serde_json::Value) {
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

    fn sealed_request(state: &AppState, msg: &str) -> (serde_json::Value, <Kem as KemTrait>::PrivateKey) {
        let mut csprng = <rand::rngs::StdRng as rand::SeedableRng>::from_os_rng();
        let (reply_sk, reply_pk) = Kem::gen_keypair(&mut csprng);
        let request = json!({ "msg": msg, "reply_pub": B64.encode(reply_pk.to_bytes()) });
        let (enc, ct) = seal(
            &state.keys.hpke_public_bytes(),
            REQUEST_INFO,
            request.to_string().as_bytes(),
        )
        .unwrap();
        (json!({ "enc": B64.encode(enc), "ct": B64.encode(ct) }), reply_sk)
    }

    #[tokio::test]
    async fn chat_roundtrips_an_encrypted_model_reply() {
        let upstream = mock_llama_server().await;
        let state = test_state(Some(upstream));
        let (envelope, reply_sk) = sealed_request(&state, "how was my week?");

        let (status, reply) = post_chat(state, envelope).await;
        assert_eq!(status, StatusCode::OK);

        let plaintext = open(
            &reply_sk,
            &B64.decode(reply["enc"].as_str().unwrap()).unwrap(),
            RESPONSE_INFO,
            &B64.decode(reply["ct"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(body["reply"], "model says: how was my week?");
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
        assert!(body["error"].as_str().unwrap().contains("unreachable"));
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
}
