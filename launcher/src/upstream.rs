//! Minimal HTTP/1 client for talking to loopback upstreams (llama-server).
//!
//! Deliberately not a full HTTP client dependency: the launcher only ever
//! makes one-shot requests to processes it supervises on 127.0.0.1, and the
//! audited surface stays smaller with ~50 lines of hyper than with a
//! general-purpose client crate.

use std::time::Duration;

use http_body_util::BodyExt;
use hyper::{Method, StatusCode};

/// CPU inference is slow; give a long-prompt completion room to finish.
const CHAT_TIMEOUT: Duration = Duration::from_secs(120);

/// One OpenAI-style chat completion against a loopback llama-server, with the
/// launcher's no-leak invariant baked in. `body` is the fully-formed request
/// JSON (built by the wasm harness, `harness.rs`); we only transport it and
/// pull out the reply text.
///
/// On *any* failure — timeout, transport error, non-2xx, or an unparseable
/// response — we log status/length only (never the body, never any decrypted
/// content: llama-server error bodies can echo prompt fragments) and return a
/// generic `Err(())`. Keeping that rule in exactly one place is the point of
/// this helper, so it cannot silently diverge between callers.
pub async fn chat_completion(upstream: &str, body: String) -> Result<String, ()> {
    let (status, response) = match tokio::time::timeout(
        CHAT_TIMEOUT,
        request(upstream, Method::POST, "/v1/chat/completions", Some(body)),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            eprintln!("upstream/chat_completion: upstream unreachable: {e}");
            return Err(());
        }
        Err(_) => {
            eprintln!("upstream/chat_completion: inference timed out after {CHAT_TIMEOUT:?}");
            return Err(());
        }
    };
    if !status.is_success() {
        eprintln!(
            "upstream/chat_completion: upstream returned {status} ({}-byte body withheld)",
            response.len()
        );
        return Err(());
    }
    let completion: serde_json::Value = serde_json::from_slice(&response).map_err(|_| ())?;
    completion["choices"][0]["message"]["content"]
        .as_str()
        .map(str::to_string)
        .ok_or(())
}

/// One-shot request to `http://{authority}{path}`. A `Some` body is sent as
/// `application/json`. Returns the status and raw response body.
pub async fn request(
    authority: &str,
    method: Method,
    path: &str,
    json_body: Option<String>,
) -> Result<(StatusCode, Vec<u8>), String> {
    let stream = tokio::net::TcpStream::connect(authority)
        .await
        .map_err(|e| format!("failed to connect to {authority}: {e}"))?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| format!("handshake with {authority} failed: {e}"))?;
    tokio::spawn(conn);

    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("Host", authority);
    if json_body.is_some() {
        builder = builder.header("Content-Type", "application/json");
    }
    let request = builder
        .body(json_body.unwrap_or_default())
        .map_err(|e| format!("failed to build request: {e}"))?;

    let response = sender
        .send_request(request)
        .await
        .map_err(|e| format!("request to {authority} failed: {e}"))?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("failed to read response from {authority}: {e}"))?
        .to_bytes()
        .to_vec();
    Ok((status, body))
}
