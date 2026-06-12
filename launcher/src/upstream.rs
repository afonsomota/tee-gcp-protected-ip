//! Minimal HTTP/1 client for talking to loopback upstreams (llama-server).
//!
//! Deliberately not a full HTTP client dependency: the launcher only ever
//! makes one-shot requests to processes it supervises on 127.0.0.1, and the
//! audited surface stays smaller with ~50 lines of hyper than with a
//! general-purpose client crate.

use http_body_util::BodyExt;
use hyper::{Method, StatusCode};

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
