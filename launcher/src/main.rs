//! Walking-skeleton launcher: an echo endpoint plus a Confidential Space
//! attestation-token endpoint. This is the seed of the audited TCB described
//! in docs/DESIGN.md.

mod gcp;
mod hpke_channel;
mod keys;
mod sealed_cache;
mod tls;

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use serde_json::json;

/// Unix socket exposed by the Confidential Space container launcher.
const TEE_SERVER_SOCKET: &str = "/run/container_launcher/teeserver.sock";
/// Default audience baked into requested tokens; the verifier must expect it.
const DEFAULT_AUDIENCE: &str = "https://tee-example/attestation";

#[derive(Clone)]
pub struct AppState {
    pub keys: Arc<keys::EnclaveKeys>,
    /// Dev mode: serve an *unsigned* attestation-shaped token (see
    /// `keys::EnclaveKeys::dev_token`) so the frontend can run locally.
    pub dev: bool,
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/echo", get(echo))
        .route("/attestation", get(attestation))
        .route("/hpke-key", get(hpke_channel::hpke_key))
        .route("/hpke/echo", post(hpke_channel::hpke_echo))
        // Attestation and the HPKE channel carry their own trust; the
        // frontend is served from a different origin (GitHub Pages / Vite).
        .layer(tower_http::cors::CorsLayer::permissive())
        .with_state(state)
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let dev = std::env::args().any(|a| a == "--dev")
        || std::env::var("LAUNCHER_DEV").is_ok_and(|v| v == "1");
    let state = AppState {
        keys: Arc::new(keys::EnclaveKeys::generate()),
        dev,
    };
    println!(
        "enclave key bindings: {} {}",
        state.keys.hpke_nonce(),
        state.keys.tls_nonce()
    );
    if dev {
        println!("DEV MODE: /attestation serves an UNSIGNED, UNVERIFIED token");
        if std::env::var("TLS_DOMAIN").is_ok_and(|d| !d.is_empty()) {
            println!("DEV MODE: ignoring TLS_DOMAIN, serving plain HTTP");
        }
    }
    // TLS (issue 004): enabled by TLS_DOMAIN outside dev mode; see tls.rs.
    let tls_config = if dev {
        None
    } else {
        tls::TlsConfig::from_env().expect("invalid TLS configuration")
    };
    if let Some(tls_config) = tls_config {
        tls::serve(state, tls_config).await;
        return;
    }
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("bind");
    println!("launcher listening on 0.0.0.0:{port}");
    axum::serve(listener, app(state)).await.expect("serve");
}

#[derive(Deserialize)]
struct EchoParams {
    msg: Option<String>,
}

async fn echo(Query(params): Query<EchoParams>) -> Json<serde_json::Value> {
    Json(json!({ "echo": params.msg.unwrap_or_default() }))
}

#[derive(Deserialize)]
struct AttestationParams {
    nonce: String,
}

async fn attestation(
    State(state): State<AppState>,
    Query(params): Query<AttestationParams>,
) -> Response {
    // The attestation service requires nonces of 10..=74 bytes; reject early
    // with a clearer error than the service's own.
    if params.nonce.len() < 10 || params.nonce.len() > 74 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "nonce must be between 10 and 74 bytes",
        );
    }
    let audience =
        std::env::var("ATTESTATION_AUDIENCE").unwrap_or_else(|_| DEFAULT_AUDIENCE.to_string());
    if state.dev {
        return Json(json!({
            "token": state.keys.dev_token(&audience, &params.nonce),
            "audience": audience,
            "dev": true,
            "warning": "DEV MODE: unsigned token, NOT verified by any hardware",
        }))
        .into_response();
    }
    // Key-hash binding: the caller's challenge plus both enclave public-key
    // hashes ride as separate nonces (see keys.rs module docs for capacity).
    let nonces = [
        params.nonce.clone(),
        state.keys.hpke_nonce(),
        state.keys.tls_nonce(),
    ];
    match fetch_attestation_token(&audience, &nonces).await {
        Ok(token) => Json(json!({ "token": token, "audience": audience })).into_response(),
        Err(e) => error_response(StatusCode::SERVICE_UNAVAILABLE, &e),
    }
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// POST to the Confidential Space launcher's attestation service over its
/// Unix socket and return the OIDC token (a JWT) it mints.
async fn fetch_attestation_token(audience: &str, nonces: &[String]) -> Result<String, String> {
    use http_body_util::BodyExt;

    if !std::path::Path::new(TEE_SERVER_SOCKET).exists() {
        return Err(format!(
            "not running in Confidential Space: attestation socket {TEE_SERVER_SOCKET} not found"
        ));
    }
    let stream = tokio::net::UnixStream::connect(TEE_SERVER_SOCKET)
        .await
        .map_err(|e| format!("failed to connect to attestation socket: {e}"))?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| format!("attestation service handshake failed: {e}"))?;
    tokio::spawn(conn);

    let body = json!({
        "audience": audience,
        "token_type": "OIDC",
        "nonces": nonces,
    })
    .to_string();
    let request = hyper::Request::post("/v1/token")
        .header("Host", "localhost")
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|e| format!("failed to build token request: {e}"))?;

    let response = sender
        .send_request(request)
        .await
        .map_err(|e| format!("token request failed: {e}"))?;
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("failed to read token response: {e}"))?
        .to_bytes();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    if !status.is_success() {
        return Err(format!("attestation service returned {status}: {text}"));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_state(dev: bool) -> AppState {
        AppState {
            keys: Arc::new(keys::EnclaveKeys::generate()),
            dev,
        }
    }

    async fn get_json_with(state: AppState, uri: &str) -> (StatusCode, serde_json::Value) {
        let response = app(state)
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn get_json(uri: &str) -> (StatusCode, serde_json::Value) {
        get_json_with(test_state(false), uri).await
    }

    #[tokio::test]
    async fn echo_returns_message() {
        let (status, body) = get_json("/echo?msg=hello%20tee").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["echo"], "hello tee");
    }

    #[tokio::test]
    async fn echo_defaults_to_empty_string() {
        let (status, body) = get_json("/echo").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["echo"], "");
    }

    #[tokio::test]
    async fn attestation_rejects_short_nonce() {
        let (status, body) = get_json("/attestation?nonce=short").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("nonce"));
    }

    #[tokio::test]
    async fn attestation_outside_tee_returns_clear_error() {
        // No teeserver.sock on dev machines / CI: must fail gracefully.
        let (status, body) = get_json("/attestation?nonce=0123456789abcdef").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let msg = body["error"].as_str().unwrap();
        assert!(msg.contains("not running in Confidential Space"), "{msg}");
    }

    #[tokio::test]
    async fn dev_mode_serves_unsigned_token_with_key_bindings() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let state = test_state(true);
        let keys = state.keys.clone();
        let (status, body) = get_json_with(state, "/attestation?nonce=0123456789abcdef").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["dev"], true);

        let token = body["token"].as_str().unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[2].is_empty(), "dev token must be unsigned");
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(payload["iss"], "urn:tee-example:dev-unverified");
        let nonces: Vec<&str> = payload["eat_nonce"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap())
            .collect();
        assert_eq!(
            nonces,
            vec![
                "0123456789abcdef".to_string(),
                keys.hpke_nonce(),
                keys.tls_nonce()
            ]
        );
        // Every bound nonce must satisfy the attestation service limits.
        for nonce in nonces {
            assert!((10..=74).contains(&nonce.len()), "{nonce}");
        }
    }
}
