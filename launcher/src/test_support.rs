//! Shared `#[cfg(test)]` glue for the launcher's unit tests. Deliberately tiny
//! — just the two pieces `harness.rs` and `chat.rs` would otherwise each copy:
//! the signed-harness fixture loader and an ephemeral llama-server stand-in.

use std::path::PathBuf;

/// Read a file from `launcher/tests/fixtures/harness/`, panicking with the
/// rebuild hint if it's missing. The fixture is build output, not committed
/// (gitignored): CI rebuilds it via scripts/build-harness.sh before `cargo
/// test`; locally, run that script once.
pub fn fixture_file(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/harness")
        .join(name);
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("missing {path:?} (run scripts/build-harness.sh): {e}"))
}

/// Spawn an OpenAI-shaped completion server on an ephemeral loopback port that
/// echoes the messages it received back inside the reply (`"model saw [...]"`),
/// returning its `host:port`. `include_system` controls whether system-role
/// turns are echoed too: the harness tests want to see their injected system
/// prompt, the chat tests assert only on the non-system turns they sent.
pub async fn mock_llama(include_system: bool) -> String {
    use axum::routing::post;
    use axum::{Json, Router};

    let completions = move |Json(body): Json<serde_json::Value>| async move {
        let seen: Vec<String> = body["messages"]
            .as_array()
            .map(|messages| {
                messages
                    .iter()
                    .filter(|m| include_system || m["role"] != "system")
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
        Json(serde_json::json!({
            "choices": [
                { "message": { "role": "assistant", "content": format!("model saw [{}]", seen.join(" | ")) } }
            ]
        }))
    };
    let app = Router::new().route("/v1/chat/completions", post(completions));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("127.0.0.1:{}", addr.port())
}

/// Spawn an OpenAI-shaped embeddings server on an ephemeral loopback port,
/// returning its `host:port`. It returns a tiny fixed-length vector derived from
/// the input length, which is enough to prove the `embed` enclave tool reached a
/// model and threaded the vector through; the values are not meaningful.
pub async fn mock_embeddings() -> String {
    use axum::routing::post;
    use axum::{Json, Router};

    let embeddings = |Json(body): Json<serde_json::Value>| async move {
        let input = body["input"].as_str().unwrap_or_default();
        let n = input.len() as f64;
        Json(serde_json::json!({
            "data": [{ "embedding": [n, n + 1.0, n + 2.0] }]
        }))
    };
    let app = Router::new().route("/v1/embeddings", post(embeddings));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("127.0.0.1:{}", addr.port())
}
