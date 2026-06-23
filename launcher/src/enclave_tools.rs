//! In-enclave tool execution (issue #11).
//!
//! The harness may ask for *enclave-locus* tools — `embed`, `summarize`,
//! `extract_metadata` — instead of (or alongside) client tools. Unlike client
//! tools, these never leave the enclave: the launcher runs them here against the
//! supervised models and feeds the results straight back to the harness
//! (`chat.rs` drives that loop). The browser never sees an enclave tool call.
//!
//! These are deliberately *capabilities*, not orchestration: their prompts are
//! fixed and auditable (part of the open TCB). The harness's IP is *when/why*
//! to call them — the policy that strings embeds, summaries and extractions
//! together — not the primitives themselves (see docs/DESIGN.md).
//!
//! The no-leak invariant from `chat.rs`/`upstream.rs` holds here too: error
//! strings name only the tool and its shape, never the (user) text being
//! processed or any model output.

use serde_json::{json, Value};

/// Token budgets: a summary is short; metadata extraction emits a tiny JSON
/// object. Bounding them keeps CPU inference snappy and the output small.
const SUMMARY_MAX_TOKENS: u32 = 128;
const METADATA_MAX_TOKENS: u32 = 192;

/// Fixed, auditable prompt for the `summarize` capability.
const SUMMARIZE_SYSTEM: &str = "You summarize a personal journal entry in one or \
    two plain sentences. Capture what happened and how the writer felt. Reply \
    with the summary only — no preamble, no quotes.";

/// Fixed, auditable prompt for the `extract_metadata` capability. The model is
/// asked for strict JSON; the request also constrains decoding to the schema in
/// `metadata_response_format`, and `parse_metadata` is lenient about what comes
/// back — the shape is enforced in three independent layers.
const EXTRACT_SYSTEM: &str = "You extract structured metadata from a personal \
    journal entry. Respond with ONLY a JSON object with exactly these keys: \
    \"emotions\", \"situations\", \"lifePhases\". Each value is an array of at \
    most five short lowercase tags (e.g. \"joy\", \"work\", \"new job\"). Use an \
    empty array when nothing fits. No prose, no code fences.";

/// The model upstreams an enclave tool may reach. `chat` is always present (it
/// is the same llama-server `/chat` uses); `embeddings` is the second
/// EmbeddingGemma instance, present only when configured.
#[derive(Clone)]
pub struct Upstreams {
    pub chat: String,
    pub embeddings: Option<String>,
}

/// Execute one enclave-locus tool call. `name` has already been manifest- and
/// locus-validated by the caller; `arguments` is the harness-supplied object.
/// Returns the tool's JSON result (the shape each tool's harness reader
/// expects), or a plaintext-free error.
pub async fn execute(
    name: &str,
    arguments: &Value,
    upstreams: &Upstreams,
) -> Result<Value, String> {
    let text = arguments
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("enclave tool {name:?}: missing string \"text\" argument"))?;
    match name {
        "embed" => embed(text, upstreams).await,
        "summarize" => summarize(text, upstreams).await,
        "extract_metadata" => extract_metadata(text, upstreams).await,
        // Unreachable in practice — the manifest gates names — but keep the
        // failure explicit rather than silently succeeding.
        other => Err(format!("enclave tool {other:?} has no in-enclave executor")),
    }
}

/// `embed` → `{ "embedding": [..] }`. Requires the embeddings instance.
async fn embed(text: &str, upstreams: &Upstreams) -> Result<Value, String> {
    let upstream = upstreams
        .embeddings
        .as_deref()
        .ok_or("enclave tool \"embed\": no embeddings model configured")?;
    let vector = crate::upstream::embeddings(upstream, text.to_string())
        .await
        .map_err(|()| "enclave tool \"embed\": embedding failed".to_string())?;
    Ok(json!({ "embedding": vector }))
}

/// `summarize` → `{ "summary": "<text>" }`.
async fn summarize(text: &str, upstreams: &Upstreams) -> Result<Value, String> {
    let summary = complete(
        &upstreams.chat,
        SUMMARIZE_SYSTEM,
        text,
        SUMMARY_MAX_TOKENS,
        None,
    )
    .await
    .map_err(|()| "enclave tool \"summarize\": inference failed".to_string())?;
    Ok(json!({ "summary": summary.trim() }))
}

/// `extract_metadata` → `{ "emotions": [..], "situations": [..], "lifePhases": [..] }`.
/// Decoding is constrained to `metadata_response_format`, so the model returns
/// schema-valid JSON; if some upstream ignores that and returns something
/// unparseable, `parse_metadata` degrades to empty arrays rather than failing
/// the enrichment turn.
async fn extract_metadata(text: &str, upstreams: &Upstreams) -> Result<Value, String> {
    let raw = complete(
        &upstreams.chat,
        EXTRACT_SYSTEM,
        text,
        METADATA_MAX_TOKENS,
        Some(metadata_response_format()),
    )
    .await
    .map_err(|()| "enclave tool \"extract_metadata\": inference failed".to_string())?;
    Ok(parse_metadata(&raw))
}

/// One chat completion with a fixed system prompt over the given user text.
/// `response_format`, when given, is llama-server's constrained-decoding spec
/// (see `metadata_response_format`).
///
/// We always send `chat_template_kwargs: {"enable_thinking": false}`. The
/// deployed Gemma GGUF ships a chat template with a reasoning channel enabled;
/// on these short, instruction-shaped tasks the model intermittently spends the
/// whole (small) token budget inside an unclosed `<|channel>thought` trace, so
/// llama-server strips the reasoning and returns empty `content` — the empty
/// `summarize`/`extract_metadata` output of issue #50 (spike 003). Turning
/// thinking off makes the model emit its answer directly, deterministically.
async fn complete(
    upstream: &str,
    system: &str,
    text: &str,
    max_tokens: u32,
    response_format: Option<Value>,
) -> Result<String, ()> {
    let mut body = json!({
        "messages": [
            { "role": "system", "content": system },
            { "role": "user", "content": text },
        ],
        "max_tokens": max_tokens,
        "chat_template_kwargs": { "enable_thinking": false },
    });
    if let Some(rf) = response_format {
        body["response_format"] = rf;
    }
    crate::upstream::chat_completion(upstream, body.to_string()).await
}

/// llama-server constrained-decoding spec that forces `extract_metadata`'s
/// reply to the exact `{emotions, situations, lifePhases}` shape — three arrays
/// of at most five short string tags. With thinking disabled (see `complete`)
/// this makes the model emit schema-valid JSON every time; `parse_metadata`
/// stays as the defensive fallback for any upstream that ignores the schema.
fn metadata_response_format() -> Value {
    let tags = json!({ "type": "array", "items": { "type": "string" }, "maxItems": 5 });
    json!({
        "type": "json_schema",
        "json_schema": {
            "name": "journal_metadata",
            "strict": true,
            "schema": {
                "type": "object",
                "properties": {
                    "emotions": tags.clone(),
                    "situations": tags.clone(),
                    "lifePhases": tags,
                },
                "required": ["emotions", "situations", "lifePhases"],
                "additionalProperties": false,
            },
        },
    })
}

/// Parse the model's metadata reply into the three tag arrays. Tolerant: it
/// pulls the first `{...}` block, accepts missing/extra keys, and keeps only
/// the short string tags. Anything it cannot read becomes an empty array.
fn parse_metadata(raw: &str) -> Value {
    let parsed = extract_json_object(raw).unwrap_or_else(|| json!({}));
    let tags = |key: &str| {
        let list = parsed
            .get(key)
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .take(5)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Value::from(list)
    };
    json!({
        "emotions": tags("emotions"),
        "situations": tags("situations"),
        "lifePhases": tags("lifePhases"),
    })
}

/// Find and parse the first balanced `{...}` JSON object in `text` (the model
/// may wrap it in prose or code fences). `None` if none parses.
fn extract_json_object(text: &str) -> Option<Value> {
    let bytes = text.as_bytes();
    let start = text.find('{')?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return serde_json::from_str(&text[start..=i]).ok();
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::mock_llama;

    fn upstreams(chat: String, embeddings: Option<String>) -> Upstreams {
        Upstreams { chat, embeddings }
    }

    #[test]
    fn parse_metadata_reads_clean_json() {
        let out = parse_metadata(
            r#"{"emotions":["joy","relief"],"situations":["work"],"lifePhases":["new job"]}"#,
        );
        assert_eq!(out["emotions"], json!(["joy", "relief"]));
        assert_eq!(out["situations"], json!(["work"]));
        assert_eq!(out["lifePhases"], json!(["new job"]));
    }

    #[test]
    fn parse_metadata_tolerates_prose_and_fences() {
        let out = parse_metadata(
            "Sure! Here is the metadata:\n```json\n{\"emotions\": [\"anxiety\"], \"situations\": [\"family\"]}\n```\nHope that helps.",
        );
        assert_eq!(out["emotions"], json!(["anxiety"]));
        assert_eq!(out["situations"], json!(["family"]));
        // Missing key degrades to an empty array, not an error.
        assert_eq!(out["lifePhases"], json!([]));
    }

    #[test]
    fn parse_metadata_degrades_to_empty_on_garbage() {
        let out = parse_metadata("I'm not sure how to answer that.");
        assert_eq!(out["emotions"], json!([]));
        assert_eq!(out["situations"], json!([]));
        assert_eq!(out["lifePhases"], json!([]));
    }

    #[test]
    fn parse_metadata_drops_non_string_and_caps_at_five() {
        let out = parse_metadata(
            r#"{"emotions":["a","b","c","d","e","f", 7],"situations":[],"lifePhases":["x"]}"#,
        );
        assert_eq!(out["emotions"], json!(["a", "b", "c", "d", "e"]));
    }

    #[tokio::test]
    async fn embed_without_an_embeddings_upstream_errors_cleanly() {
        let err = execute(
            "embed",
            &json!({ "text": "secret-journal-text" }),
            &upstreams("127.0.0.1:1".to_string(), None),
        )
        .await
        .unwrap_err();
        assert!(err.contains("no embeddings model"), "unexpected: {err}");
        assert!(!err.contains("secret-journal"), "plaintext leaked: {err}");
    }

    #[tokio::test]
    async fn summarize_calls_the_chat_model() {
        // mock_llama echoes the prompt it saw; summarize sends a system + user
        // turn, so the echo proves the user text reached the model.
        let upstream = mock_llama(true).await;
        let out = execute(
            "summarize",
            &json!({ "text": "started a new job" }),
            &upstreams(upstream, None),
        )
        .await
        .unwrap();
        let summary = out["summary"].as_str().unwrap();
        assert!(summary.contains("started a new job"), "got: {summary}");
    }

    /// A llama stand-in that records the request body it last received, so a
    /// test can assert on the parameters the enclave tools *send* (not just the
    /// reply). Returns its `host:port` and a handle to the captured body.
    async fn capturing_llama() -> (String, std::sync::Arc<std::sync::Mutex<Option<Value>>>) {
        use axum::routing::post;
        use axum::{Json, Router};
        use std::sync::{Arc, Mutex};

        let seen = Arc::new(Mutex::new(None));
        let sink = seen.clone();
        let handler = move |Json(body): Json<Value>| {
            let sink = sink.clone();
            async move {
                *sink.lock().unwrap() = Some(body);
                Json(json!({
                    "choices": [{ "message": { "role": "assistant", "content": "{}" } }]
                }))
            }
        };
        let app = Router::new().route("/v1/chat/completions", post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("127.0.0.1:{}", addr.port()), seen)
    }

    // Issue #50 / spike 003: the deployed Gemma template has a reasoning channel
    // that, on these short tasks, swallows the whole token budget and yields
    // empty output. Both enclave completions must turn thinking off so the model
    // answers directly.
    #[tokio::test]
    async fn summarize_disables_thinking_and_does_not_constrain_output() {
        let (upstream, seen) = capturing_llama().await;
        execute(
            "summarize",
            &json!({ "text": "x" }),
            &upstreams(upstream, None),
        )
        .await
        .unwrap();
        let body = seen.lock().unwrap().clone().unwrap();
        assert_eq!(
            body["chat_template_kwargs"]["enable_thinking"],
            json!(false)
        );
        // Free-text summary: no forced grammar.
        assert!(body.get("response_format").is_none(), "got: {body}");
    }

    #[tokio::test]
    async fn extract_metadata_disables_thinking_and_constrains_to_schema() {
        let (upstream, seen) = capturing_llama().await;
        execute(
            "extract_metadata",
            &json!({ "text": "x" }),
            &upstreams(upstream, None),
        )
        .await
        .unwrap();
        let body = seen.lock().unwrap().clone().unwrap();
        assert_eq!(
            body["chat_template_kwargs"]["enable_thinking"],
            json!(false)
        );
        assert_eq!(body["response_format"]["type"], json!("json_schema"));
        let schema = &body["response_format"]["json_schema"]["schema"];
        assert_eq!(
            schema["required"],
            json!(["emotions", "situations", "lifePhases"])
        );
        assert_eq!(schema["additionalProperties"], json!(false));
        // The cap on tags lives in the grammar as well as in parse_metadata.
        assert_eq!(schema["properties"]["emotions"]["maxItems"], json!(5));
    }

    #[tokio::test]
    async fn missing_text_argument_is_rejected() {
        let err = execute(
            "summarize",
            &json!({}),
            &upstreams("127.0.0.1:1".to_string(), None),
        )
        .await
        .unwrap_err();
        assert!(err.contains("text"), "unexpected: {err}");
    }

    /// End-to-end check of issue #50 against a *real* `llama-server` running the
    /// production Gemma GGUF — the acceptance criterion that the fix be verified
    /// against a faithful local run, not only mocks. Ignored by default (CI has
    /// no model); run it with the chat upstream in the environment:
    ///
    /// ```sh
    /// llama-server -m gemma-4-E2B_q4_0-it.gguf --port 8099 --no-webui &
    /// TEE_LIVE_CHAT=127.0.0.1:8099 cargo test live_enrich -- --ignored --nocapture
    /// ```
    ///
    /// Asserts what the pre-fix model failed at: a non-empty summary and at
    /// least one populated metadata field, repeatably (the bug was intermittent).
    #[tokio::test]
    #[ignore = "needs a live llama-server with the production model; set TEE_LIVE_CHAT"]
    async fn live_enrich_yields_nonempty_summary_and_metadata() {
        let Ok(chat) = std::env::var("TEE_LIVE_CHAT") else {
            eprintln!("skipping: set TEE_LIVE_CHAT=host:port to a live llama-server");
            return;
        };
        let entry = "Today was rough. I finally told my manager I'm burning out and \
            need to step back from the launch. Saying it out loud was terrifying, but \
            she was kind and we agreed I'd hand off on-call. Relief, then guilt about \
            letting the team down before the deadline. Walked by the river to clear my head.";
        let ups = upstreams(chat, None);

        // Run several times: the pre-fix failure was intermittent (the reasoning
        // channel only sometimes blew the token budget), so a single pass could
        // pass by luck. With thinking off it must succeed every time.
        for i in 0..5 {
            let summary = execute("summarize", &json!({ "text": entry }), &ups)
                .await
                .unwrap();
            let s = summary["summary"].as_str().unwrap_or_default();
            assert!(!s.trim().is_empty(), "run {i}: empty summary");

            let meta = execute("extract_metadata", &json!({ "text": entry }), &ups)
                .await
                .unwrap();
            let populated = ["emotions", "situations", "lifePhases"]
                .iter()
                .any(|k| meta[k].as_array().is_some_and(|a| !a.is_empty()));
            assert!(populated, "run {i}: all metadata fields empty: {meta}");
            eprintln!("run {i}: summary={s:?} metadata={meta}");
        }
    }
}
