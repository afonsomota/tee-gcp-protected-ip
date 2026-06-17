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
/// asked for strict JSON; `parse_metadata` is lenient about what comes back.
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
    let summary = complete(&upstreams.chat, SUMMARIZE_SYSTEM, text, SUMMARY_MAX_TOKENS)
        .await
        .map_err(|()| "enclave tool \"summarize\": inference failed".to_string())?;
    Ok(json!({ "summary": summary.trim() }))
}

/// `extract_metadata` → `{ "emotions": [..], "situations": [..], "lifePhases": [..] }`.
/// The model is asked for JSON; if it returns something unparseable we degrade
/// to empty arrays rather than fail the enrichment turn.
async fn extract_metadata(text: &str, upstreams: &Upstreams) -> Result<Value, String> {
    let raw = complete(&upstreams.chat, EXTRACT_SYSTEM, text, METADATA_MAX_TOKENS)
        .await
        .map_err(|()| "enclave tool \"extract_metadata\": inference failed".to_string())?;
    Ok(parse_metadata(&raw))
}

/// One chat completion with a fixed system prompt over the given user text.
async fn complete(upstream: &str, system: &str, text: &str, max_tokens: u32) -> Result<String, ()> {
    let body = json!({
        "messages": [
            { "role": "system", "content": system },
            { "role": "user", "content": text },
        ],
        "max_tokens": max_tokens,
    })
    .to_string();
    crate::upstream::chat_completion(upstream, body).await
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
}
