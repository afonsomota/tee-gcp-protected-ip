//! The tool manifest — per-tool policy enforced by the launcher (the audited TCB).
//!
//! The harness (closed IP, sandboxed) may *request* tool calls, but it is
//! untrusted: the launcher decides what it is allowed to ask the client to do.
//! This module is the gate. It declares every tool — its name, a human
//! description, its JSON-schema parameters, and its **execution locus** (client
//! or enclave) — and validates each harness-emitted call against that
//! declaration before the call is allowed to leave the enclave.
//!
//! Issue #10 ships the *client* locus with two data-bound tools:
//!   * `search_entries`  — keyword/metadata search over the browser's IndexedDB
//!   * `attach_metadata` — write harness-provided enrichment into local storage
//!
//! Issue #11 adds the *enclave* locus (model-bound) — executed in-enclave by
//! the launcher (`enclave_tools.rs`), never handed to the browser:
//!   * `embed`            — embed text with the EmbeddingGemma instance
//!   * `summarize`        — summarize text with the chat model
//!   * `extract_metadata` — pull emotions/situations/life-phases (chat model)
//!
//! `embed` is advertised only when an embeddings model is loaded (see
//! `manifest_json`): the harness reads the manifest to learn which enclave
//! tools a deployment offers, so semantic search degrades gracefully to keyword
//! search where no embeddings instance exists.
//!
//! Validation is deliberately lightweight — name membership, locus, and the
//! presence of each declared required argument — so the audited TCB carries no
//! JSON-schema engine. The full parameter schemas live in `manifest_json` for
//! the harness and the frontend to read; the launcher only enforces the parts
//! it must to keep a hostile harness from smuggling an undeclared capability or
//! a malformed call onto the user's device.

use serde::Serialize;
use serde_json::{json, Value};

/// Where a tool runs. Client tools execute in the browser (over local,
/// decrypted data); enclave tools execute in-enclave against the models.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Locus {
    Client,
    /// Model-bound tools the launcher runs in-enclave (`enclave_tools.rs`); the
    /// browser must never be asked to run one. `chat.rs` routes on this.
    Enclave,
}

/// One declared tool. The launcher matches harness calls against these.
#[derive(Debug)]
pub struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub locus: Locus,
    /// Argument keys that must be present for the call to be well-formed. The
    /// launcher checks presence only; richer typing lives in the JSON schema.
    pub required: &'static [&'static str],
}

/// The manifest. Single source of truth for what tools exist and where they
/// run. Keep names in sync with `parameters_schema` and the frontend executor.
const TOOLS: &[ToolSpec] = &[
    ToolSpec {
        name: "search_entries",
        description: "Search the user's locally stored journal entries by \
                      keywords and metadata filters; returns only the matched \
                      entries (top-k). The only path by which entries enter \
                      enclave memory — on-demand data minimization.",
        locus: Locus::Client,
        required: &["query"],
    },
    ToolSpec {
        name: "attach_metadata",
        description: "Write harness-provided enrichment (emotions, situations, \
                      life phases, summary, embedding) into one locally stored, \
                      encrypted journal entry.",
        locus: Locus::Client,
        required: &["entry_id", "enrichment"],
    },
    ToolSpec {
        name: "embed",
        description: "Embed text with the in-enclave EmbeddingGemma instance; \
                      returns a similarity vector. Available only when an \
                      embeddings model is loaded.",
        locus: Locus::Enclave,
        required: &["text"],
    },
    ToolSpec {
        name: "summarize",
        description: "Summarize text with the in-enclave chat model; returns a \
                      short summary.",
        locus: Locus::Enclave,
        required: &["text"],
    },
    ToolSpec {
        name: "extract_metadata",
        description: "Extract emotions, situations, and life phases from text \
                      with the in-enclave chat model.",
        locus: Locus::Enclave,
        required: &["text"],
    },
];

/// Look up a tool by name.
pub fn lookup(name: &str) -> Option<&'static ToolSpec> {
    TOOLS.iter().find(|t| t.name == name)
}

/// Validate one harness-emitted tool call against the manifest. Returns the
/// matched spec on success. Errors describe only the manifest (public policy)
/// and the call's shape — never user content — so they are safe to surface.
pub fn validate_call(name: &str, arguments: &Value) -> Result<&'static ToolSpec, String> {
    let spec = lookup(name).ok_or_else(|| format!("tool not in manifest: {name:?}"))?;
    let obj = arguments
        .as_object()
        .ok_or_else(|| format!("tool {name:?}: arguments must be a JSON object"))?;
    if let Some(missing) = spec.required.iter().find(|k| !obj.contains_key(**k)) {
        return Err(format!(
            "tool {name:?}: missing required argument {missing:?}"
        ));
    }
    Ok(spec)
}

/// The full manifest as JSON — names, descriptions, loci, and parameter
/// schemas — for the harness (handed in with the chat context) and the
/// frontend to read. The schemas are descriptive (JSON Schema); the launcher
/// enforces only `validate_call`'s subset.
///
/// `embeddings_available` gates the `embed` tool: when no embeddings model is
/// loaded it is omitted, and the harness (which reads the advertised names)
/// falls back to keyword-only search. The text tools (`summarize`,
/// `extract_metadata`) ride the always-present chat model, so they are always
/// advertised.
pub fn manifest_json(embeddings_available: bool) -> Value {
    let mut tools = vec![
        json!({
            "name": "search_entries",
            "description": lookup("search_entries").unwrap().description,
            "locus": Locus::Client,
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Natural-language or keyword query to match against entry titles, bodies, and metadata.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of entries to return (top-k). Defaults to 5.",
                    },
                    "query_embedding": {
                        "type": "array",
                        "items": { "type": "number" },
                        "description": "Optional query embedding (from the `embed` tool) for semantic ranking over locally stored entry embeddings.",
                    },
                },
                "required": ["query"],
            },
        }),
        json!({
            "name": "attach_metadata",
            "description": lookup("attach_metadata").unwrap().description,
            "locus": Locus::Client,
            "parameters": {
                "type": "object",
                "properties": {
                    "entry_id": {
                        "type": "string",
                        "description": "Opaque id of the entry to enrich.",
                    },
                    "enrichment": {
                        "type": "object",
                        "description": "Enrichment to merge into the entry (emotions, situations, lifePhases, summary, embedding).",
                    },
                },
                "required": ["entry_id", "enrichment"],
            },
        }),
        json!({
            "name": "summarize",
            "description": lookup("summarize").unwrap().description,
            "locus": Locus::Enclave,
            "parameters": text_tool_parameters(),
        }),
        json!({
            "name": "extract_metadata",
            "description": lookup("extract_metadata").unwrap().description,
            "locus": Locus::Enclave,
            "parameters": text_tool_parameters(),
        }),
    ];
    if embeddings_available {
        tools.push(json!({
            "name": "embed",
            "description": lookup("embed").unwrap().description,
            "locus": Locus::Enclave,
            "parameters": text_tool_parameters(),
        }));
    }
    json!({ "tools": tools })
}

/// The shared `{ text }` parameter schema of the enclave text tools.
fn text_tool_parameters() -> Value {
    json!({
        "type": "object",
        "properties": {
            "text": { "type": "string", "description": "The text to process." },
        },
        "required": ["text"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_tool_with_required_args_validates() {
        let spec = validate_call("search_entries", &json!({ "query": "Mochi" })).unwrap();
        assert_eq!(spec.name, "search_entries");
        assert_eq!(spec.locus, Locus::Client);
    }

    #[test]
    fn enclave_tool_validates_with_its_locus() {
        let spec = validate_call("embed", &json!({ "text": "hello" })).unwrap();
        assert_eq!(spec.name, "embed");
        assert_eq!(spec.locus, Locus::Enclave);
        let spec = validate_call("summarize", &json!({ "text": "hello" })).unwrap();
        assert_eq!(spec.locus, Locus::Enclave);
    }

    #[test]
    fn unknown_tool_is_rejected() {
        let err = validate_call("exfiltrate", &json!({})).unwrap_err();
        assert!(err.contains("not in manifest"), "unexpected error: {err}");
    }

    #[test]
    fn missing_required_argument_is_rejected() {
        let err = validate_call("attach_metadata", &json!({ "entry_id": "x" })).unwrap_err();
        assert!(err.contains("enrichment"), "unexpected error: {err}");
    }

    #[test]
    fn non_object_arguments_are_rejected() {
        let err = validate_call("search_entries", &json!("just a string")).unwrap_err();
        assert!(err.contains("JSON object"), "unexpected error: {err}");
    }

    /// Every tool advertised in `manifest_json` must be enforceable by
    /// `validate_call` (i.e. present in `TOOLS`) — no advertise-but-don't-gate
    /// drift, which would let a harness call a tool the launcher can't police.
    #[test]
    fn every_advertised_tool_is_enforceable() {
        let manifest = manifest_json(true);
        for tool in manifest["tools"].as_array().unwrap() {
            let name = tool["name"].as_str().unwrap();
            assert!(
                lookup(name).is_some(),
                "advertised but unenforceable: {name}"
            );
            // Each advertised `required` key is one `validate_call` enforces.
            let advertised: Vec<&str> = tool["parameters"]["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            assert_eq!(advertised, lookup(name).unwrap().required);
        }
    }

    /// `embed` is advertised only when an embeddings model is loaded, so the
    /// harness can fall back to keyword search where there is none.
    #[test]
    fn embed_is_advertised_only_when_embeddings_available() {
        let names = |available| {
            manifest_json(available)["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };
        assert!(names(true).contains(&"embed".to_string()));
        assert!(!names(false).contains(&"embed".to_string()));
        // The text tools ride the always-present chat model, both ways.
        for available in [true, false] {
            assert!(names(available).contains(&"summarize".to_string()));
            assert!(names(available).contains(&"extract_metadata".to_string()));
        }
    }
}
