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
//!   * `search_entries`  — keyword/metadata/vector similarity search over IndexedDB
//!   * `attach_metadata` — write harness-provided enrichment into local storage
//!
//! Issue #11 adds the enclave locus (model-bound tools executed in-enclave):
//!   * `embed(text)`                   — embed text to vector via EmbeddingGemma
//!   * `summarize(text)`               — generate short summary via chat model
//!   * `extract_metadata(text)`        — extract emotions/situations/life phases
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
    // No enclave-locus tools ship until issue #11, but the variant (and the
    // locus check in `chat.rs`) are here now so the routing is explicit: a
    // harness must never get an enclave tool returned to the browser.
    #[allow(dead_code)]
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
                      keywords, metadata filters, and vector similarity; \
                      returns only the matched entries (top-k). The only path \
                      by which entries enter enclave memory — on-demand data minimization.",
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
        description: "Embed text to a vector via the local EmbeddingGemma model \
                      for use in similarity search. Returns a float array.",
        locus: Locus::Enclave,
        required: &["text"],
    },
    ToolSpec {
        name: "summarize",
        description: "Generate a short (1-2 sentence) summary of the given text \
                      using the chat model. Returns a string.",
        locus: Locus::Enclave,
        required: &["text"],
    },
    ToolSpec {
        name: "extract_metadata",
        description: "Extract structured metadata (emotions, situations, life \
                      phases) from the given text using the chat model with \
                      specialized prompting. Returns an object with string arrays.",
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
pub fn manifest_json() -> Value {
    json!({
        "tools": [
            {
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
                        "embedding": {
                            "type": "array",
                            "items": { "type": "number" },
                            "description": "Optional embedding vector for similarity search. If present, returned entries are ranked by cosine similarity to this vector.",
                        },
                    },
                    "required": ["query"],
                },
            },
            {
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
            },
            {
                "name": "embed",
                "description": lookup("embed").unwrap().description,
                "locus": Locus::Enclave,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "Text to embed.",
                        },
                    },
                    "required": ["text"],
                },
            },
            {
                "name": "summarize",
                "description": lookup("summarize").unwrap().description,
                "locus": Locus::Enclave,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "Text to summarize.",
                        },
                    },
                    "required": ["text"],
                },
            },
            {
                "name": "extract_metadata",
                "description": lookup("extract_metadata").unwrap().description,
                "locus": Locus::Enclave,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "Text to extract metadata from.",
                        },
                    },
                    "required": ["text"],
                },
            },
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_client_tool_validates() {
        let spec = validate_call("search_entries", &json!({ "query": "Mochi" })).unwrap();
        assert_eq!(spec.name, "search_entries");
        assert_eq!(spec.locus, Locus::Client);
    }

    #[test]
    fn known_enclave_tool_validates() {
        let spec = validate_call("embed", &json!({ "text": "hello" })).unwrap();
        assert_eq!(spec.name, "embed");
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
        let manifest = manifest_json();
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
}
