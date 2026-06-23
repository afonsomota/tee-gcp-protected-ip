# Spike 003 — `/enrich` returns empty summary + metadata on the deployed model

**Date:** 2026-06-23 (decision recorded 2026-06-23)
**Issue:** #50 (relates to #11)
**Question:** On a real enclave, saving an entry runs the in-enclave
`summarize`, `extract_metadata`, and `embed` tools. `embed` returns a valid
768-dim vector, but `summarize` returns empty text and `extract_metadata`
produces no parseable JSON — so `attach_metadata` carries a real embedding
with an empty summary and empty `emotions`/`situations`/`lifePhases`. Ordinary
`/chat` prompts answer fine. What is the right fix?

## Diagnosis

Reproduced locally against the *exact* production model
(`gemma-4-E2B_q4_0-it.gguf`) under a recent `llama-server`, replaying the exact
request bodies `enclave_tools.rs` sends.

The deployed Gemma 4 E2B GGUF ships a chat template with a **reasoning channel
enabled** — `llama-server` logs `chat template, thinking = 1` at load. On the
short, instruction-shaped `summarize`/`extract_metadata` tasks, the model
*intermittently* opens a `<|channel>thought` reasoning trace and spends the
whole (small) token budget inside it without ever closing it. `llama-server`'s
reasoning parser then strips the unclosed trace, leaving `content` empty and
`finish_reason: "length"`.

Measured (`max_tokens` 128 / 192, thinking on, production model):

| Tool | Empty (`finish=length`) | Good (`finish=stop`) |
|---|---|---|
| `summarize`        | ~2 / 8  | ~6 / 8 |
| `extract_metadata` | 6 / 6   | 0 / 6  |

`extract_metadata` fails *every* time — the "respond with ONLY JSON"
instruction reliably triggers a long reasoning preamble that the 192-token
budget can never escape. `summarize` fails intermittently. Successful summaries
used only 35–57 tokens, so the budget itself is ample — the reasoning channel,
not budget size, is the failure. `/chat` mostly escaped this: a 512-token
budget plus conversational (not instruction-shaped) prompts.

It is **not** a transport, harness-loop, or `parse_metadata` bug — those work
exactly as designed. The fallback-to-empty is faithfully passing through empty
model output.

## Decision

Two changes in `launcher/src/enclave_tools.rs`, both confined to the enclave
tool's model call — the harness and the client contract are untouched:

1. **Disable the reasoning channel** for enclave-tool completions by sending
   `chat_template_kwargs: {"enable_thinking": false}`. This is the root-cause
   fix; the model then emits its answer directly.

2. **Constrain `extract_metadata` decoding** with a `response_format`
   `json_schema` that pins the `{emotions, situations, lifePhases}` shape (three
   arrays of ≤5 string tags). This is the remedy the issue suggested
   (constrained decoding) and makes the JSON contract bulletproof.

`parse_metadata`'s degrade-to-empty stays as a defensive third layer, so a
future `llama-server` that ignores either knob still fails soft, not the turn.

### Why not just raise `max_tokens`?

It doesn't fix `extract_metadata` (the reasoning trace runs arbitrarily long),
wastes CPU inference on discarded thinking, and only papers over the
intermittent `summarize` failure. Disabling thinking is deterministic.

### Why both knobs, not one?

`json_schema` *alone* (thinking left on) still returns empty — the reasoning
channel preempts the grammar, so the schema never gets to constrain anything.
`enable_thinking: false` is required; the schema is added on top so
`extract_metadata` is also robust against malformed output independent of the
model's mood.

## Verification

Against the production model via a faithful local `llama-server` run
(acceptance criterion #4):

- Direct request replay: with both knobs, `summarize` 6/6 non-empty and
  `extract_metadata` 6/6 schema-valid with rich tags; generalises across
  distinct emotion-rich entries.
- Real code path: `enclave_tools::tests::live_enrich_yields_nonempty_summary_and_metadata`
  (`#[ignore]`d; run with `TEE_LIVE_CHAT=host:port`) drives the actual
  `execute()` 5× and asserts non-empty summary + ≥1 populated metadata field
  every run. Passes.

The production llama.cpp image is recent (build b9592, 2026-06-11) and supports
both `chat_template_kwargs.enable_thinking` and `json_schema` response formats.
The fix is template-level (consumed by the jinja template baked into the GGUF),
so it transfers from the local run to the enclave unchanged.

## Follow-ups (out of scope here)

- `/chat` shares the same template and could, in principle, hit the reasoning
  channel on a long turn. It works today (512-token budget, conversational
  prompts) and the harness builds its own request body in wasm, so changing it
  touches the IP layer — tracked separately if it ever surfaces.
