/**
 * Pins the /enrich request plaintext to the launcher's wire format
 * (`EnrichRequest` in launcher/src/chat.rs): serde deserializes exactly
 * `{ entry, reply_pub }` (+ optional `tool_results`), so any field-name drift
 * here breaks enrichment end-to-end. The info strings are pinned too.
 */
import { describe, expect, it } from "vitest";
import { b64decode } from "./hpke";
import {
  ENRICH_REQUEST_INFO,
  ENRICH_RESPONSE_INFO,
  type EnrichEntry,
  buildEnrichPayload,
} from "./enrich";

describe("enrich request payload matches the launcher wire format", () => {
  const entry: EnrichEntry = { id: "e1", title: "New job", body: "first week, nervous" };
  const replyPub = new Uint8Array(32).fill(9);

  it("uses exactly the field names launcher/src/chat.rs deserializes", () => {
    const payload = JSON.parse(buildEnrichPayload(entry, replyPub)) as Record<string, unknown>;
    expect(Object.keys(payload).sort()).toEqual(["entry", "reply_pub"]);
  });

  it("carries the entry as {id, title, body}", () => {
    const payload = JSON.parse(buildEnrichPayload(entry, replyPub)) as { entry: EnrichEntry };
    expect(payload.entry).toEqual(entry);
    expect(Object.keys(payload.entry).sort()).toEqual(["body", "id", "title"]);
  });

  it("encodes reply_pub as base64 of the raw 32-byte X25519 key", () => {
    const payload = JSON.parse(buildEnrichPayload(entry, replyPub)) as { reply_pub: string };
    expect(b64decode(payload.reply_pub)).toEqual(replyPub);
  });

  it("omits tool_results on the first turn but includes them once present", () => {
    const fresh = JSON.parse(buildEnrichPayload(entry, replyPub)) as Record<string, unknown>;
    expect("tool_results" in fresh).toBe(false);

    const results = [{ id: "attach-e1", name: "attach_metadata", result: { ok: true } }];
    const followUp = JSON.parse(buildEnrichPayload(entry, replyPub, results)) as Record<
      string,
      unknown
    >;
    expect(Object.keys(followUp).sort()).toEqual(["entry", "reply_pub", "tool_results"]);
    expect(followUp.tool_results).toEqual(results);
  });

  it("pins the enrich info strings to launcher/src/chat.rs", () => {
    expect(ENRICH_REQUEST_INFO).toBe("tee-example/hpke/enrich/request/v1");
    expect(ENRICH_RESPONSE_INFO).toBe("tee-example/hpke/enrich/response/v1");
  });
});
