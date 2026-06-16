/**
 * Pins the /chat request plaintext to the launcher's wire format
 * (`ChatRequest` in launcher/src/chat.rs): serde deserializes exactly
 * `{ messages, reply_pub }` with no aliases, so any field-name drift here
 * breaks chat end-to-end. The info strings are pinned for the same reason.
 */
import { describe, expect, it } from "vitest";
import { b64decode } from "./hpke";
import {
  CHAT_REQUEST_INFO,
  CHAT_RESPONSE_INFO,
  buildChatPayload,
  type ChatMessage,
} from "./chat";

describe("chat request payload matches the launcher wire format", () => {
  const history: ChatMessage[] = [
    { role: "user", content: "my cat is called Mochi" },
    { role: "assistant", content: "noted!" },
    { role: "user", content: "what is my cat called?" },
  ];
  const replyPub = new Uint8Array(32).fill(7);

  it("uses exactly the field names launcher/src/chat.rs deserializes", () => {
    const payload = JSON.parse(buildChatPayload(history, replyPub)) as Record<string, unknown>;
    // serde rejects unknown shapes with "missing field" — the envelope must
    // be { messages, reply_pub } and nothing else.
    expect(Object.keys(payload).sort()).toEqual(["messages", "reply_pub"]);
  });

  it("carries the full history oldest-first as {role, content} objects", () => {
    const payload = JSON.parse(buildChatPayload(history, replyPub)) as {
      messages: Record<string, unknown>[];
    };
    expect(payload.messages).toEqual(history);
    for (const message of payload.messages) {
      expect(Object.keys(message).sort()).toEqual(["content", "role"]);
      expect(["user", "assistant"]).toContain(message.role);
      expect(typeof message.content).toBe("string");
    }
  });

  it("encodes reply_pub as base64 of the raw 32-byte X25519 key", () => {
    const payload = JSON.parse(buildChatPayload(history, replyPub)) as { reply_pub: string };
    expect(b64decode(payload.reply_pub)).toEqual(replyPub);
  });

  it("pins the chat info strings to launcher/src/chat.rs", () => {
    expect(CHAT_REQUEST_INFO).toBe("tee-example/hpke/chat/request/v1");
    expect(CHAT_RESPONSE_INFO).toBe("tee-example/hpke/chat/response/v1");
  });

  it("omits tool_results on a fresh turn but includes them once present", () => {
    // serde's `#[serde(default)]` accepts the field's absence, so a first turn
    // stays { messages, reply_pub }; a follow-up adds the matching loop state.
    const fresh = JSON.parse(buildChatPayload(history, replyPub)) as Record<string, unknown>;
    expect("tool_results" in fresh).toBe(false);

    const results = [{ id: "search-1", name: "search_entries", result: { matches: [] } }];
    const followUp = JSON.parse(buildChatPayload(history, replyPub, results)) as Record<
      string,
      unknown
    >;
    expect(Object.keys(followUp).sort()).toEqual(["messages", "reply_pub", "tool_results"]);
    expect(followUp.tool_results).toEqual(results);
  });
});
